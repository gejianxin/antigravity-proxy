use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

fn wait_socket_ready(fd: libc::c_int, events: libc::c_short, timeout_ms: u32) -> Result<()> {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms as libc::c_int) };
    if ret > 0 && (pfd.revents & events != 0) {
        Ok(())
    } else if ret == 0 {
        Err(Error::new(ErrorKind::TimedOut, "Socket poll timed out"))
    } else {
        Err(Error::last_os_error())
    }
}

pub fn http_handshake(
    fd: libc::c_int,
    dest_host: Option<&str>,
    dest_port: u16,
    orig_addr: *const libc::sockaddr,
    timeout_ms: u32,
) -> Result<()> {
    let target = if let Some(h) = dest_host {
        format!("{}:{}", h, dest_port)
    } else if !orig_addr.is_null() {
        unsafe {
            if (*orig_addr).sa_family == libc::AF_INET as libc::sa_family_t {
                let sin = &*(orig_addr as *const libc::sockaddr_in);
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                format!("{}:{}", ip, u16::from_be(sin.sin_port))
            } else if (*orig_addr).sa_family == libc::AF_INET6 as libc::sa_family_t {
                let sin6 = &*(orig_addr as *const libc::sockaddr_in6);
                let ip6 = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                format!("[{}]:{}", ip6, u16::from_be(sin6.sin6_port))
            } else {
                return Err(Error::new(ErrorKind::InvalidInput, "Unsupported address family"));
            }
        }
    } else {
        return Err(Error::new(ErrorKind::InvalidInput, "No target address"));
    };

    let req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Antigravity-Proxy-Rust/2.4\r\nProxy-Connection: Keep-Alive\r\n\r\n",
        target, target
    );

    wait_socket_ready(fd, libc::POLLOUT, timeout_ms)?;
    let sent = unsafe {
        libc::send(
            fd,
            req.as_ptr() as *const libc::c_void,
            req.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if sent != req.len() as isize {
        return Err(Error::new(ErrorKind::WriteZero, "Failed to send HTTP CONNECT request"));
    }

    // Read response until \r\n\r\n
    let mut resp = Vec::with_capacity(1024);
    let mut byte_buf = [0u8; 1];
    while resp.len() < 1024 {
        wait_socket_ready(fd, libc::POLLIN, timeout_ms)?;
        let r = unsafe { libc::recv(fd, byte_buf.as_mut_ptr() as *mut libc::c_void, 1, 0) };
        if r <= 0 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Failed reading HTTP response"));
        }
        resp.push(byte_buf[0]);
        if resp.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let resp_str = String::from_utf8_lossy(&resp);
    if let Some(status_line) = resp_str.lines().next() {
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(code) = parts[1].parse::<u16>() {
                if (200..300).contains(&code) {
                    return Ok(());
                }
            }
        }
    }

    Err(Error::new(
        ErrorKind::ConnectionRefused,
        format!("HTTP CONNECT rejected: {}", resp_str.lines().next().unwrap_or("")),
    ))
}
