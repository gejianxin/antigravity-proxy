use std::io::{Error, ErrorKind, Result};

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

fn send_all(fd: libc::c_int, buf: &[u8], timeout_ms: u32) -> Result<()> {
    let mut total = 0;
    while total < buf.len() {
        wait_socket_ready(fd, libc::POLLOUT, timeout_ms)?;
        let sent = unsafe {
            libc::send(
                fd,
                buf[total..].as_ptr() as *const libc::c_void,
                buf.len() - total,
                libc::MSG_NOSIGNAL,
            )
        };
        if sent < 0 {
            let err = Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        total += sent as usize;
    }
    Ok(())
}

fn recv_exact(fd: libc::c_int, buf: &mut [u8], timeout_ms: u32) -> Result<()> {
    let mut total = 0;
    while total < buf.len() {
        wait_socket_ready(fd, libc::POLLIN, timeout_ms)?;
        let recvd = unsafe {
            libc::recv(
                fd,
                buf[total..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - total,
                0,
            )
        };
        if recvd <= 0 {
            let err = Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(Error::new(ErrorKind::UnexpectedEof, "Connection closed"));
        }
        total += recvd as usize;
    }
    Ok(())
}

pub fn socks5_handshake(
    fd: libc::c_int,
    dest_host: Option<&str>,
    dest_port: u16,
    orig_addr: *const libc::sockaddr,
    timeout_ms: u32,
) -> Result<()> {
    // 1. Send SOCKS5 Greeting: VER=5, NMETHODS=1, METHOD=0(No Auth)
    let greeting = [0x05u8, 0x01, 0x00];
    send_all(fd, &greeting, timeout_ms)?;

    // 2. Read Greeting Response: [0x05, 0x00]
    let mut greeting_resp = [0u8; 2];
    recv_exact(fd, &mut greeting_resp, timeout_ms)?;

    if greeting_resp[0] != 0x05 || greeting_resp[1] != 0x00 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("SOCKS5 server rejected auth: {:02X} {:02X}", greeting_resp[0], greeting_resp[1]),
        ));
    }

    // 3. Send SOCKS5 CONNECT Request
    let mut req = Vec::with_capacity(300);
    req.extend_from_slice(&[0x05, 0x01, 0x00]); // VER, CMD=CONNECT, RSV

    if let Some(host) = dest_host {
        let h_bytes = host.as_bytes();
        let len = h_bytes.len().min(255) as u8;
        req.push(0x03); // ATYP: DOMAINNAME
        req.push(len);
        req.extend_from_slice(&h_bytes[..len as usize]);
        req.extend_from_slice(&dest_port.to_be_bytes());
    } else if !orig_addr.is_null() {
        unsafe {
            if (*orig_addr).sa_family == libc::AF_INET as libc::sa_family_t {
                let sin = &*(orig_addr as *const libc::sockaddr_in);
                req.push(0x01); // ATYP: IPv4
                req.extend_from_slice(&sin.sin_addr.s_addr.to_ne_bytes());
                req.extend_from_slice(&sin.sin_port.to_ne_bytes());
            } else if (*orig_addr).sa_family == libc::AF_INET6 as libc::sa_family_t {
                let sin6 = &*(orig_addr as *const libc::sockaddr_in6);
                req.push(0x04); // ATYP: IPv6
                req.extend_from_slice(&sin6.sin6_addr.s6_addr);
                req.extend_from_slice(&sin6.sin6_port.to_ne_bytes());
            } else {
                return Err(Error::new(ErrorKind::InvalidInput, "Unsupported address family"));
            }
        }
    } else {
        return Err(Error::new(ErrorKind::InvalidInput, "No target address specified"));
    }

    send_all(fd, &req, timeout_ms)?;

    // 4. Read SOCKS5 CONNECT Response Header
    let mut resp_hdr = [0u8; 4];
    recv_exact(fd, &mut resp_hdr, timeout_ms)?;

    if resp_hdr[0] != 0x05 {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid SOCKS5 version in reply"));
    }
    if resp_hdr[1] != 0x00 {
        return Err(Error::new(
            ErrorKind::ConnectionRefused,
            format!("SOCKS5 connect failed with status code 0x{:02X}", resp_hdr[1]),
        ));
    }

    // 5. Drain bound address/port
    let to_drain = match resp_hdr[3] {
        0x01 => 6,  // IPv4 (4) + Port (2)
        0x04 => 18, // IPv6 (16) + Port (2)
        0x03 => {
            let mut dlen = [0u8; 1];
            recv_exact(fd, &mut dlen, timeout_ms)?;
            dlen[0] as usize + 2
        }
        other => {
            return Err(Error::new(ErrorKind::InvalidData, format!("Unknown ATYP 0x{:02X}", other)));
        }
    };

    let mut drain_buf = vec![0u8; to_drain];
    recv_exact(fd, &mut drain_buf, timeout_ms)?;

    Ok(())
}
