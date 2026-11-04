use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::sockio::{recv_exact, send_all, wait_socket};

pub fn http_handshake(
    fd: libc::c_int,
    dest_host: Option<&str>,
    dest_port: u16,
    orig_addr: *const libc::sockaddr,
    send_timeout_ms: u32,
    recv_timeout_ms: u32,
) -> Result<()> {
    let target = if let Some(host) = dest_host {
        format_target(host, dest_port)
    } else {
        sockaddr_target(orig_addr)?
    };

    let req = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Antigravity-Proxy-Rust/2.5\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    );
    send_all(fd, req.as_bytes(), send_timeout_ms)?;

    let mut resp = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while resp.len() < 8192 {
        wait_socket(fd, libc::POLLIN, recv_timeout_ms)?;
        recv_exact(fd, &mut byte, recv_timeout_ms)?;
        resp.push(byte[0]);
        if resp.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let resp_str = String::from_utf8_lossy(&resp);
    if let Some(status_line) = resp_str.lines().next() {
        let mut parts = status_line.split_whitespace();
        let _http = parts.next();
        if let Some(code) = parts.next().and_then(|p| p.parse::<u16>().ok()) {
            if (200..300).contains(&code) {
                return Ok(());
            }
        }
        return Err(Error::new(
            ErrorKind::ConnectionRefused,
            format!("HTTP CONNECT rejected: {status_line}"),
        ));
    }
    Err(Error::new(
        ErrorKind::InvalidData,
        "empty HTTP CONNECT response",
    ))
}

fn format_target(host: &str, port: u16) -> String {
    let host = host.trim();
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn sockaddr_target(addr: *const libc::sockaddr) -> Result<String> {
    if addr.is_null() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "missing target address",
        ));
    }
    unsafe {
        if (*addr).sa_family == libc::AF_INET as libc::sa_family_t {
            let sin = &*(addr as *const libc::sockaddr_in);
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            return Ok(format!("{}:{}", ip, u16::from_be(sin.sin_port)));
        }
        if (*addr).sa_family == libc::AF_INET6 as libc::sa_family_t {
            let sin6 = &*(addr as *const libc::sockaddr_in6);
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            return Ok(format!("[{}]:{}", ip, u16::from_be(sin6.sin6_port)));
        }
    }
    Err(Error::new(
        ErrorKind::InvalidInput,
        "unsupported address family",
    ))
}
