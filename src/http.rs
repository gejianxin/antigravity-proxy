use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::sockio::{recv_exact, send_all, wait_socket};

pub fn http_handshake(
    fd: libc::c_int,
    dest_host: Option<&str>,
    dest_port: u16,
    orig_addr: *const libc::sockaddr,
    username: &str,
    password: &str,
    send_timeout_ms: u32,
    recv_timeout_ms: u32,
) -> Result<()> {
    let target = if let Some(host) = dest_host {
        format_target(host, dest_port)
    } else {
        sockaddr_target(orig_addr)?
    };

    let req = agy_core::proto::http_connect_request_with_auth(&target, username, password);
    send_all(fd, req.as_bytes(), send_timeout_ms)?;

    let mut resp = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while resp.len() < 8192 {
        if let Err(err) = wait_socket(fd, libc::POLLIN, recv_timeout_ms)
            .and_then(|_| recv_exact(fd, &mut byte, recv_timeout_ms))
        {
            let hint = match err.kind() {
                ErrorKind::TimedOut | ErrorKind::ConnectionReset | ErrorKind::UnexpectedEof => {
                    agy_core::proto::http_mismatch_hint_for_io()
                }
                _ => "",
            };
            return Err(Error::new(
                err.kind(),
                format!("HTTP CONNECT 接收响应失败: {err}{hint}"),
            ));
        }
        resp.push(byte[0]);
        match agy_core::proto::http_connect_status(&resp) {
            Ok(true) => return Ok(()),
            Ok(false) => continue,
            Err(msg) => return Err(Error::new(ErrorKind::ConnectionRefused, msg)),
        }
    }
    Err(Error::new(
        ErrorKind::InvalidData,
        "HTTP CONNECT response header too large or incomplete",
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
