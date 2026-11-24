//! Blocking handshake helpers. They poll, so a non-blocking socket still
//! finishes the proxy setup inside `connect` and the original flags stay put.

use std::net::Ipv4Addr;

use agy_core::config::AppConfig;
use agy_core::proto::{self, SocksTarget};

use super::hooks;
use super::log;

pub unsafe fn tcp_proxy(
    fd: libc::c_int,
    family: i32,
    host: &str,
    port: u16,
    cfg: &AppConfig,
) -> bool {
    let timeout = cfg.timeout.connect.max(1000);
    let Some(proxy) = proxy_addr(family, cfg) else {
        log(&format!("无法构造代理地址 {host}:{port}"));
        return false;
    };
    if family == libc::AF_INET6 {
        let off = 0i32;
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &off as *const _ as *const libc::c_void,
            4,
        );
    }
    let one = 1i32;
    libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_NOSIGPIPE,
        &one as *const _ as *const libc::c_void,
        4,
    );
    let rc = hooks::raw_connect(fd, proxy.as_ptr(), proxy.len);
    if rc != 0 {
        let err = *libc::__error();
        if err != libc::EINPROGRESS && err != libc::EAGAIN && err != libc::EWOULDBLOCK {
            log(&format!("连接代理失败 errno={err}"));
            return false;
        }
        if !wait(fd, true, timeout) || socket_error(fd) != 0 {
            log("连接代理超时");
            return false;
        }
    }
    if !handshake(fd, host, port, cfg) {
        *libc::__error() = libc::ECONNREFUSED;
        return false;
    }
    log(&format!("SOCKS5/HTTP 隧道建立: {host}:{port}"));
    true
}

struct Addr {
    bytes: [u8; 128],
    len: libc::socklen_t,
}

impl Addr {
    fn as_ptr(&self) -> *const libc::sockaddr {
        self.bytes.as_ptr() as *const libc::sockaddr
    }
}

fn proxy_addr(family: i32, cfg: &AppConfig) -> Option<Addr> {
    let host_str = cfg.proxy.host.trim();
    let ip: Ipv4Addr = if let Ok(v4) = host_str.parse::<Ipv4Addr>() {
        v4
    } else if host_str.eq_ignore_ascii_case("localhost") {
        Ipv4Addr::LOCALHOST
    } else {
        // Resolve proxy hostname via real libSystem getaddrinfo
        let c_host = std::ffi::CString::new(host_str).ok()?;
        let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
        hints.ai_family = libc::AF_INET;
        hints.ai_socktype = libc::SOCK_STREAM;
        let mut res: *mut libc::addrinfo = std::ptr::null_mut();
        let ok = unsafe { libc::getaddrinfo(c_host.as_ptr(), std::ptr::null(), &hints, &mut res) };
        if ok != 0 || res.is_null() {
            return None;
        }
        let resolved = unsafe {
            let sin = &*((*res).ai_addr as *const libc::sockaddr_in);
            let v4 = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            libc::freeaddrinfo(res);
            v4
        };
        resolved
    };
    let port = cfg.proxy.port.to_be();
    let mut addr = Addr {
        bytes: [0; 128],
        len: 0,
    };
    if family == libc::AF_INET6 {
        #[repr(C)]
        struct V6 {
            len: u8,
            family: u8,
            port: u16,
            flow: u32,
            ip: [u8; 16],
            scope: u32,
        }
        let mut mapped = [0u8; 16];
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        mapped[12..].copy_from_slice(&ip.octets());
        let v6 = V6 {
            len: std::mem::size_of::<V6>() as u8,
            family: libc::AF_INET6 as u8,
            port,
            flow: 0,
            ip: mapped,
            scope: 0,
        };
        addr.len = std::mem::size_of::<V6>() as libc::socklen_t;
        unsafe { std::ptr::write_unaligned(addr.bytes.as_mut_ptr() as *mut V6, v6) };
    } else {
        #[repr(C)]
        struct V4 {
            len: u8,
            family: u8,
            port: u16,
            addr: u32,
            zero: [i8; 8],
        }
        let v4 = V4 {
            len: 16,
            family: libc::AF_INET as u8,
            port,
            addr: u32::from(ip).to_be(),
            zero: [0; 8],
        };
        addr.len = 16;
        unsafe { std::ptr::write_unaligned(addr.bytes.as_mut_ptr() as *mut V4, v4) };
    }
    Some(addr)
}

fn socket_error(fd: libc::c_int) -> i32 {
    let mut err = 0i32;
    let mut len = 4u32;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut err as *mut _ as *mut libc::c_void,
            &mut len as *mut _ as *mut libc::socklen_t,
        )
    };
    if rc != 0 {
        unsafe { *libc::__error() }
    } else {
        err
    }
}

fn wait(fd: libc::c_int, write: bool, timeout_ms: u32) -> bool {
    unsafe {
        let mut pfd = libc::pollfd {
            fd,
            events: if write { libc::POLLOUT } else { libc::POLLIN },
            revents: 0,
        };
        libc::poll(&mut pfd, 1, timeout_ms as i32) > 0
    }
}

unsafe fn send_all(fd: libc::c_int, buf: &[u8], timeout_ms: u32) -> bool {
    let mut off = 0usize;
    while off < buf.len() {
        if !wait(fd, true, timeout_ms) {
            return false;
        }
        let n = super::hooks::raw_send(
            fd,
            buf[off..].as_ptr() as *const libc::c_void,
            buf.len() - off,
            0,
        );
        if n < 0 {
            let err = *libc::__error();
            if err == libc::EAGAIN || err == libc::EWOULDBLOCK || err == libc::EINTR {
                continue;
            }
            return false;
        }
        if n == 0 {
            return false;
        }
        off += n as usize;
    }
    true
}

unsafe fn recv_exact(fd: libc::c_int, buf: &mut [u8], timeout_ms: u32) -> bool {
    let mut off = 0usize;
    while off < buf.len() {
        if !wait(fd, false, timeout_ms) {
            return false;
        }
        let n = super::hooks::raw_recv(
            fd,
            buf[off..].as_mut_ptr() as *mut libc::c_void,
            buf.len() - off,
            0,
        );
        if n < 0 {
            let err = *libc::__error();
            if err == libc::EAGAIN || err == libc::EWOULDBLOCK || err == libc::EINTR {
                continue;
            }
            return false;
        }
        if n == 0 {
            return false;
        }
        off += n as usize;
    }
    true
}

unsafe fn handshake(fd: libc::c_int, host: &str, port: u16, cfg: &AppConfig) -> bool {
    let timeout = cfg.timeout.connect.max(1000);
    if cfg.proxy.is_http() {
        let authority = format!("{host}:{port}");
        let req = proto::http_connect_request_with_auth(
            &authority,
            &cfg.proxy.username,
            &cfg.proxy.password,
        );
        if !send_all(fd, req.as_bytes(), timeout) {
            return false;
        }
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while buf.len() < 2048 {
            if !recv_exact(fd, &mut byte, timeout) {
                log(&format!(
                    "HTTP CONNECT 接收响应失败{}",
                    proto::http_mismatch_hint_for_io()
                ));
                return false;
            }
            buf.push(byte[0]);
            match proto::http_connect_status(&buf) {
                Ok(true) => return true,
                Ok(false) => continue,
                Err(err) => {
                    log(&err);
                    return false;
                }
            }
        }
        return false;
    }
    let has_auth = cfg.proxy.has_auth();
    if !send_all(fd, &proto::socks5_greeting_for_auth(has_auth), timeout) {
        return false;
    }
    let mut greet = [0u8; 2];
    if !recv_exact(fd, &mut greet, timeout) {
        log(&format!(
            "SOCKS5 读取认证响应失败{}",
            proto::socks5_mismatch_hint_for_io()
        ));
        return false;
    }
    let choice = match proto::socks5_check_greeting(&greet, has_auth) {
        Ok(c) => c,
        Err(msg) => {
            log(&msg);
            return false;
        }
    };
    if choice == proto::Socks5AuthChoice::UserPass {
        let up_req = match proto::socks5_userpass_request(&cfg.proxy.username, &cfg.proxy.password) {
            Ok(b) => b,
            Err(msg) => {
                log(&msg);
                return false;
            }
        };
        if !send_all(fd, &up_req, timeout) {
            return false;
        }
        let mut up_resp = [0u8; 2];
        if !recv_exact(fd, &mut up_resp, timeout) {
            log("SOCKS5 读取账密认证响应失败");
            return false;
        }
        if let Err(msg) = proto::socks5_userpass_ok(&up_resp) {
            log(&msg);
            return false;
        }
    }
    let req = proto::socks5_connect_request(&SocksTarget::Domain(host.to_string()), port);
    if !send_all(fd, &req, timeout) {
        return false;
    }
    let mut hdr = [0u8; 4];
    if !recv_exact(fd, &mut hdr, timeout) || proto::socks5_reply_ok(&hdr).is_err() {
        log("SOCKS5 连接被拒绝");
        return false;
    }
    let mut domain_len = None;
    if hdr[3] == 0x03 {
        let mut len = [0u8; 1];
        if !recv_exact(fd, &mut len, timeout) {
            return false;
        }
        domain_len = Some(len[0]);
    }
    let Some(tail) = proto::socks5_bind_tail(hdr[3], domain_len) else {
        return false;
    };
    let mut drain = vec![0u8; tail];
    recv_exact(fd, &mut drain, timeout)
}
