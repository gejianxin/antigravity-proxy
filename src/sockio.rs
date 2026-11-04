use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use crate::config::AppConfig;
use crate::ffi;

pub fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

pub fn set_errno(err: i32) {
    unsafe {
        *libc::__errno_location() = err;
    }
}

pub fn fail(err: i32) -> libc::c_int {
    set_errno(err);
    -1
}

pub fn socket_type(fd: libc::c_int) -> Option<libc::c_int> {
    let mut socktype: libc::c_int = 0;
    let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut socktype as *mut _ as *mut libc::c_void,
            &mut optlen,
        )
    };
    if rc == 0 {
        Some(socktype)
    } else {
        None
    }
}

pub fn socket_domain(fd: libc::c_int) -> Option<libc::c_int> {
    let mut domain: libc::c_int = 0;
    let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            &mut domain as *mut _ as *mut libc::c_void,
            &mut optlen,
        )
    };
    if rc == 0 {
        Some(domain)
    } else {
        None
    }
}

fn remaining_ms(start: Instant, timeout_ms: u32) -> Result<i32> {
    let budget = Duration::from_millis(timeout_ms as u64);
    let elapsed = start.elapsed();
    if elapsed >= budget {
        return Err(Error::new(ErrorKind::TimedOut, "socket poll timed out"));
    }
    let left = (budget - elapsed).as_millis().min(i32::MAX as u128) as i32;
    Ok(left.max(1))
}

pub fn wait_socket(fd: libc::c_int, events: libc::c_short, timeout_ms: u32) -> Result<()> {
    let start = Instant::now();
    loop {
        let timeout = remaining_ms(start, timeout_ms)?;
        let mut pfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout) };
        if ret > 0 {
            if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
                && pfd.revents & events == 0
            {
                return Err(Error::new(ErrorKind::BrokenPipe, "socket poll error"));
            }
            if pfd.revents & events != 0 {
                return Ok(());
            }
            return Err(Error::new(ErrorKind::BrokenPipe, "socket poll error"));
        } else if ret == 0 {
            return Err(Error::new(ErrorKind::TimedOut, "socket poll timed out"));
        } else if errno() == libc::EINTR {
            continue;
        } else {
            return Err(Error::last_os_error());
        }
    }
}

pub fn send_all(fd: libc::c_int, buf: &[u8], timeout_ms: u32) -> Result<()> {
    let mut total = 0;
    while total < buf.len() {
        wait_socket(fd, libc::POLLOUT, timeout_ms)?;
        let sent = unsafe {
            ffi::real_send(
                fd,
                buf[total..].as_ptr() as *const libc::c_void,
                buf.len() - total,
                libc::MSG_NOSIGNAL,
            )
        };
        if sent > 0 {
            total += sent as usize;
            continue;
        }
        if sent == 0 {
            return Err(Error::new(
                ErrorKind::WriteZero,
                "connection closed while sending",
            ));
        }
        let err = errno();
        if err == libc::EINTR || err == libc::EAGAIN || err == libc::EWOULDBLOCK {
            continue;
        }
        return Err(Error::from_raw_os_error(err));
    }
    Ok(())
}

pub fn recv_exact(fd: libc::c_int, buf: &mut [u8], timeout_ms: u32) -> Result<()> {
    let mut total = 0;
    while total < buf.len() {
        wait_socket(fd, libc::POLLIN, timeout_ms)?;
        let recvd = unsafe {
            ffi::real_recv(
                fd,
                buf[total..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - total,
                0,
            )
        };
        if recvd > 0 {
            total += recvd as usize;
            continue;
        }
        if recvd == 0 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "connection closed"));
        }
        let err = errno();
        if err == libc::EINTR || err == libc::EAGAIN || err == libc::EWOULDBLOCK {
            continue;
        }
        return Err(Error::from_raw_os_error(err));
    }
    Ok(())
}

pub unsafe fn wait_connected(fd: libc::c_int, timeout_ms: u32) -> std::result::Result<(), i32> {
    let start = Instant::now();
    let budget = Duration::from_millis(timeout_ms as u64);
    loop {
        let elapsed = start.elapsed();
        if elapsed >= budget {
            return Err(libc::ETIMEDOUT);
        }
        let left = (budget - elapsed).as_millis().min(i32::MAX as u128) as i32;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let rc = libc::poll(&mut pfd, 1, left.max(1));
        if rc < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return Err(errno());
        }
        if rc == 0 {
            return Err(libc::ETIMEDOUT);
        }
        let mut soerr: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let g = libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut soerr as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if g < 0 {
            return Err(errno());
        }
        if soerr == 0 {
            return Ok(());
        }
        return Err(soerr);
    }
}

pub unsafe fn connect_timeout(
    fd: libc::c_int,
    addr: *const libc::sockaddr,
    len: libc::socklen_t,
    timeout_ms: u32,
) -> std::result::Result<(), i32> {
    let rc = ffi::real_connect(fd, addr, len);
    if rc == 0 {
        return Ok(());
    }
    let err = errno();
    if err == libc::EINPROGRESS
        || err == libc::EAGAIN
        || err == libc::EWOULDBLOCK
        || err == libc::EALREADY
    {
        return wait_connected(fd, timeout_ms);
    }
    Err(err)
}

fn disable_v6only(fd: libc::c_int) {
    let off: libc::c_int = 0;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &off as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

pub struct SockBuf {
    pub storage: libc::sockaddr_storage,
    pub len: libc::socklen_t,
}

pub unsafe fn connect_fd_to_proxy(
    fd: libc::c_int,
    cfg: &AppConfig,
    timeout_ms: u32,
) -> std::result::Result<(), i32> {
    prepare_v6_proxy_socket(fd);
    let domain = socket_domain(fd).unwrap_or(libc::AF_INET);
    let dest = proxy_sockaddr(cfg, domain)?;
    connect_timeout(
        fd,
        &dest.storage as *const _ as *const libc::sockaddr,
        dest.len,
        timeout_ms,
    )
}

pub unsafe fn proxy_sockaddr(
    cfg: &AppConfig,
    domain: libc::c_int,
) -> std::result::Result<SockBuf, i32> {
    let host = cfg.proxy.host.trim();
    let port = cfg.proxy.port;

    if domain == libc::AF_INET {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            let mut sin: libc::sockaddr_in = std::mem::zeroed();
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = port.to_be();
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from(ip).to_be(),
            };
            return Ok(storage_from_v4(&sin));
        }
        if host.parse::<Ipv6Addr>().is_ok() {
            return Err(libc::EAFNOSUPPORT);
        }
        return resolve_proxy(host, port, libc::AF_INET);
    }

    if domain == libc::AF_INET6 {
        if let Ok(ip) = host.parse::<Ipv6Addr>() {
            let mut sin6: libc::sockaddr_in6 = std::mem::zeroed();
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = port.to_be();
            sin6.sin6_addr.s6_addr = ip.octets();
            return Ok(storage_from_v6(&sin6));
        }
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Ok(v4_mapped_sockaddr(ip, port));
        }
        if let Ok(buf) = resolve_proxy(host, port, libc::AF_INET6) {
            return Ok(buf);
        }
        if let Ok(buf) = resolve_proxy(host, port, libc::AF_INET) {
            let sin = &*(&buf.storage as *const _ as *const libc::sockaddr_in);
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            return Ok(v4_mapped_sockaddr(ip, port));
        }
        return Err(libc::EHOSTUNREACH);
    }

    Err(libc::EAFNOSUPPORT)
}

fn v4_mapped_sockaddr(ip: Ipv4Addr, port: u16) -> SockBuf {
    let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    sin6.sin6_port = port.to_be();
    let o = ip.octets();
    sin6.sin6_addr.s6_addr = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, o[0], o[1], o[2], o[3],
    ];
    storage_from_v6(&sin6)
}

fn storage_from_v4(sin: &libc::sockaddr_in) -> SockBuf {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::copy_nonoverlapping(
            sin as *const _ as *const u8,
            &mut storage as *mut _ as *mut u8,
            std::mem::size_of::<libc::sockaddr_in>(),
        );
    }
    SockBuf {
        storage,
        len: std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
    }
}

fn storage_from_v6(sin: &libc::sockaddr_in6) -> SockBuf {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::copy_nonoverlapping(
            sin as *const _ as *const u8,
            &mut storage as *mut _ as *mut u8,
            std::mem::size_of::<libc::sockaddr_in6>(),
        );
    }
    SockBuf {
        storage,
        len: std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
    }
}

unsafe fn resolve_proxy(
    host: &str,
    port: u16,
    family: libc::c_int,
) -> std::result::Result<SockBuf, i32> {
    let c_host = std::ffi::CString::new(host).map_err(|_| libc::EINVAL)?;
    let mut hints: libc::addrinfo = std::mem::zeroed();
    hints.ai_family = family;
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    let rc = ffi::real_getaddrinfo(c_host.as_ptr(), std::ptr::null(), &hints, &mut res);
    if rc != 0 || res.is_null() {
        return Err(libc::EHOSTUNREACH);
    }
    let ai = &*res;
    if ai.ai_addr.is_null() || ai.ai_addrlen == 0 {
        ffi::real_freeaddrinfo(res);
        return Err(libc::EHOSTUNREACH);
    }
    let mut storage: libc::sockaddr_storage = std::mem::zeroed();
    let n = std::cmp::min(
        ai.ai_addrlen as usize,
        std::mem::size_of::<libc::sockaddr_storage>(),
    );
    std::ptr::copy_nonoverlapping(
        ai.ai_addr as *const u8,
        &mut storage as *mut _ as *mut u8,
        n,
    );
    ffi::real_freeaddrinfo(res);

    if family == libc::AF_INET {
        let sin = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in);
        sin.sin_port = port.to_be();
        return Ok(SockBuf {
            storage,
            len: std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        });
    }
    let sin6 = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6);
    sin6.sin6_port = port.to_be();
    Ok(SockBuf {
        storage,
        len: std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
    })
}

pub unsafe fn prepare_v6_proxy_socket(fd: libc::c_int) {
    if socket_domain(fd) == Some(libc::AF_INET6) {
        disable_v6only(fd);
    }
}

pub fn positive_timeout(ms: u32, fallback: u32) -> u32 {
    if ms == 0 {
        fallback
    } else {
        ms
    }
}
