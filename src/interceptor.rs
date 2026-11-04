use std::ffi::{CStr, CString};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::config::AppConfig;
use crate::ffi;
use crate::fakeip;
use crate::socks5;
use crate::http;

fn is_private_ipv4(ip: u32) -> bool {
    // 10.0.0.0/8
    if (ip & 0xFF000000) == 0x0A000000 { return true; }
    // 172.16.0.0/12
    if (ip & 0xFFF00000) == 0xAC100000 { return true; }
    // 192.168.0.0/16
    if (ip & 0xFFFF0000) == 0xC0A80000 { return true; }
    // 169.254.0.0/16
    if (ip & 0xFFFF0000) == 0xA9FE0000 { return true; }
    false
}

fn is_port_allowed(port: u16, cfg: &AppConfig) -> bool {
    if cfg.proxy_rules.allowed_ports.is_empty() {
        return true;
    }
    cfg.proxy_rules.allowed_ports.contains(&port)
}

pub unsafe fn handle_getaddrinfo(
    node: *const libc::c_char,
    service: *const libc::c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> libc::c_int {
    let cfg = crate::get_config();

    if !crate::process::is_targeted_process(cfg) || !cfg.fake_ip.enabled || node.is_null() {
        return ffi::real_getaddrinfo(node, service, hints, res);
    }

    let node_cstr = CStr::from_ptr(node);
    let node_str = match node_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return ffi::real_getaddrinfo(node, service, hints, res),
    };

    if node_str.is_empty()
        || node_str.eq_ignore_ascii_case("localhost")
        || node_str.eq_ignore_ascii_case("localhost.localdomain")
        || Ipv4Addr::from_str(node_str).is_ok()
        || Ipv6Addr::from_str(node_str).is_ok()
    {
        return ffi::real_getaddrinfo(node, service, hints, res);
    }

    if !hints.is_null() && ((*hints).ai_flags & libc::AI_NUMERICHOST != 0) {
        return ffi::real_getaddrinfo(node, service, hints, res);
    }

    // Allocate / Retrieve FakeIP
    let fake_ip = fakeip::get_or_create(node_str);
    if fake_ip == 0 {
        return ffi::real_getaddrinfo(node, service, hints, res);
    }

    let port = if !service.is_null() {
        if let Ok(svc_str) = CStr::from_ptr(service).to_str() {
            if let Ok(p) = svc_str.parse::<u16>() {
                p
            } else if svc_str.eq_ignore_ascii_case("https") {
                443
            } else if svc_str.eq_ignore_ascii_case("http") {
                80
            } else {
                0
            }
        } else {
            0
        }
    } else {
        0
    };

    let fake_ai = fakeip::create_fake_addrinfo(fake_ip, port, if hints.is_null() { None } else { Some(&*hints) });
    if fake_ai.is_null() {
        return ffi::real_getaddrinfo(node, service, hints, res);
    }

    crate::log_debug!("[FakeIP] 解析域名拦截: {} -> 198.18.x.x (端口 {})", node_str, port);

    *res = fake_ai;
    0
}

pub unsafe fn handle_freeaddrinfo(res: *mut libc::addrinfo) {
    if fakeip::is_fake_addrinfo(res) {
        fakeip::free_fake_addrinfo(res);
    } else {
        ffi::real_freeaddrinfo(res);
    }
}

pub unsafe fn handle_gethostbyname(name: *const libc::c_char) -> *mut libc::hostent {
    let cfg = crate::get_config();

    if !crate::process::is_targeted_process(cfg) || !cfg.fake_ip.enabled || name.is_null() {
        return ffi::real_gethostbyname(name);
    }

    let name_cstr = CStr::from_ptr(name);
    let name_str = match name_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return ffi::real_gethostbyname(name),
    };

    if name_str.is_empty()
        || name_str.eq_ignore_ascii_case("localhost")
        || Ipv4Addr::from_str(name_str).is_ok()
    {
        return ffi::real_gethostbyname(name);
    }

    let fake_ip = fakeip::get_or_create(name_str);
    if fake_ip == 0 {
        return ffi::real_gethostbyname(name);
    }

    fakeip::create_fake_hostent(name_str, fake_ip)
}

pub unsafe fn handle_connect(
    sockfd: libc::c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> libc::c_int {
    let cfg = crate::get_config();

    if !crate::process::is_targeted_process(cfg) || addr.is_null() {
        return ffi::real_connect(sockfd, addr, addrlen);
    }

    let family = (*addr).sa_family as libc::c_int;
    if family != libc::AF_INET && family != libc::AF_INET6 {
        return ffi::real_connect(sockfd, addr, addrlen);
    }

    // Only hook stream sockets (TCP)
    let mut socktype: libc::c_int = 0;
    let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if libc::getsockopt(
        sockfd,
        libc::SOL_SOCKET,
        libc::SO_TYPE,
        &mut socktype as *mut _ as *mut libc::c_void,
        &mut optlen,
    ) == 0 && socktype != libc::SOCK_STREAM {
        return ffi::real_connect(sockfd, addr, addrlen);
    }

    let mut dest_domain: Option<String> = None;
    let mut dest_port: u16 = 0;
    let mut should_proxy = false;

    if family == libc::AF_INET {
        let sin = &*(addr as *const libc::sockaddr_in);
        let ip = u32::from_be(sin.sin_addr.s_addr);
        dest_port = u16::from_be(sin.sin_port);

        // Loopback 127.0.0.0/8
        if (ip >> 24) == 127 {
            return ffi::real_connect(sockfd, addr, addrlen);
        }

        if fakeip::is_fakeip(ip) {
            dest_domain = fakeip::get_domain(ip);
            should_proxy = true;
        } else {
            if cfg.proxy_rules.routing.use_default_private && is_private_ipv4(ip) {
                return ffi::real_connect(sockfd, addr, addrlen);
            }
            should_proxy = is_port_allowed(dest_port, cfg);
        }
    } else if family == libc::AF_INET6 {
        let sin6 = &*(addr as *const libc::sockaddr_in6);
        dest_port = u16::from_be(sin6.sin6_port);

        // Loopback ::1
        static LOOPBACK_6: [u8; 16] = [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1];
        if sin6.sin6_addr.s6_addr == LOOPBACK_6 {
            return ffi::real_connect(sockfd, addr, addrlen);
        }

        should_proxy = is_port_allowed(dest_port, cfg);
    }

    if !should_proxy {
        return ffi::real_connect(sockfd, addr, addrlen);
    }

    // Check if target is the proxy server itself to avoid recursive loops
    if let Ok(proxy_ip) = Ipv4Addr::from_str(&cfg.proxy.host) {
        if family == libc::AF_INET {
            let sin = &*(addr as *const libc::sockaddr_in);
            if u32::from_be(sin.sin_addr.s_addr) == u32::from(proxy_ip) && dest_port == cfg.proxy.port {
                return ffi::real_connect(sockfd, addr, addrlen);
            }
        }
    }

    crate::log_debug!(
        "[代理/路由] 拦截连接 fd={}, 目标={}:{}",
        sockfd,
        dest_domain.as_deref().unwrap_or("(IP目标)"),
        dest_port
    );

    // Save non-blocking socket flags
    let orig_flags = libc::fcntl(sockfd, libc::F_GETFL, 0);
    if orig_flags != -1 && (orig_flags & libc::O_NONBLOCK != 0) {
        libc::fcntl(sockfd, libc::F_SETFL, orig_flags & !libc::O_NONBLOCK);
    }

    // Set temporary timeouts
    let timeout_ms = cfg.timeout.connect.max(1000);
    let tv = libc::timeval {
        tv_sec: (timeout_ms / 1000) as libc::time_t,
        tv_usec: ((timeout_ms % 1000) * 1000) as libc::suseconds_t,
    };
    libc::setsockopt(
        sockfd,
        libc::SOL_SOCKET,
        libc::SO_RCVTIMEO,
        &tv as *const _ as *const libc::c_void,
        std::mem::size_of::<libc::timeval>() as libc::socklen_t,
    );
    libc::setsockopt(
        sockfd,
        libc::SOL_SOCKET,
        libc::SO_SNDTIMEO,
        &tv as *const _ as *const libc::c_void,
        std::mem::size_of::<libc::timeval>() as libc::socklen_t,
    );

    // Resolve & Connect to Proxy server
    let mut proxy_sin: libc::sockaddr_in = std::mem::zeroed();
    proxy_sin.sin_family = libc::AF_INET as libc::sa_family_t;
    proxy_sin.sin_port = cfg.proxy.port.to_be();

    let proxy_ip_parsed = Ipv4Addr::from_str(&cfg.proxy.host);
    let resolved_proxy = match proxy_ip_parsed {
        Ok(ip) => {
            proxy_sin.sin_addr.s_addr = u32::from(ip).to_be();
            true
        }
        Err(_) => {
            // Domain lookup using real getaddrinfo
            let c_host = CString::new(cfg.proxy.host.as_str()).unwrap_or_default();
            let mut hints: libc::addrinfo = std::mem::zeroed();
            hints.ai_family = libc::AF_INET;
            hints.ai_socktype = libc::SOCK_STREAM;
            let mut res: *mut libc::addrinfo = std::ptr::null_mut();
            if ffi::real_getaddrinfo(c_host.as_ptr(), std::ptr::null(), &hints, &mut res) == 0 && !res.is_null() {
                let p_sin = &*((*res).ai_addr as *const libc::sockaddr_in);
                proxy_sin.sin_addr = p_sin.sin_addr;
                ffi::real_freeaddrinfo(res);
                true
            } else {
                false
            }
        }
    };

    if !resolved_proxy {
        crate::log_error!("[代理/连接] 无法解析代理服务器地址: {}", cfg.proxy.host);
        if orig_flags != -1 {
            libc::fcntl(sockfd, libc::F_SETFL, orig_flags);
        }
        *libc::__errno_location() = libc::ECONNREFUSED;
        return -1;
    }

    let conn_res = ffi::real_connect(
        sockfd,
        &proxy_sin as *const _ as *const libc::sockaddr,
        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
    );

    if conn_res != 0 {
        let err = *libc::__errno_location();
        crate::log_warn!("[代理/连接] 连接代理服务器 {}:{} 失败 (errno={})", cfg.proxy.host, cfg.proxy.port, err);
        if orig_flags != -1 {
            libc::fcntl(sockfd, libc::F_SETFL, orig_flags);
        }
        return -1;
    }

    // Perform Handshake
    let handshake_res = if cfg.proxy.r#type.eq_ignore_ascii_case("http") {
        http::http_handshake(sockfd, dest_domain.as_deref(), dest_port, addr, timeout_ms)
    } else {
        socks5::socks5_handshake(sockfd, dest_domain.as_deref(), dest_port, addr, timeout_ms)
    };

    // Clear temporary timeouts
    let zero_tv: libc::timeval = std::mem::zeroed();
    libc::setsockopt(
        sockfd,
        libc::SOL_SOCKET,
        libc::SO_RCVTIMEO,
        &zero_tv as *const _ as *const libc::c_void,
        std::mem::size_of::<libc::timeval>() as libc::socklen_t,
    );
    libc::setsockopt(
        sockfd,
        libc::SOL_SOCKET,
        libc::SO_SNDTIMEO,
        &zero_tv as *const _ as *const libc::c_void,
        std::mem::size_of::<libc::timeval>() as libc::socklen_t,
    );

    // Restore original socket flags
    if orig_flags != -1 {
        libc::fcntl(sockfd, libc::F_SETFL, orig_flags);
    }

    match handshake_res {
        Ok(()) => {
            crate::log_info!(
                "[代理/成功] 隧道建立成功: {}:{} (fd={})",
                dest_domain.as_deref().unwrap_or("(IP)"),
                dest_port,
                sockfd
            );
            0
        }
        Err(e) => {
            crate::log_warn!(
                "[代理/失败] 代理握手失败: {}:{} ({})",
                dest_domain.as_deref().unwrap_or("(IP)"),
                dest_port,
                e
            );
            *libc::__errno_location() = libc::ECONNREFUSED;
            -1
        }
    }
}
