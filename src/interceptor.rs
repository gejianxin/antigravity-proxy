use std::ffi::{CStr, CString};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use crate::config::AppConfig;
use crate::endpoint::{self, Endpoint};
use crate::fakeip;
use crate::ffi;
use crate::route::{self, Action};
use crate::sockio::{self, fail};

static PROXY_IPS: OnceLock<ProxyIps> = OnceLock::new();

struct ProxyIps {
    v4: Vec<u32>,
    v6: Vec<[u8; 16]>,
}

pub unsafe fn handle_getaddrinfo(
    node: *const libc::c_char,
    service: *const libc::c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> libc::c_int {
    if crate::guard::in_hook() {
        return ffi::real_getaddrinfo(node, service, hints, res);
    }
    let cfg = crate::get_config();
    if !crate::process::is_targeted_process(cfg) || !cfg.fake_ip.enabled || node.is_null() {
        return ffi::real_getaddrinfo(node, service, hints, res);
    }

    let node_str = match CStr::from_ptr(node).to_str() {
        Ok(s) => s,
        Err(_) => return ffi::real_getaddrinfo(node, service, hints, res),
    };
    if node_str.is_empty() || route::is_loopback_host(node_str) || route::is_ip_literal(node_str) {
        return ffi::real_getaddrinfo(node, service, hints, res);
    }
    if !hints.is_null() && (*hints).ai_flags & libc::AI_NUMERICHOST != 0 {
        return ffi::real_getaddrinfo(node, service, hints, res);
    }

    let _guard = crate::guard::Guard::enter();
    let port = service_port(service);
    if dns_uses_real_resolver(cfg, node_str, port) {
        return ffi::real_getaddrinfo(node, service, hints, res);
    }

    let fake_ip = fakeip::get_or_create(node_str);
    if fake_ip == 0 {
        crate::log_warn!("[FakeIP] 地址池不可用，回退系统解析: {node_str}");
        return ffi::real_getaddrinfo(node, service, hints, res);
    }

    let family = if hints.is_null() {
        libc::AF_UNSPEC
    } else {
        (*hints).ai_family
    };
    let numeric = match family {
        libc::AF_INET6 => format!("::ffff:{}", Ipv4Addr::from(fake_ip)),
        libc::AF_INET | libc::AF_UNSPEC => Ipv4Addr::from(fake_ip).to_string(),
        _ => return ffi::real_getaddrinfo(node, service, hints, res),
    };
    let Ok(c_numeric) = CString::new(numeric) else {
        return ffi::real_getaddrinfo(node, service, hints, res);
    };
    let rc = ffi::real_getaddrinfo(c_numeric.as_ptr(), service, hints, res);
    if rc != 0 {
        crate::log_warn!("[FakeIP] 数值地址回填失败 (rc={rc})，回退系统解析: {node_str}");
        return ffi::real_getaddrinfo(node, service, hints, res);
    }
    crate::log_debug!(
        "[FakeIP] {} -> {} (port {port})",
        node_str,
        Ipv4Addr::from(fake_ip)
    );
    0
}

pub unsafe fn handle_freeaddrinfo(res: *mut libc::addrinfo) {
    ffi::real_freeaddrinfo(res);
}

pub unsafe fn handle_gethostbyname(name: *const libc::c_char) -> *mut libc::hostent {
    if crate::guard::in_hook() {
        return ffi::real_gethostbyname(name);
    }
    let cfg = crate::get_config();
    if !crate::process::is_targeted_process(cfg) || !cfg.fake_ip.enabled || name.is_null() {
        return ffi::real_gethostbyname(name);
    }
    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return ffi::real_gethostbyname(name),
    };
    if name_str.is_empty() || route::is_loopback_host(name_str) || route::is_ip_literal(name_str) {
        return ffi::real_gethostbyname(name);
    }
    let _guard = crate::guard::Guard::enter();
    if dns_uses_real_resolver(cfg, name_str, 0) {
        return ffi::real_gethostbyname(name);
    }
    let fake_ip = fakeip::get_or_create(name_str);
    if fake_ip == 0 {
        return ffi::real_gethostbyname(name);
    }
    let Ok(numeric) = CString::new(Ipv4Addr::from(fake_ip).to_string()) else {
        return ffi::real_gethostbyname(name);
    };
    ffi::real_gethostbyname(numeric.as_ptr())
}

pub unsafe fn handle_connect(
    sockfd: libc::c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> libc::c_int {
    if crate::guard::in_hook() {
        return ffi::real_connect(sockfd, addr, addrlen);
    }
    let cfg = crate::get_config();
    if !crate::process::is_targeted_process(cfg) || addr.is_null() {
        return ffi::real_connect(sockfd, addr, addrlen);
    }
    let family = (*addr).sa_family as libc::c_int;
    if family != libc::AF_INET && family != libc::AF_INET6 {
        return ffi::real_connect(sockfd, addr, addrlen);
    }

    let _guard = crate::guard::Guard::enter();
    let socktype = sockio::socket_type(sockfd);
    if socktype == Some(libc::SOCK_DGRAM) {
        return crate::udp::handle_connect(sockfd, addr, addrlen);
    }
    if socktype.is_some() && socktype != Some(libc::SOCK_STREAM) {
        return ffi::real_connect(sockfd, addr, addrlen);
    }

    let Some(ep) = endpoint::from_sockaddr(addr) else {
        return ffi::real_connect(sockfd, addr, addrlen);
    };

    if ep.ip_v6.is_some() {
        let mode = cfg.proxy_rules.ipv6_mode.as_str();
        if mode.eq_ignore_ascii_case("direct") {
            return ffi::real_connect(sockfd, addr, addrlen);
        }
        if !mode.eq_ignore_ascii_case("proxy") {
            crate::log_warn!(
                "[IPv6] 已阻止连接 (ipv6_mode=block): {}:{}",
                ep.host,
                ep.port
            );
            return fail(libc::EAFNOSUPPORT);
        }
    }

    if ep.is_loopback() || is_proxy_self(cfg, &ep) {
        return ffi::real_connect(sockfd, addr, addrlen);
    }

    if ep.fake_missing {
        crate::log_warn!(
            "[FakeIP] 虚拟地址没有域名映射，拒绝连接: {}:{}",
            ep.host,
            ep.port
        );
        return fail(libc::EHOSTUNREACH);
    }

    if let Some(decision) = route_decision(cfg, &ep, "tcp") {
        if decision == Action::Direct {
            crate::log_debug!("[Route] direct target={}:{}", ep.host, ep.port);
            return connect_direct(sockfd, addr, addrlen, &ep);
        }
    } else if cfg.proxy_rules.routing.use_default_private && ep.is_lan() && !ep.is_fake {
        return ffi::real_connect(sockfd, addr, addrlen);
    }

    if ep.port == 53
        && (cfg.proxy_rules.dns_mode.eq_ignore_ascii_case("direct")
            || cfg.proxy_rules.dns_mode.trim().is_empty())
    {
        return connect_direct(sockfd, addr, addrlen, &ep);
    }
    if !cfg.port_allowed(ep.port) {
        return connect_direct(sockfd, addr, addrlen, &ep);
    }

    proxy_tcp(sockfd, addr, &ep)
}

fn dns_uses_real_resolver(cfg: &AppConfig, host: &str, port: u16) -> bool {
    match cfg.compiled_routes.decide(route::Query {
        host,
        ip_v4: None,
        ip_v6: None,
        port,
        protocol: "tcp",
    }) {
        Some(hit) => hit.action == Action::Direct,
        None => false,
    }
}

fn route_decision(cfg: &AppConfig, ep: &Endpoint, protocol: &str) -> Option<Action> {
    cfg.compiled_routes
        .decide(route::Query {
            host: &ep.host,
            ip_v4: ep.ip_v4.filter(|_| !ep.is_fake),
            ip_v6: ep.ip_v6,
            port: ep.port,
            protocol,
        })
        .map(|hit| {
            if let Some(rule) = hit.rule.as_deref() {
                crate::log_debug!(
                    "[Route] {} rule={rule} target={}:{}",
                    if hit.action == Action::Direct {
                        "direct"
                    } else {
                        "proxy"
                    },
                    ep.host,
                    ep.port
                );
            }
            hit.action
        })
}

unsafe fn connect_direct(
    fd: libc::c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
    ep: &Endpoint,
) -> libc::c_int {
    if ep.is_fake && !ep.fake_missing {
        let timeout = sockio::positive_timeout(crate::get_config().timeout.connect, 5000);
        return match connect_resolved(fd, &ep.host, ep.port, timeout) {
            Ok(()) => 0,
            Err(err) => {
                crate::log_warn!(
                    "[Route] FakeIP 目标直连重解析失败: {}:{} (errno={err})",
                    ep.host,
                    ep.port
                );
                fail(err)
            }
        };
    }
    ffi::real_connect(fd, addr, addrlen)
}

unsafe fn connect_resolved(
    fd: libc::c_int,
    host: &str,
    port: u16,
    timeout_ms: u32,
) -> Result<(), i32> {
    let family = sockio::socket_domain(fd).unwrap_or(libc::AF_UNSPEC);
    let c_host = CString::new(host).map_err(|_| libc::EINVAL)?;
    let service = CString::new(port.to_string()).map_err(|_| libc::EINVAL)?;
    let mut hints: libc::addrinfo = std::mem::zeroed();
    hints.ai_family = family;
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    let rc = ffi::real_getaddrinfo(c_host.as_ptr(), service.as_ptr(), &hints, &mut res);
    if rc != 0 || res.is_null() {
        return Err(libc::EHOSTUNREACH);
    }
    let mut ai = res;
    let mut last = libc::EHOSTUNREACH;
    while !ai.is_null() {
        let item = &*ai;
        match sockio::connect_timeout(fd, item.ai_addr, item.ai_addrlen, timeout_ms) {
            Ok(()) => {
                ffi::real_freeaddrinfo(res);
                return Ok(());
            }
            Err(err) => last = err,
        }
        ai = item.ai_next;
    }
    ffi::real_freeaddrinfo(res);
    Err(last)
}

unsafe fn proxy_tcp(fd: libc::c_int, addr: *const libc::sockaddr, ep: &Endpoint) -> libc::c_int {
    let cfg = crate::get_config();
    let connect_ms = sockio::positive_timeout(cfg.timeout.connect, 5000);
    let send_ms = sockio::positive_timeout(cfg.timeout.send, 5000);
    let recv_ms = sockio::positive_timeout(cfg.timeout.recv, 5000);

    if let Err(err) = sockio::connect_fd_to_proxy(fd, cfg, connect_ms) {
        crate::log_warn!(
            "[代理/连接] 连接代理服务器 {}:{} 失败 (errno={err})",
            cfg.proxy.host,
            cfg.proxy.port
        );
        return fail(err);
    }

    let host = Some(ep.host.as_str());
    let handshake = if cfg.proxy.r#type.eq_ignore_ascii_case("http") {
        crate::http::http_handshake(fd, host, ep.port, addr, send_ms, recv_ms)
    } else {
        crate::socks5::socks5_handshake(fd, host, ep.port, addr, send_ms, recv_ms)
    };

    match handshake {
        Ok(()) => {
            let shown = if ep.is_fake {
                ep.host.as_str()
            } else {
                ep.host.as_str()
            };
            crate::log_info!("[代理/成功] 隧道建立: {shown}:{} (fd={fd})", ep.port);
            0
        }
        Err(err) => {
            crate::log_warn!("[代理/失败] 握手失败: {}:{} ({err})", ep.host, ep.port);
            fail(libc::ECONNREFUSED)
        }
    }
}

fn is_proxy_self(cfg: &AppConfig, ep: &Endpoint) -> bool {
    if ep.port != cfg.proxy.port {
        return false;
    }
    let ips = proxy_ips(cfg);
    if let Some(ip) = ep.ip_v4 {
        if ips.v4.contains(&ip) {
            return true;
        }
    }
    if let Some(ip) = ep.ip_v6 {
        if ips.v6.contains(&ip) {
            return true;
        }
    }
    route::normalize_host(&ep.host) == route::normalize_host(&cfg.proxy.host)
}

fn proxy_ips(cfg: &AppConfig) -> &ProxyIps {
    PROXY_IPS.get_or_init(|| {
        let mut found = ProxyIps {
            v4: Vec::new(),
            v6: Vec::new(),
        };
        let host = cfg.proxy.host.trim();
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            found.v4.push(u32::from(ip));
            return found;
        }
        if let Ok(ip) = host.parse::<Ipv6Addr>() {
            found.v6.push(ip.octets());
            return found;
        }
        unsafe {
            if let Ok(c_host) = CString::new(host) {
                let mut hints: libc::addrinfo = std::mem::zeroed();
                hints.ai_socktype = libc::SOCK_STREAM;
                hints.ai_family = libc::AF_UNSPEC;
                let mut res: *mut libc::addrinfo = std::ptr::null_mut();
                if ffi::real_getaddrinfo(c_host.as_ptr(), std::ptr::null(), &hints, &mut res) == 0 {
                    let mut ai = res;
                    while !ai.is_null() {
                        let item = &*ai;
                        if item.ai_family == libc::AF_INET && !item.ai_addr.is_null() {
                            let sin = &*(item.ai_addr as *const libc::sockaddr_in);
                            found.v4.push(u32::from_be(sin.sin_addr.s_addr));
                        } else if item.ai_family == libc::AF_INET6 && !item.ai_addr.is_null() {
                            let sin6 = &*(item.ai_addr as *const libc::sockaddr_in6);
                            found.v6.push(sin6.sin6_addr.s6_addr);
                        }
                        ai = item.ai_next;
                    }
                    ffi::real_freeaddrinfo(res);
                }
            }
        }
        found
    })
}

unsafe fn service_port(service: *const libc::c_char) -> u16 {
    if service.is_null() {
        return 0;
    }
    let Ok(text) = CStr::from_ptr(service).to_str() else {
        return 0;
    };
    if let Ok(port) = text.parse::<u16>() {
        return port;
    }
    let Ok(name) = CString::new(text) else {
        return 0;
    };
    let proto = CString::new("tcp").unwrap();
    let ent = libc::getservbyname(name.as_ptr(), proto.as_ptr());
    if ent.is_null() {
        0
    } else {
        u16::from_be((*ent).s_port as u16)
    }
}
