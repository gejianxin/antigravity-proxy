use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};

use crate::config::AppConfig;
use crate::endpoint::{self, Endpoint};
use crate::ffi;
use crate::route::{self, Action, UdpAction};
use crate::sockio::{self, fail};
use crate::socks5;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static BLOCK_LOGS: AtomicUsize = AtomicUsize::new(0);

struct Session {
    control: libc::c_int,
    relay: libc::sockaddr_storage,
    relay_len: libc::socklen_t,
    connected: bool,
    host: String,
    port: u16,
}

static SESSIONS: LazyLock<Mutex<HashMap<libc::c_int, Session>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn sessions() -> std::sync::MutexGuard<'static, HashMap<libc::c_int, Session>> {
    SESSIONS.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn has_sessions() -> bool {
    LIVE.load(Ordering::Relaxed) > 0
}

pub fn inspect_udp() -> bool {
    if has_sessions() {
        return true;
    }
    !matches!(crate::get_config().udp_action(), UdpAction::Direct)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Decision {
    Direct,
    Block,
    Proxy,
}

fn decide(cfg: &AppConfig, ep: &Endpoint) -> Decision {
    if ep.is_loopback() {
        return Decision::Direct;
    }
    if ep.fake_missing {
        return Decision::Block;
    }
    match cfg.udp_action() {
        UdpAction::Direct => Decision::Direct,
        UdpAction::Block => {
            if ep.port == 53 {
                Decision::Direct
            } else {
                Decision::Block
            }
        }
        UdpAction::Proxy => {
            if !cfg.proxy.r#type.eq_ignore_ascii_case("socks5") {
                return fallback_decision(cfg);
            }
            if ep.port == 53
                && (cfg.proxy_rules.dns_mode.eq_ignore_ascii_case("direct")
                    || cfg.proxy_rules.dns_mode.trim().is_empty())
            {
                return Decision::Direct;
            }
            if ep.ip_v6.is_some() {
                if cfg.proxy_rules.ipv6_mode.eq_ignore_ascii_case("direct") {
                    return Decision::Direct;
                }
                if !cfg.proxy_rules.ipv6_mode.eq_ignore_ascii_case("proxy") {
                    return Decision::Block;
                }
            }
            if let Some(hit) = cfg.compiled_routes.decide(route::Query {
                host: &ep.host,
                ip_v4: ep.ip_v4.filter(|_| !ep.is_fake),
                ip_v6: ep.ip_v6,
                port: ep.port,
                protocol: "udp",
            }) {
                if hit.action == Action::Direct {
                    return Decision::Direct;
                }
            } else if cfg.proxy_rules.routing.use_default_private && ep.is_lan() && !ep.is_fake {
                return Decision::Direct;
            }
            if !cfg.port_allowed(ep.port) {
                return Decision::Direct;
            }
            Decision::Proxy
        }
    }
}

fn fallback_decision(cfg: &AppConfig) -> Decision {
    if cfg.proxy_rules.udp_fallback.eq_ignore_ascii_case("direct") {
        Decision::Direct
    } else {
        Decision::Block
    }
}

pub unsafe fn handle_connect(
    fd: libc::c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> libc::c_int {
    let Some(ep) = endpoint::from_sockaddr(addr) else {
        return ffi::real_connect(fd, addr, addrlen);
    };
    let cfg = crate::get_config();
    match decide(cfg, &ep) {
        Decision::Direct => ffi::real_connect(fd, addr, addrlen),
        Decision::Block => {
            log_block(&ep);
            let err = if ep.fake_missing {
                libc::EHOSTUNREACH
            } else {
                libc::EACCES
            };
            fail(err)
        }
        Decision::Proxy => match ensure_session(fd, &ep.host, ep.port, true) {
            Ok(()) => 0,
            Err(err) => {
                if cfg.proxy_rules.udp_fallback.eq_ignore_ascii_case("direct") {
                    crate::log_warn!(
                        "[UDP] 代理失败，按 udp_fallback=direct 回退直连: {}:{} ({})",
                        ep.host,
                        ep.port,
                        err
                    );
                    ffi::real_connect(fd, addr, addrlen)
                } else {
                    crate::log_warn!(
                        "[UDP] SOCKS5 UDP Associate 失败: {}:{} (errno={err})",
                        ep.host,
                        ep.port
                    );
                    fail(err)
                }
            }
        },
    }
}

pub unsafe fn on_send(
    fd: libc::c_int,
    buf: *const libc::c_void,
    len: libc::size_t,
    flags: libc::c_int,
) -> Option<libc::ssize_t> {
    if !has_sessions() && !matches!(crate::get_config().udp_action(), UdpAction::Block) {
        return None;
    }
    let connected_target = {
        let map = sessions();
        map.get(&fd)
            .filter(|session| session.connected)
            .map(|session| (session.host.clone(), session.port))
    };
    if let Some((host, port)) = connected_target {
        return Some(send_wrapped(
            fd,
            &host,
            port,
            buf,
            len,
            flags,
            true,
            std::ptr::null(),
            0,
        ));
    }
    if sockio::socket_type(fd) != Some(libc::SOCK_DGRAM) {
        return None;
    }
    let cfg = crate::get_config();
    if !matches!(cfg.udp_action(), UdpAction::Block) {
        return None;
    }
    if let Some(ep) = peer_endpoint(fd) {
        if decide(cfg, &ep) == Decision::Block {
            log_block(&ep);
            let err = if ep.fake_missing {
                libc::EHOSTUNREACH
            } else {
                libc::EACCES
            };
            return Some(fail(err) as libc::ssize_t);
        }
    }
    None
}

pub unsafe fn on_sendto(
    fd: libc::c_int,
    buf: *const libc::c_void,
    len: libc::size_t,
    flags: libc::c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> Option<libc::ssize_t> {
    if sockio::socket_type(fd) != Some(libc::SOCK_DGRAM) && !sessions().contains_key(&fd) {
        return None;
    }
    let Some(ep) = endpoint::from_sockaddr(addr) else {
        return None;
    };
    let cfg = crate::get_config();
    match decide(cfg, &ep) {
        Decision::Direct => None,
        Decision::Block => {
            log_block(&ep);
            let err = if ep.fake_missing {
                libc::EHOSTUNREACH
            } else {
                libc::EACCES
            };
            Some(fail(err) as libc::ssize_t)
        }
        Decision::Proxy => match ensure_session(fd, &ep.host, ep.port, false) {
            Ok(()) => {
                let connected = sessions().get(&fd).map(|s| s.connected).unwrap_or(false);
                Some(send_wrapped(
                    fd, &ep.host, ep.port, buf, len, flags, connected, addr, addrlen,
                ))
            }
            Err(err) => {
                if cfg.proxy_rules.udp_fallback.eq_ignore_ascii_case("direct") {
                    None
                } else {
                    Some(fail(err) as libc::ssize_t)
                }
            }
        },
    }
}

pub unsafe fn on_recv(
    fd: libc::c_int,
    buf: *mut libc::c_void,
    len: libc::size_t,
    flags: libc::c_int,
) -> Option<libc::ssize_t> {
    if !sessions().contains_key(&fd) {
        return None;
    }
    Some(recv_wrapped(
        fd,
        buf,
        len,
        flags,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    ))
}

pub unsafe fn on_recvfrom(
    fd: libc::c_int,
    buf: *mut libc::c_void,
    len: libc::size_t,
    flags: libc::c_int,
    addr: *mut libc::sockaddr,
    addrlen: *mut libc::socklen_t,
) -> Option<libc::ssize_t> {
    if !sessions().contains_key(&fd) {
        return None;
    }
    Some(recv_wrapped(fd, buf, len, flags, addr, addrlen))
}

pub unsafe fn on_sendmsg(
    fd: libc::c_int,
    msg: *const libc::msghdr,
    flags: libc::c_int,
) -> Option<libc::ssize_t> {
    if msg.is_null() {
        return None;
    }
    if !sessions().contains_key(&fd) && sockio::socket_type(fd) != Some(libc::SOCK_DGRAM) {
        return None;
    }
    let msg = &*msg;
    if !msg.msg_name.is_null() {
        let gathered = gather_iov(msg.msg_iov, msg.msg_iovlen);
        return on_sendto(
            fd,
            gathered.as_ptr() as *const libc::c_void,
            gathered.len(),
            flags,
            msg.msg_name as *const libc::sockaddr,
            msg.msg_namelen,
        );
    }
    let gathered = gather_iov(msg.msg_iov, msg.msg_iovlen);
    on_send(
        fd,
        gathered.as_ptr() as *const libc::c_void,
        gathered.len(),
        flags,
    )
}

pub unsafe fn on_recvmsg(
    fd: libc::c_int,
    msg: *mut libc::msghdr,
    flags: libc::c_int,
) -> Option<libc::ssize_t> {
    if msg.is_null() || !sessions().contains_key(&fd) {
        return None;
    }
    let msg = &mut *msg;
    let cap = iov_cap(msg.msg_iov, msg.msg_iovlen).saturating_add(512);
    let mut raw = vec![0u8; cap.max(2048)];
    let n = ffi::real_recv(fd, raw.as_mut_ptr() as *mut libc::c_void, raw.len(), flags);
    if n < 0 {
        return Some(n);
    }
    match socks5::unwrap_udp(&raw[..n as usize]) {
        Ok(pkt) => {
            let copied = scatter_iov(msg.msg_iov, msg.msg_iovlen, pkt.payload);
            if let Some((ip, port)) = pkt.src {
                write_src(
                    msg.msg_name as *mut libc::sockaddr,
                    &mut msg.msg_namelen,
                    ip,
                    port,
                );
            }
            if copied < pkt.payload.len() {
                msg.msg_flags |= libc::MSG_TRUNC;
            }
            Some(copied as libc::ssize_t)
        }
        Err(_) => Some(fail(libc::EIO) as libc::ssize_t),
    }
}

pub unsafe fn on_sendmmsg(
    fd: libc::c_int,
    msgvec: *mut libc::mmsghdr,
    vlen: libc::c_uint,
    flags: libc::c_int,
) -> Option<libc::c_int> {
    if msgvec.is_null() || vlen == 0 {
        return None;
    }
    if !sessions().contains_key(&fd) && sockio::socket_type(fd) != Some(libc::SOCK_DGRAM) {
        return None;
    }
    let mut completed = 0u32;
    for index in 0..vlen {
        let item = &mut *msgvec.add(index as usize);
        match on_sendmsg(fd, &item.msg_hdr, flags) {
            None => {
                if completed == 0 {
                    return None;
                }
                break;
            }
            Some(n) if n < 0 => {
                if completed == 0 {
                    return Some(-1);
                }
                break;
            }
            Some(n) => {
                item.msg_len = n as libc::c_uint;
                completed += 1;
            }
        }
    }
    Some(completed as libc::c_int)
}

pub unsafe fn on_recvmmsg(
    fd: libc::c_int,
    msgvec: *mut libc::mmsghdr,
    vlen: libc::c_uint,
    flags: libc::c_int,
) -> Option<libc::c_int> {
    if msgvec.is_null() || vlen == 0 || !sessions().contains_key(&fd) {
        return None;
    }
    let mut completed = 0u32;
    for index in 0..vlen {
        let item = &mut *msgvec.add(index as usize);
        match on_recvmsg(fd, &mut item.msg_hdr, flags) {
            Some(n) if n < 0 => {
                if completed == 0 {
                    return Some(-1);
                }
                break;
            }
            Some(n) => {
                item.msg_len = n as libc::c_uint;
                completed += 1;
                if flags & libc::MSG_DONTWAIT != 0 || sock_is_nonblocking(fd) {
                    if index + 1 < vlen {
                        break;
                    }
                }
            }
            None => break,
        }
    }
    if completed == 0 {
        None
    } else {
        Some(completed as libc::c_int)
    }
}

unsafe fn sock_is_nonblocking(fd: libc::c_int) -> bool {
    let flags = libc::fcntl(fd, libc::F_GETFL, 0);
    flags >= 0 && flags & libc::O_NONBLOCK != 0
}

pub unsafe fn on_close(fd: libc::c_int) -> libc::c_int {
    if let Some(session) = sessions().remove(&fd) {
        LIVE.fetch_sub(1, Ordering::Relaxed);
        ffi::real_close(session.control);
    }
    ffi::real_close(fd)
}

fn log_block(ep: &Endpoint) {
    let n = BLOCK_LOGS.fetch_add(1, Ordering::Relaxed);
    if n < 8 || n % 64 == 0 {
        crate::log_warn!(
            "[UDP] 已阻止数据报: {}:{} (udp_mode/ipv6_mode)",
            ep.host,
            ep.port
        );
    }
}

unsafe fn peer_endpoint(fd: libc::c_int) -> Option<Endpoint> {
    let mut storage: libc::sockaddr_storage = std::mem::zeroed();
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    if libc::getpeername(fd, &mut storage as *mut _ as *mut libc::sockaddr, &mut len) != 0 {
        return None;
    }
    endpoint::from_sockaddr(&storage as *const _ as *const libc::sockaddr)
}

unsafe fn ensure_session(
    fd: libc::c_int,
    host: &str,
    port: u16,
    connect_relay: bool,
) -> Result<(), i32> {
    let existing = {
        let mut map = sessions();
        if let Some(session) = map.get_mut(&fd) {
            session.host = host.to_string();
            session.port = port;
            if connect_relay && !session.connected {
                Some((session.relay, session.relay_len))
            } else {
                return Ok(());
            }
        } else {
            None
        }
    };
    if let Some((relay, relay_len)) = existing {
        connect_app_to_relay(fd, &relay, relay_len)?;
        if let Some(session) = sessions().get_mut(&fd) {
            session.connected = true;
        }
        return Ok(());
    }

    let cfg = crate::get_config();
    let send_ms = sockio::positive_timeout(cfg.timeout.send, 5000);
    let recv_ms = sockio::positive_timeout(cfg.timeout.recv, 5000);
    let connect_ms = sockio::positive_timeout(cfg.timeout.connect, 5000);
    let family = if cfg.proxy.host.parse::<Ipv6Addr>().is_ok() {
        libc::AF_INET6
    } else {
        libc::AF_INET
    };
    let control = libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
    if control < 0 {
        return Err(sockio::errno());
    }
    if let Err(err) = sockio::connect_fd_to_proxy(control, cfg, connect_ms) {
        ffi::real_close(control);
        return Err(err);
    }
    let relay = match socks5::udp_associate(control, send_ms, recv_ms) {
        Ok(relay) => relay,
        Err(_) => {
            ffi::real_close(control);
            return Err(libc::ECONNREFUSED);
        }
    };
    let (relay_addr, relay_len) = match adapt_relay(fd, &relay.storage, relay.len) {
        Ok(v) => v,
        Err(err) => {
            ffi::real_close(control);
            return Err(err);
        }
    };
    if connect_relay {
        if let Err(err) = connect_app_to_relay(fd, &relay_addr, relay_len) {
            ffi::real_close(control);
            return Err(err);
        }
    }

    let mut map = sessions();
    if let Some(existing) = map.get(&fd) {
        let _ = existing;
        drop(map);
        ffi::real_close(control);
        return ensure_session(fd, host, port, connect_relay);
    }
    map.insert(
        fd,
        Session {
            control,
            relay: relay_addr,
            relay_len,
            connected: connect_relay,
            host: host.to_string(),
            port,
        },
    );
    LIVE.fetch_add(1, Ordering::Relaxed);
    crate::log_info!("[UDP] SOCKS5 UDP Associate 已建立: {host}:{port} (fd={fd})");
    Ok(())
}

unsafe fn connect_app_to_relay(
    fd: libc::c_int,
    relay: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Result<(), i32> {
    sockio::prepare_v6_proxy_socket(fd);
    let timeout = sockio::positive_timeout(crate::get_config().timeout.connect, 5000);
    sockio::connect_timeout(fd, relay as *const _ as *const libc::sockaddr, len, timeout)
}

unsafe fn adapt_relay(
    fd: libc::c_int,
    relay: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Result<(libc::sockaddr_storage, libc::socklen_t), i32> {
    let app_domain = sockio::socket_domain(fd).unwrap_or(libc::AF_INET);
    let relay_family = relay.ss_family as libc::c_int;
    if app_domain == relay_family {
        return Ok((*relay, len));
    }
    if app_domain == libc::AF_INET6 && relay_family == libc::AF_INET {
        let sin = &*(relay as *const _ as *const libc::sockaddr_in);
        let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
        let mut sin6: libc::sockaddr_in6 = std::mem::zeroed();
        sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        sin6.sin6_port = sin.sin_port;
        let o = ip.octets();
        sin6.sin6_addr.s6_addr = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, o[0], o[1], o[2], o[3],
        ];
        let mut storage: libc::sockaddr_storage = std::mem::zeroed();
        std::ptr::copy_nonoverlapping(
            &sin6 as *const _ as *const u8,
            &mut storage as *mut _ as *mut u8,
            std::mem::size_of::<libc::sockaddr_in6>(),
        );
        return Ok((
            storage,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        ));
    }
    Err(libc::EAFNOSUPPORT)
}

unsafe fn send_wrapped(
    fd: libc::c_int,
    host: &str,
    port: u16,
    buf: *const libc::c_void,
    len: libc::size_t,
    flags: libc::c_int,
    connected: bool,
    _orig_addr: *const libc::sockaddr,
    _orig_len: libc::socklen_t,
) -> libc::ssize_t {
    if buf.is_null() && len > 0 {
        return fail(libc::EFAULT) as libc::ssize_t;
    }
    if len > 65535 {
        return fail(libc::EMSGSIZE) as libc::ssize_t;
    }
    let payload = if len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(buf as *const u8, len)
    };
    let packet = match socks5::wrap_udp(host, port, payload) {
        Ok(packet) => packet,
        Err(_) => return fail(libc::EINVAL) as libc::ssize_t,
    };
    let sent = if connected {
        ffi::real_send(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            flags,
        )
    } else {
        let (relay, relay_len) = {
            let map = sessions();
            match map.get(&fd) {
                Some(session) => (session.relay, session.relay_len),
                None => return fail(libc::ENOTCONN) as libc::ssize_t,
            }
        };
        ffi::real_sendto(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            flags,
            &relay as *const _ as *const libc::sockaddr,
            relay_len,
        )
    };
    if sent < 0 {
        return sent;
    }
    len as libc::ssize_t
}

unsafe fn recv_wrapped(
    fd: libc::c_int,
    buf: *mut libc::c_void,
    len: libc::size_t,
    flags: libc::c_int,
    addr: *mut libc::sockaddr,
    addrlen: *mut libc::socklen_t,
) -> libc::ssize_t {
    let cap = len.saturating_add(512).max(2048);
    let mut raw = vec![0u8; cap];
    let n = ffi::real_recv(fd, raw.as_mut_ptr() as *mut libc::c_void, raw.len(), flags);
    if n < 0 {
        return n;
    }
    match socks5::unwrap_udp(&raw[..n as usize]) {
        Ok(pkt) => {
            if buf.is_null() && len > 0 {
                return fail(libc::EFAULT) as libc::ssize_t;
            }
            let copy = std::cmp::min(len, pkt.payload.len());
            if copy > 0 {
                std::ptr::copy_nonoverlapping(pkt.payload.as_ptr(), buf as *mut u8, copy);
            }
            if let Some((ip, port)) = pkt.src {
                write_src(addr, addrlen, ip, port);
            }
            copy as libc::ssize_t
        }
        Err(_) => fail(libc::EIO) as libc::ssize_t,
    }
}

unsafe fn write_src(
    addr: *mut libc::sockaddr,
    addrlen: *mut libc::socklen_t,
    ip: IpAddr,
    port: u16,
) {
    if addr.is_null() || addrlen.is_null() || *addrlen == 0 {
        return;
    }
    match ip {
        IpAddr::V4(ip) => {
            let mut sin: libc::sockaddr_in = std::mem::zeroed();
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = port.to_be();
            sin.sin_addr.s_addr = u32::from(ip).to_be();
            let n = std::mem::size_of::<libc::sockaddr_in>();
            let copy = std::cmp::min(*addrlen as usize, n);
            std::ptr::copy_nonoverlapping(&sin as *const _ as *const u8, addr as *mut u8, copy);
            *addrlen = n as libc::socklen_t;
        }
        IpAddr::V6(ip) => {
            let mut sin6: libc::sockaddr_in6 = std::mem::zeroed();
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = port.to_be();
            sin6.sin6_addr.s6_addr = ip.octets();
            let n = std::mem::size_of::<libc::sockaddr_in6>();
            let copy = std::cmp::min(*addrlen as usize, n);
            std::ptr::copy_nonoverlapping(&sin6 as *const _ as *const u8, addr as *mut u8, copy);
            *addrlen = n as libc::socklen_t;
        }
    }
}

unsafe fn gather_iov(iov: *const libc::iovec, count: libc::size_t) -> Vec<u8> {
    if iov.is_null() || count == 0 {
        return Vec::new();
    }
    let items = std::slice::from_raw_parts(iov, count);
    let mut out = Vec::new();
    for item in items {
        if item.iov_base.is_null() || item.iov_len == 0 {
            continue;
        }
        let take = std::cmp::min(item.iov_len, 65535 - out.len());
        let slice = std::slice::from_raw_parts(item.iov_base as *const u8, take);
        out.extend_from_slice(slice);
        if out.len() >= 65535 {
            break;
        }
    }
    out
}

unsafe fn iov_cap(iov: *const libc::iovec, count: libc::size_t) -> usize {
    if iov.is_null() || count == 0 {
        return 0;
    }
    std::slice::from_raw_parts(iov, count)
        .iter()
        .fold(0usize, |acc, item| acc.saturating_add(item.iov_len))
}

unsafe fn scatter_iov(iov: *mut libc::iovec, count: libc::size_t, data: &[u8]) -> usize {
    if iov.is_null() || count == 0 {
        return 0;
    }
    let items = std::slice::from_raw_parts(iov, count);
    let mut off = 0;
    for item in items {
        if off >= data.len() {
            break;
        }
        if item.iov_base.is_null() || item.iov_len == 0 {
            continue;
        }
        let n = std::cmp::min(item.iov_len, data.len() - off);
        std::ptr::copy_nonoverlapping(data[off..].as_ptr(), item.iov_base as *mut u8, n);
        off += n;
    }
    off
}
