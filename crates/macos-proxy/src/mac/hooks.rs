//! dyld `__interpose` hooks for the BSD socket calls Antigravity uses.
//!
//! The real libSystem entry points are called directly. dyld does not
//! rewrite binds inside the interposing image. `dlsym` is unsafe here: on
//! macOS it can return this dylib's replacement and the hook recurses until
//! the stack overflows (SIGSEGV, exit 139) before the caller prints anything.

use std::ffi::{CStr, CString};
use std::net::Ipv4Addr;
use std::sync::OnceLock;

use agy_core::config::AppConfig;
use agy_core::fakeip;
use agy_core::routing::{self, Action, DecideOpts, Endpoint, Proto};

use super::child;
use super::net;
use super::{is_targeted, log, try_startup};

static CONFIG: OnceLock<AppConfig> = OnceLock::new();

#[repr(C)]
struct Interpose {
    replacement: *const (),
    original: *const (),
}

unsafe impl Sync for Interpose {}

pub fn install(cfg: AppConfig) {
    let _ = CONFIG.set(cfg);
}

pub fn config() -> &'static AppConfig {
    CONFIG.get().expect("macos proxy config")
}

extern "C" {
    fn gethostbyname(name: *const libc::c_char) -> *mut libc::hostent;
}

fn trace(msg: &[u8]) {
    unsafe {
        if libc::getenv(b"ANTIGRAVITY_PROXY_DEBUG\0".as_ptr() as *const libc::c_char).is_null() {
            return;
        }
        libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
    }
}

pub unsafe fn raw_connect(fd: libc::c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> libc::c_int {
    libc::connect(fd, addr, len)
}

pub(super) unsafe fn raw_send(fd: libc::c_int, buf: *const libc::c_void, len: usize, flags: libc::c_int) -> isize {
    libc::send(fd, buf, len, flags)
}

pub(super) unsafe fn raw_recv(fd: libc::c_int, buf: *mut libc::c_void, len: usize, flags: libc::c_int) -> isize {
    libc::recv(fd, buf, len, flags)
}

unsafe fn raw_getaddrinfo(
    node: *const libc::c_char,
    service: *const libc::c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> libc::c_int {
    libc::getaddrinfo(node, service, hints, res)
}

unsafe fn raw_sendto(
    fd: libc::c_int,
    buf: *const libc::c_void,
    len: usize,
    flags: libc::c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> isize {
    libc::sendto(fd, buf, len, flags, addr, addrlen)
}

pub unsafe extern "C" fn hook_getaddrinfo(
    node: *const libc::c_char,
    service: *const libc::c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> libc::c_int {
    trace(b"[agy] getaddrinfo\n");
    if node.is_null() || !try_startup() || !is_targeted(config()) {
        return raw_getaddrinfo(node, service, hints, res);
    }
    let name = match CStr::from_ptr(node).to_str() {
        Ok(s) => s,
        Err(_) => return raw_getaddrinfo(node, service, hints, res),
    };
    if !hints.is_null() && ((*hints).ai_flags & libc::AI_NUMERICHOST) != 0 {
        return raw_getaddrinfo(node, service, hints, res);
    }
    if !routing::should_fake_dns(config(), name) {
        return raw_getaddrinfo(node, service, hints, res);
    }
    let ip = fakeip::get_or_create(name);
    if ip == 0 {
        return raw_getaddrinfo(node, service, hints, res);
    }
    let mut literal = Ipv4Addr::from(ip).to_string();
    let family = if hints.is_null() {
        libc::AF_UNSPEC
    } else {
        (*hints).ai_family
    };
    if family == libc::AF_INET6 {
        literal = format!("::ffff:{literal}");
    } else if family != libc::AF_UNSPEC && family != libc::AF_INET {
        return raw_getaddrinfo(node, service, hints, res);
    }
    let Ok(c_lit) = CString::new(literal) else {
        return raw_getaddrinfo(node, service, hints, res);
    };
    log(&format!("[FakeIP] {name}"));
    raw_getaddrinfo(c_lit.as_ptr(), service, hints, res)
}

pub unsafe extern "C" fn hook_freeaddrinfo(res: *mut libc::addrinfo) {
    let _ = try_startup();
    libc::freeaddrinfo(res);
}

pub unsafe extern "C" fn hook_gethostbyname(name: *const libc::c_char) -> *mut libc::hostent {
    if name.is_null() || !try_startup() || !is_targeted(config()) {
        return gethostbyname(name);
    }
    let host = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return gethostbyname(name),
    };
    if !routing::should_fake_dns(config(), host) {
        return gethostbyname(name);
    }
    let ip = fakeip::get_or_create(host);
    if ip == 0 {
        return gethostbyname(name);
    }
    let literal = CString::new(Ipv4Addr::from(ip).to_string()).unwrap_or_default();
    gethostbyname(literal.as_ptr())
}

pub unsafe extern "C" fn hook_connect(
    fd: libc::c_int,
    addr: *const libc::sockaddr,
    len: libc::socklen_t,
) -> libc::c_int {
    if addr.is_null() || !try_startup() || !is_targeted(config()) {
        return raw_connect(fd, addr, len);
    }
    let Some(ep) = endpoint_of(addr, socket_proto(fd)) else {
        return raw_connect(fd, addr, len);
    };
    match routing::decide(config(), &ep.view(), DecideOpts::MACOS) {
        Action::Direct => raw_connect(fd, addr, len),
        Action::Block => {
            *libc::__error() = if ep.v6_only {
                libc::EAFNOSUPPORT
            } else {
                libc::EACCES
            };
            -1
        }
        Action::Proxy => {
            let host = ep.domain.clone().unwrap_or_else(|| display_ep(&ep));
            if net::tcp_proxy(fd, ep.family, &host, ep.port, config()) {
                0
            } else {
                -1
            }
        }
    }
}

pub unsafe extern "C" fn hook_sendto(
    fd: libc::c_int,
    buf: *const libc::c_void,
    len: usize,
    flags: libc::c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> isize {
    if addr.is_null() || !try_startup() || !is_targeted(config()) || socket_proto(fd) != Proto::Udp {
        return raw_sendto(fd, buf, len, flags, addr, addrlen);
    }
    let Some(ep) = endpoint_of(addr, Proto::Udp) else {
        return raw_sendto(fd, buf, len, flags, addr, addrlen);
    };
    match routing::decide(config(), &ep.view(), DecideOpts::MACOS) {
        Action::Direct => raw_sendto(fd, buf, len, flags, addr, addrlen),
        Action::Block => {
            *libc::__error() = libc::EACCES;
            -1
        }
        Action::Proxy => {
            // Synchronous UDP associate is not wrapped on macOS yet. Follow
            // udp_fallback so QUIC cannot silently bypass the proxy.
            if config().proxy_rules.udp_fallback.eq_ignore_ascii_case("direct") {
                log("UDP associate 未实现，按 udp_fallback=direct 放行");
                raw_sendto(fd, buf, len, flags, addr, addrlen)
            } else {
                log("UDP associate 未实现，按 udp_fallback 阻断");
                *libc::__error() = libc::EACCES;
                -1
            }
        }
    }
}

pub unsafe extern "C" fn hook_send(
    fd: libc::c_int,
    buf: *const libc::c_void,
    len: usize,
    flags: libc::c_int,
) -> isize {
    raw_send(fd, buf, len, flags)
}

pub unsafe extern "C" fn hook_recv(
    fd: libc::c_int,
    buf: *mut libc::c_void,
    len: usize,
    flags: libc::c_int,
) -> isize {
    raw_recv(fd, buf, len, flags)
}

pub unsafe extern "C" fn hook_posix_spawn(
    pid: *mut i32,
    path: *const libc::c_char,
    file_actions: *const libc::c_void,
    attrp: *const libc::c_void,
    argv: *const *mut libc::c_char,
    envp: *const *mut libc::c_char,
) -> i32 {
    if !try_startup() {
        return libc::posix_spawn(
            pid,
            path,
            file_actions as *const libc::posix_spawn_file_actions_t,
            attrp as *const libc::posix_spawnattr_t,
            argv,
            envp,
        );
    }
    child::spawn(pid, path, file_actions, attrp, argv, envp)
}

pub unsafe extern "C" fn hook_execve(
    path: *const libc::c_char,
    argv: *const *mut libc::c_char,
    envp: *const *mut libc::c_char,
) -> i32 {
    if !try_startup() {
        return libc::execve(
            path,
            argv as *const *const libc::c_char,
            envp as *const *const libc::c_char,
        );
    }
    child::execve(path, argv, envp)
}

struct OwnedEp {
    domain: Option<String>,
    v4: Option<u32>,
    v6: Option<[u8; 16]>,
    port: u16,
    fake: bool,
    proto: Proto,
    family: i32,
    v6_only: bool,
}

impl OwnedEp {
    fn view(&self) -> Endpoint<'_> {
        Endpoint {
            domain: self.domain.as_deref(),
            ipv4: self.v4,
            ipv6: self.v6,
            port: self.port,
            proto: self.proto,
            is_fake_ip: self.fake,
        }
    }
}

/// Darwin `sockaddr` starts with `sa_len` then an 8-bit family.
unsafe fn endpoint_of(addr: *const libc::sockaddr, proto: Proto) -> Option<OwnedEp> {
    let raw = addr as *const u8;
    let family = *raw.add(1) as i32;
    if family == libc::AF_INET {
        let port = u16::from_be(std::ptr::read_unaligned(raw.add(2) as *const u16));
        let ip_be = std::ptr::read_unaligned(raw.add(4) as *const u32);
        let ip = u32::from_be(ip_be);
        let fake = fakeip::is_fakeip(ip);
        Some(OwnedEp {
            domain: if fake { fakeip::get_domain(ip) } else { None },
            v4: Some(ip),
            v6: None,
            port,
            fake,
            proto,
            family,
            v6_only: false,
        })
    } else if family == libc::AF_INET6 {
        let port = u16::from_be(std::ptr::read_unaligned(raw.add(2) as *const u16));
        let mut bytes = [0u8; 16];
        std::ptr::copy_nonoverlapping(raw.add(8), bytes.as_mut_ptr(), 16);
        if let Some(ip) = fakeip::ipv4_from_mapped_v6(&bytes) {
            let fake = fakeip::is_fakeip(ip);
            Some(OwnedEp {
                domain: if fake { fakeip::get_domain(ip) } else { None },
                v4: Some(ip),
                v6: Some(bytes),
                port,
                fake,
                proto,
                family: libc::AF_INET6,
                v6_only: false,
            })
        } else {
            Some(OwnedEp {
                domain: None,
                v4: None,
                v6: Some(bytes),
                port,
                fake: false,
                proto,
                family,
                v6_only: true,
            })
        }
    } else {
        None
    }
}

fn display_ep(ep: &OwnedEp) -> String {
    if let Some(ip) = ep.v4 {
        Ipv4Addr::from(ip).to_string()
    } else {
        "ipv6".into()
    }
}

fn socket_proto(fd: libc::c_int) -> Proto {
    let mut ty = 0i32;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut ty as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 && ty == libc::SOCK_DGRAM {
        Proto::Udp
    } else {
        Proto::Tcp
    }
}

macro_rules! interpose {
    ($name:ident => $hook:ident, $real:path) => {
        #[used]
        #[link_section = "__DATA,__interpose"]
        static $name: Interpose = Interpose {
            replacement: $hook as *const (),
            original: $real as *const (),
        };
    };
}

interpose!(INTERPOSE_CONNECT => hook_connect, libc::connect);
interpose!(INTERPOSE_GETADDRINFO => hook_getaddrinfo, libc::getaddrinfo);
interpose!(INTERPOSE_FREEADDRINFO => hook_freeaddrinfo, libc::freeaddrinfo);
interpose!(INTERPOSE_GETHOSTBYNAME => hook_gethostbyname, gethostbyname);
interpose!(INTERPOSE_SEND => hook_send, libc::send);
interpose!(INTERPOSE_RECV => hook_recv, libc::recv);
interpose!(INTERPOSE_SENDTO => hook_sendto, libc::sendto);
interpose!(INTERPOSE_POSIX_SPAWN => hook_posix_spawn, libc::posix_spawn);
interpose!(INTERPOSE_EXECVE => hook_execve, libc::execve);
