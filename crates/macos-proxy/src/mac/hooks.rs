//! dyld `__interpose` hooks for the BSD socket calls Antigravity uses.

use std::ffi::{CStr, CString};
use std::net::Ipv4Addr;
use std::sync::OnceLock;

use agy_core::config::AppConfig;
use agy_core::fakeip;
use agy_core::routing::{self, Action, DecideOpts, Endpoint, Proto};

use super::child;
use super::net;
use super::{is_targeted, log, startup};

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

pub fn sym(name: &str) -> usize {
    let c = CString::new(name).unwrap_or_default();
    unsafe {
        let ptr = libc::dlsym(libc::RTLD_NEXT, c.as_ptr());
        ptr as usize
    }
}

pub unsafe fn raw_connect(fd: libc::c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> libc::c_int {
    type Fn = unsafe extern "C" fn(libc::c_int, *const libc::sockaddr, libc::socklen_t) -> libc::c_int;
    let f: Fn = std::mem::transmute(sym("connect"));
    f(fd, addr, len)
}

pub(super) unsafe fn raw_send(fd: libc::c_int, buf: *const libc::c_void, len: usize, flags: libc::c_int) -> isize {
    type Fn = unsafe extern "C" fn(libc::c_int, *const libc::c_void, usize, libc::c_int) -> isize;
    let f: Fn = std::mem::transmute(sym("send"));
    f(fd, buf, len, flags)
}

pub(super) unsafe fn raw_recv(fd: libc::c_int, buf: *mut libc::c_void, len: usize, flags: libc::c_int) -> isize {
    type Fn = unsafe extern "C" fn(libc::c_int, *mut libc::c_void, usize, libc::c_int) -> isize;
    let f: Fn = std::mem::transmute(sym("recv"));
    f(fd, buf, len, flags)
}

unsafe fn raw_getaddrinfo(
    node: *const libc::c_char,
    service: *const libc::c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> libc::c_int {
    type Fn = unsafe extern "C" fn(
        *const libc::c_char,
        *const libc::c_char,
        *const libc::addrinfo,
        *mut *mut libc::addrinfo,
    ) -> libc::c_int;
    let f: Fn = std::mem::transmute(sym("getaddrinfo"));
    f(node, service, hints, res)
}

unsafe fn raw_sendto(
    fd: libc::c_int,
    buf: *const libc::c_void,
    len: usize,
    flags: libc::c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> isize {
    type Fn = unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_void,
        usize,
        libc::c_int,
        *const libc::sockaddr,
        libc::socklen_t,
    ) -> isize;
    let f: Fn = std::mem::transmute(sym("sendto"));
    f(fd, buf, len, flags, addr, addrlen)
}

fn ensure() {
    startup();
}

pub unsafe extern "C" fn hook_getaddrinfo(
    node: *const libc::c_char,
    service: *const libc::c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> libc::c_int {
    ensure();
    if node.is_null() || !is_targeted(config()) {
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
    ensure();
    type Fn = unsafe extern "C" fn(*mut libc::addrinfo);
    let f: Fn = std::mem::transmute(sym("freeaddrinfo"));
    f(res);
}

pub unsafe extern "C" fn hook_gethostbyname(name: *const libc::c_char) -> *mut libc::hostent {
    ensure();
    type Fn = unsafe extern "C" fn(*const libc::c_char) -> *mut libc::hostent;
    let real: Fn = std::mem::transmute(sym("gethostbyname"));
    if name.is_null() || !is_targeted(config()) {
        return real(name);
    }
    let host = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return real(name),
    };
    if !routing::should_fake_dns(config(), host) {
        return real(name);
    }
    let ip = fakeip::get_or_create(host);
    if ip == 0 {
        return real(name);
    }
    let literal = CString::new(Ipv4Addr::from(ip).to_string()).unwrap_or_default();
    real(literal.as_ptr())
}

pub unsafe extern "C" fn hook_connect(
    fd: libc::c_int,
    addr: *const libc::sockaddr,
    len: libc::socklen_t,
) -> libc::c_int {
    ensure();
    if addr.is_null() || !is_targeted(config()) {
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
    ensure();
    if addr.is_null() || !is_targeted(config()) || socket_proto(fd) != Proto::Udp {
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
    ensure();
    child::spawn(pid, path, file_actions, attrp, argv, envp)
}

pub unsafe extern "C" fn hook_execve(
    path: *const libc::c_char,
    argv: *const *mut libc::c_char,
    envp: *const *mut libc::c_char,
) -> i32 {
    ensure();
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

#[used]
#[link_section = "__DATA,__interpose"]
static INTERPOSE: [Interpose; 8] = [
    Interpose {
        replacement: hook_connect as *const (),
        original: libc::connect as *const (),
    },
    Interpose {
        replacement: hook_getaddrinfo as *const (),
        original: libc::getaddrinfo as *const (),
    },
    Interpose {
        replacement: hook_freeaddrinfo as *const (),
        original: libc::freeaddrinfo as *const (),
    },
    Interpose {
        replacement: hook_gethostbyname as *const (),
        original: gethostbyname as *const (),
    },
    Interpose {
        replacement: hook_send as *const (),
        original: libc::send as *const (),
    },
    Interpose {
        replacement: hook_recv as *const (),
        original: libc::recv as *const (),
    },
    Interpose {
        replacement: hook_sendto as *const (),
        original: libc::sendto as *const (),
    },
    Interpose {
        replacement: hook_posix_spawn as *const (),
        original: libc::posix_spawn as *const (),
    },
];

#[used]
#[link_section = "__DATA,__interpose"]
static INTERPOSE_EXEC: Interpose = Interpose {
    replacement: hook_execve as *const (),
    original: libc::execve as *const (),
};
