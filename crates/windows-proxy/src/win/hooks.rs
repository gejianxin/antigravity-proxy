//! Winsock and CreateProcess hooks. Original pointers come from `GetProcAddress`
//! before any IAT slot is rewritten, so calling them cannot re-enter these hooks.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::net::Ipv4Addr;
use std::sync::{LazyLock, Mutex, OnceLock};

use agy_core::config::{AppConfig, HostPlatform};
use agy_core::fakeip;
use agy_core::process;
use agy_core::proto::{self, SocksTarget};
use agy_core::routing::{self, Action, DecideOpts, Endpoint, Proto};
use windows_sys::Win32::Foundation::{GetLastError, FALSE, HANDLE, TRUE};
use windows_sys::Win32::Networking::WinSock::{
    closesocket, getsockopt, select, setsockopt, WSAGetLastError, WSASetLastError, WSAStartup,
    AF_INET, AF_INET6, AF_UNSPEC, INVALID_SOCKET, IPPROTO_IPV6, IPPROTO_TCP, IPV6_V6ONLY, SD_BOTH,
    SOCKET, SOCKET_ERROR, SOCK_DGRAM, SOCK_STREAM, SOL_SOCKET, SO_ERROR, SO_TYPE, WSADATA,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Threading::{ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION};
use windows_sys::Win32::System::IO::OVERLAPPED;

use super::iat;
use super::inject;
use super::log;
use super::{lossy_wide, our_module, wide};

static CONFIG: OnceLock<AppConfig> = OnceLock::new();
static API: OnceLock<Api> = OnceLock::new();
static UDP: LazyLock<Mutex<HashMap<usize, UdpCtx>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static CONNECTEX: LazyLock<Mutex<HashMap<usize, CxCtx>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static OVERLAP_UDP_LOGGED: LazyLock<Mutex<bool>> = LazyLock::new(|| Mutex::new(false));

struct Api {
    connect: usize,
    #[allow(dead_code)]
    wsa_connect: usize,
    getaddrinfo: usize,
    getaddrinfo_w: usize,
    gethostbyname: usize,
    send: usize,
    recv: usize,
    sendto: usize,
    recvfrom: usize,
    closesocket: usize,
    wsaioctl: usize,
    socket: usize,
    wsa_send_to: usize,
    wsa_recv_from: usize,
    create_process_w: usize,
    create_process_a: usize,
    get_proc_address: usize,
    gqcs: usize,
    gqcs_ex: usize,
    load_library_w: usize,
    load_library_a: usize,
    load_library_ex_w: usize,
    connect_ex: usize,
}

struct UdpCtx {
    control: SOCKET,
    relay: SockAddrBuf,
    host: Option<String>,
    port: u16,
    v4: Option<[u8; 4]>,
    v6: Option<[u8; 16]>,
}

struct CxCtx {
    socket: SOCKET,
    host: String,
    port: u16,
    initial: Vec<u8>,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrBuf {
    bytes: [u8; 128],
    len: i32,
}

#[repr(C)]
struct SockV4 {
    family: u16,
    port: u16,
    addr: u32,
    zero: [u8; 8],
}

#[repr(C)]
struct SockV6 {
    family: u16,
    port: u16,
    flow: u32,
    addr: [u8; 16],
    scope: u32,
}

#[repr(C)]
pub(crate) struct WsaBuf {
    len: u32,
    buf: *mut i8,
}

pub fn config() -> &'static AppConfig {
    CONFIG.get().expect("config installed")
}

pub fn install(cfg: &AppConfig) {
    let _ = CONFIG.set(cfg.clone());
    let _ = API.set(resolve_api());
    let our = our_module() as *mut u8;
    let patched = iat::patch_loaded(our, &|dll, func| {
        if !dll_interesting(dll) {
            return None;
        }
        detour_for(func)
    });
    log::info(&format!("IAT Hook 安装完成, patched={patched}"));
    if patched == 0 {
        log::warn(
            "没有改写任何 IAT 槽。若目标进程在 DLL 加载前就缓存了 Winsock 指针，连接不会被重定向",
        );
    }
}

fn api() -> &'static Api {
    API.get().expect("api resolved")
}

fn network_enabled() -> bool {
    let cfg = config();
    process::is_targeted(
        &super::current_process_name(),
        cfg,
        HostPlatform::Windows,
        super::forced(),
    )
}

fn dll_interesting(dll: &str) -> bool {
    let dll = dll.to_ascii_lowercase();
    dll.contains("ws2_32")
        || dll.contains("kernel32")
        || dll.contains("kernelbase")
        || dll.contains("api-ms-win")
}

fn is_network_api(name: &str) -> bool {
    !matches!(
        name,
        "CreateProcessW"
            | "CreateProcessA"
            | "GetProcAddress"
            | "LoadLibraryW"
            | "LoadLibraryA"
            | "LoadLibraryExW"
            | "GetQueuedCompletionStatus"
            | "GetQueuedCompletionStatusEx"
    )
}

fn detour_for(name: &str) -> Option<usize> {
    let addr = detour_addr(name)?;
    if is_network_api(name) && !network_enabled() {
        return None;
    }
    Some(addr)
}

fn detour_addr(name: &str) -> Option<usize> {
    Some(match name {
        "connect" => hook_connect as usize,
        "WSAConnect" => hook_wsa_connect as usize,
        "getaddrinfo" => hook_getaddrinfo as usize,
        "GetAddrInfoW" => hook_getaddrinfo_w as usize,
        "gethostbyname" => hook_gethostbyname as usize,
        "send" => hook_send as usize,
        "recv" => hook_recv as usize,
        "sendto" => hook_sendto as usize,
        "recvfrom" => hook_recvfrom as usize,
        "closesocket" => hook_closesocket as usize,
        "WSAIoctl" => hook_wsaioctl as usize,
        "socket" => hook_socket as usize,
        "WSASendTo" => hook_wsa_send_to as usize,
        "WSARecvFrom" => hook_wsa_recv_from as usize,
        "CreateProcessW" => hook_create_process_w as usize,
        "CreateProcessA" => hook_create_process_a as usize,
        "GetProcAddress" => hook_get_proc_address as usize,
        "GetQueuedCompletionStatus" => hook_gqcs as usize,
        "GetQueuedCompletionStatusEx" => hook_gqcs_ex as usize,
        "LoadLibraryW" => hook_load_library_w as usize,
        "LoadLibraryA" => hook_load_library_a as usize,
        "LoadLibraryExW" => hook_load_library_ex_w as usize,
        _ => return None,
    })
}

fn resolve_api() -> Api {
    unsafe {
        let mut data: WSADATA = std::mem::zeroed();
        WSAStartup(0x0202, &mut data);
    }
    let mut api = Api {
        connect: lookup("ws2_32.dll", "connect"),
        wsa_connect: lookup("ws2_32.dll", "WSAConnect"),
        getaddrinfo: lookup("ws2_32.dll", "getaddrinfo"),
        getaddrinfo_w: lookup("ws2_32.dll", "GetAddrInfoW"),
        gethostbyname: lookup("ws2_32.dll", "gethostbyname"),
        send: lookup("ws2_32.dll", "send"),
        recv: lookup("ws2_32.dll", "recv"),
        sendto: lookup("ws2_32.dll", "sendto"),
        recvfrom: lookup("ws2_32.dll", "recvfrom"),
        closesocket: lookup("ws2_32.dll", "closesocket"),
        wsaioctl: lookup("ws2_32.dll", "WSAIoctl"),
        socket: lookup("ws2_32.dll", "socket"),
        wsa_send_to: lookup("ws2_32.dll", "WSASendTo"),
        wsa_recv_from: lookup("ws2_32.dll", "WSARecvFrom"),
        create_process_w: lookup("kernel32.dll", "CreateProcessW"),
        create_process_a: lookup("kernel32.dll", "CreateProcessA"),
        get_proc_address: lookup("kernel32.dll", "GetProcAddress"),
        gqcs: lookup("kernel32.dll", "GetQueuedCompletionStatus"),
        gqcs_ex: lookup("kernel32.dll", "GetQueuedCompletionStatusEx"),
        load_library_w: lookup("kernel32.dll", "LoadLibraryW"),
        load_library_a: lookup("kernel32.dll", "LoadLibraryA"),
        load_library_ex_w: lookup("kernel32.dll", "LoadLibraryExW"),
        connect_ex: 0,
    };
    api.connect_ex = capture_connect_ex(api.wsaioctl, api.socket);
    api
}

fn lookup(dll: &str, name: &str) -> usize {
    unsafe {
        let wide_dll = wide(dll);
        let mut module = GetModuleHandleW(wide_dll.as_ptr());
        if module.is_null() {
            module = LoadLibraryW(wide_dll.as_ptr());
        }
        if module.is_null() {
            log::warn(&format!("未能加载 {dll} 以解析 {name}"));
            return 0;
        }
        let c_name = CString::new(name).unwrap_or_default();
        GetProcAddress(module, c_name.as_ptr() as *const u8)
            .map(|fp| fp as usize)
            .unwrap_or(0)
    }
}

fn capture_connect_ex(wsaioctl: usize, socket_fn: usize) -> usize {
    if wsaioctl == 0 || socket_fn == 0 {
        return 0;
    }
    unsafe {
        type SocketFn = unsafe extern "system" fn(i32, i32, i32) -> SOCKET;
        type IoctlFn = unsafe extern "system" fn(
            SOCKET,
            u32,
            *mut core::ffi::c_void,
            u32,
            *mut core::ffi::c_void,
            u32,
            *mut u32,
            *mut OVERLAPPED,
            usize,
        ) -> i32;
        let socket_fn: SocketFn = std::mem::transmute(socket_fn);
        let ioctl: IoctlFn = std::mem::transmute(wsaioctl);
        let s = socket_fn(AF_INET as i32, SOCK_STREAM, IPPROTO_TCP);
        if s == INVALID_SOCKET {
            return 0;
        }
        #[repr(C)]
        struct Guid {
            d1: u32,
            d2: u16,
            d3: u16,
            d4: [u8; 8],
        }
        let mut guid = Guid {
            d1: 0x25a207b9,
            d2: 0xddf3,
            d3: 0x4660,
            d4: [0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e],
        };
        let mut out = 0usize;
        let mut bytes = 0u32;
        let rc = ioctl(
            s,
            0xC800_0006,
            &mut guid as *mut _ as *mut _,
            std::mem::size_of::<Guid>() as u32,
            &mut out as *mut _ as *mut _,
            std::mem::size_of::<usize>() as u32,
            &mut bytes,
            std::ptr::null_mut(),
            0,
        );
        type CloseFn = unsafe extern "system" fn(SOCKET) -> i32;
        let close: CloseFn = std::mem::transmute(api_closesocket_fallback());
        if close as usize != 0 {
            close(s);
        } else {
            closesocket(s);
        }
        if rc == 0 {
            out
        } else {
            0
        }
    }
}

fn api_closesocket_fallback() -> usize {
    API.get().map(|a| a.closesocket).unwrap_or(0)
}

fn repatch() {
    let our = our_module() as *mut u8;
    iat::patch_loaded(our, &|dll, func| {
        if !dll_interesting(dll) {
            return None;
        }
        detour_for(func)
    });
}

fn hint_family(hints: *const core::ffi::c_void) -> i32 {
    if hints.is_null() {
        return AF_UNSPEC as i32;
    }
    // ADDRINFOA/W: ai_flags at 0, ai_family at 4.
    unsafe { std::ptr::read_unaligned((hints as *const u8).add(4) as *const i32) }
}

fn cstr(ptr: *const u8) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe {
        CStr::from_ptr(ptr as *const i8)
            .to_string_lossy()
            .into_owned()
    }
}

pub unsafe extern "system" fn hook_get_proc_address(
    module: windows_sys::Win32::Foundation::HMODULE,
    name: *const u8,
) -> usize {
    if !name.is_null() && (name as usize) > 0xFFFF {
        let label = cstr(name);
        if let Some(detour) = detour_for(&label) {
            return detour;
        }
    }
    type Fn =
        unsafe extern "system" fn(windows_sys::Win32::Foundation::HMODULE, *const u8) -> usize;
    let fp = api().get_proc_address;
    if fp == 0 {
        return 0;
    }
    let f: Fn = std::mem::transmute(fp);
    f(module, name)
}

pub unsafe extern "system" fn hook_load_library_w(
    name: *const u16,
) -> windows_sys::Win32::Foundation::HMODULE {
    type Fn = unsafe extern "system" fn(*const u16) -> windows_sys::Win32::Foundation::HMODULE;
    let f: Fn = std::mem::transmute(api().load_library_w);
    let module = f(name);
    if !module.is_null() {
        repatch();
    }
    module
}

pub unsafe extern "system" fn hook_load_library_a(
    name: *const u8,
) -> windows_sys::Win32::Foundation::HMODULE {
    type Fn = unsafe extern "system" fn(*const u8) -> windows_sys::Win32::Foundation::HMODULE;
    let f: Fn = std::mem::transmute(api().load_library_a);
    let module = f(name);
    if !module.is_null() {
        repatch();
    }
    module
}

pub unsafe extern "system" fn hook_load_library_ex_w(
    name: *const u16,
    file: HANDLE,
    flags: u32,
) -> windows_sys::Win32::Foundation::HMODULE {
    type Fn = unsafe extern "system" fn(
        *const u16,
        HANDLE,
        u32,
    ) -> windows_sys::Win32::Foundation::HMODULE;
    let f: Fn = std::mem::transmute(api().load_library_ex_w);
    let module = f(name, file, flags);
    if !module.is_null() {
        repatch();
    }
    module
}

pub unsafe extern "system" fn hook_socket(af: i32, ty: i32, proto: i32) -> SOCKET {
    type Fn = unsafe extern "system" fn(i32, i32, i32) -> SOCKET;
    let f: Fn = std::mem::transmute(api().socket);
    let s = f(af, ty, proto);
    if s != INVALID_SOCKET
        && af == (AF_INET6 as i32)
        && config().proxy_rules.ipv6_mode.eq_ignore_ascii_case("proxy")
    {
        let off = 0i32;
        setsockopt(
            s,
            IPPROTO_IPV6,
            IPV6_V6ONLY,
            &off as *const _ as *const _,
            4,
        );
    }
    s
}

pub unsafe extern "system" fn hook_getaddrinfo(
    node: *const u8,
    service: *const u8,
    hints: *const core::ffi::c_void,
    res: *mut *mut core::ffi::c_void,
) -> i32 {
    if node.is_null() || !network_enabled() {
        return real_getaddrinfo(node, service, hints, res);
    }
    let name = cstr(node);
    if !routing::should_fake_dns(config(), &name) {
        return real_getaddrinfo(node, service, hints, res);
    }
    let ip = fakeip::get_or_create(&name);
    if ip == 0 {
        return real_getaddrinfo(node, service, hints, res);
    }
    let mut literal = Ipv4Addr::from(ip).to_string();
    let family = hint_family(hints);
    if family == (AF_INET6 as i32) {
        literal = format!("::ffff:{literal}");
    } else if family != (AF_UNSPEC as i32) && family != (AF_INET as i32) {
        return real_getaddrinfo(node, service, hints, res);
    }
    let Ok(c_lit) = CString::new(literal) else {
        return real_getaddrinfo(node, service, hints, res);
    };
    log::debug(&format!("[FakeIP] 解析域名拦截: {name}"));
    real_getaddrinfo(c_lit.as_ptr() as *const u8, service, hints, res)
}

pub unsafe extern "system" fn hook_getaddrinfo_w(
    node: *const u16,
    service: *const u16,
    hints: *const core::ffi::c_void,
    res: *mut *mut core::ffi::c_void,
) -> i32 {
    if node.is_null() || !network_enabled() {
        return real_getaddrinfo_w(node, service, hints, res);
    }
    let name = lossy_wide(node);
    if !routing::should_fake_dns(config(), &name) {
        return real_getaddrinfo_w(node, service, hints, res);
    }
    let ip = fakeip::get_or_create(&name);
    if ip == 0 {
        return real_getaddrinfo_w(node, service, hints, res);
    }
    let mut literal = Ipv4Addr::from(ip).to_string();
    let family = hint_family(hints);
    if family == (AF_INET6 as i32) {
        literal = format!("::ffff:{literal}");
    } else if family != (AF_UNSPEC as i32) && family != (AF_INET as i32) {
        return real_getaddrinfo_w(node, service, hints, res);
    }
    let wide_lit = wide(&literal);
    log::debug(&format!("[FakeIP] 解析域名拦截(W): {name}"));
    real_getaddrinfo_w(wide_lit.as_ptr(), service, hints, res)
}

pub unsafe extern "system" fn hook_gethostbyname(name: *const u8) -> *mut core::ffi::c_void {
    if name.is_null() || !network_enabled() {
        return real_gethostbyname(name);
    }
    let host = cstr(name);
    if !routing::should_fake_dns(config(), &host) {
        return real_gethostbyname(name);
    }
    let ip = fakeip::get_or_create(&host);
    if ip == 0 {
        return real_gethostbyname(name);
    }
    let literal = CString::new(Ipv4Addr::from(ip).to_string()).unwrap_or_default();
    real_gethostbyname(literal.as_ptr() as *const u8)
}

unsafe fn real_getaddrinfo(
    node: *const u8,
    service: *const u8,
    hints: *const core::ffi::c_void,
    res: *mut *mut core::ffi::c_void,
) -> i32 {
    type Fn = unsafe extern "system" fn(
        *const u8,
        *const u8,
        *const core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> i32;
    let f: Fn = std::mem::transmute(api().getaddrinfo);
    f(node, service, hints, res)
}

unsafe fn real_getaddrinfo_w(
    node: *const u16,
    service: *const u16,
    hints: *const core::ffi::c_void,
    res: *mut *mut core::ffi::c_void,
) -> i32 {
    type Fn = unsafe extern "system" fn(
        *const u16,
        *const u16,
        *const core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> i32;
    let f: Fn = std::mem::transmute(api().getaddrinfo_w);
    f(node, service, hints, res)
}

unsafe fn real_gethostbyname(name: *const u8) -> *mut core::ffi::c_void {
    type Fn = unsafe extern "system" fn(*const u8) -> *mut core::ffi::c_void;
    let f: Fn = std::mem::transmute(api().gethostbyname);
    f(name)
}

pub unsafe extern "system" fn hook_connect(
    s: SOCKET,
    name: *const core::ffi::c_void,
    namelen: i32,
) -> i32 {
    proxy_connect(s, name, namelen)
}

pub unsafe extern "system" fn hook_wsa_connect(
    s: SOCKET,
    name: *const core::ffi::c_void,
    namelen: i32,
    _caller: *mut core::ffi::c_void,
    _callee: *mut core::ffi::c_void,
    _sqos: *mut core::ffi::c_void,
    _gqos: *mut core::ffi::c_void,
) -> i32 {
    proxy_connect(s, name, namelen)
}

unsafe fn proxy_connect(s: SOCKET, name: *const core::ffi::c_void, namelen: i32) -> i32 {
    if name.is_null() || !network_enabled() {
        return raw_connect(s, name, namelen);
    }
    let Some(ep) = endpoint_of(name, socket_proto(s)) else {
        return raw_connect(s, name, namelen);
    };
    let action = routing::decide(config(), &ep.view(), DecideOpts::WINDOWS);
    match action {
        Action::Direct => {
            if ep.fake {
                if let Some(domain) = ep.domain.as_deref() {
                    if let Some(buf) = resolve_literal(domain, ep.port) {
                        return raw_connect(s, buf.bytes.as_ptr() as *const _, buf.len);
                    }
                }
            }
            raw_connect(s, name, namelen)
        }
        Action::Block => {
            let err = if ep.v6.is_some() && ep.v4.is_none() {
                10047
            } else {
                10013
            };
            WSASetLastError(err);
            SOCKET_ERROR
        }
        Action::Proxy if ep.proto == Proto::Udp => udp_connect(s, &ep, name, namelen),
        Action::Proxy => tcp_proxy(s, &ep, name),
    }
}

struct OwnedEp {
    domain: Option<String>,
    v4: Option<u32>,
    v6: Option<[u8; 16]>,
    port: u16,
    fake: bool,
    proto: Proto,
    family: i32,
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

unsafe fn endpoint_of(name: *const core::ffi::c_void, proto: Proto) -> Option<OwnedEp> {
    let family = std::ptr::read_unaligned(name as *const u16) as i32;
    if family == (AF_INET as i32) {
        let sin = &*(name as *const SockV4);
        let ip = u32::from_be(sin.addr);
        let fake = fakeip::is_fakeip(ip);
        Some(OwnedEp {
            domain: if fake { fakeip::get_domain(ip) } else { None },
            v4: Some(ip),
            v6: None,
            port: u16::from_be(sin.port),
            fake,
            proto,
            family,
        })
    } else if family == (AF_INET6 as i32) {
        let sin6 = &*(name as *const SockV6);
        let mapped = fakeip::ipv4_from_mapped_v6(&sin6.addr);
        let fake = mapped.map(fakeip::is_fakeip).unwrap_or(false);
        Some(OwnedEp {
            domain: mapped.and_then(fakeip::get_domain).filter(|_| fake),
            v4: mapped,
            v6: Some(sin6.addr),
            port: u16::from_be(sin6.port),
            fake,
            proto,
            family,
        })
    } else {
        None
    }
}

fn socket_proto(s: SOCKET) -> Proto {
    let mut ty = 0i32;
    let mut len = 4i32;
    let rc = unsafe {
        getsockopt(
            s,
            SOL_SOCKET,
            SO_TYPE,
            &mut ty as *mut _ as *mut _,
            &mut len,
        )
    };
    if rc == 0 && ty == SOCK_DGRAM {
        Proto::Udp
    } else {
        Proto::Tcp
    }
}

unsafe fn raw_connect(s: SOCKET, name: *const core::ffi::c_void, namelen: i32) -> i32 {
    type Fn = unsafe extern "system" fn(SOCKET, *const core::ffi::c_void, i32) -> i32;
    let f: Fn = std::mem::transmute(api().connect);
    f(s, name, namelen)
}

unsafe fn resolve_literal(domain: &str, port: u16) -> Option<SockAddrBuf> {
    let c = CString::new(domain).ok()?;
    let mut hints = [0u8; 64];
    hints[4..8].copy_from_slice(&(AF_INET as i32).to_ne_bytes());
    hints[8..12].copy_from_slice(&SOCK_STREAM.to_ne_bytes());
    let mut res: *mut core::ffi::c_void = std::ptr::null_mut();
    if real_getaddrinfo(
        c.as_ptr() as *const u8,
        std::ptr::null(),
        hints.as_ptr() as *const _,
        &mut res,
    ) != 0
        || res.is_null()
    {
        return None;
    }
    // ADDRINFOA.ai_addr is at offset 16 on x64 (flags, family, socktype, protocol, addrlen, canonname, addr).
    // Layout: i32 flags, i32 family, i32 socktype, i32 protocol, usize addrlen, *canon, *addr, *next.
    let addr = std::ptr::read_unaligned(res.add(32) as *const *const u8);
    let addrlen = std::ptr::read_unaligned(res.add(16) as *const usize) as i32;
    let mut buf = SockAddrBuf {
        bytes: [0; 128],
        len: addrlen,
    };
    if !addr.is_null() && addrlen > 0 && (addrlen as usize) <= buf.bytes.len() {
        std::ptr::copy_nonoverlapping(addr, buf.bytes.as_mut_ptr(), addrlen as usize);
        if addrlen >= 8 {
            let port_slot = &mut buf.bytes[2..4];
            port_slot.copy_from_slice(&port.to_be_bytes());
        }
    } else {
        type FreeFn = unsafe extern "system" fn(*mut core::ffi::c_void);
        if let Some(fp) = lookup_freeaddrinfo() {
            let f: FreeFn = std::mem::transmute(fp);
            f(res);
        }
        return None;
    }
    if let Some(fp) = lookup_freeaddrinfo() {
        type FreeFn = unsafe extern "system" fn(*mut core::ffi::c_void);
        let f: FreeFn = std::mem::transmute(fp);
        f(res);
    }
    Some(buf)
}

fn lookup_freeaddrinfo() -> Option<usize> {
    let fp = lookup("ws2_32.dll", "freeaddrinfo");
    if fp == 0 {
        None
    } else {
        Some(fp)
    }
}

unsafe fn tcp_proxy(s: SOCKET, ep: &OwnedEp, _name: *const core::ffi::c_void) -> i32 {
    let timeout = config().timeout.connect.max(1000);
    let proxy = match proxy_buf(ep.family) {
        Some(buf) => buf,
        None => {
            WSASetLastError(10014);
            return SOCKET_ERROR;
        }
    };
    if ep.family == (AF_INET6 as i32) {
        let off = 0i32;
        setsockopt(
            s,
            IPPROTO_IPV6,
            IPV6_V6ONLY,
            &off as *const _ as *const _,
            4,
        );
    }
    let rc = raw_connect(s, proxy.bytes.as_ptr() as *const _, proxy.len);
    if rc != 0 {
        let err = WSAGetLastError();
        if err != 10035 && err != 10036 {
            log::error(&format!("连接代理服务器失败, WSA错误码={err}"));
            return SOCKET_ERROR;
        }
        if !wait_socket(s, true, timeout) || socket_error(s) != 0 {
            log::error("连接代理服务器失败 (非阻塞等待)");
            return SOCKET_ERROR;
        }
    }
    let host = ep.domain.clone().unwrap_or_else(|| display_ep(ep));
    if !handshake(s, &host, ep.port, timeout) {
        WSASetLastError(10061);
        return SOCKET_ERROR;
    }
    log::info(&format!("SOCKS5: 隧道建立成功, 目标={host}:{}", ep.port));
    0
}

fn display_ep(ep: &OwnedEp) -> String {
    if let Some(ip) = ep.v4 {
        Ipv4Addr::from(ip).to_string()
    } else if let Some(bytes) = ep.v6 {
        std::net::Ipv6Addr::from(bytes).to_string()
    } else {
        "0.0.0.0".into()
    }
}

fn proxy_buf(family: i32) -> Option<SockAddrBuf> {
    let cfg = config();
    let ip: Ipv4Addr = cfg.proxy.host.parse().ok()?;
    let port = cfg.proxy.port.to_be();
    let mut buf = SockAddrBuf {
        bytes: [0; 128],
        len: 0,
    };
    if family == (AF_INET6 as i32) {
        let v6 = SockV6 {
            family: AF_INET6 as u16,
            port,
            flow: 0,
            addr: {
                let mut a = [0u8; 16];
                a[10] = 0xff;
                a[11] = 0xff;
                a[12..].copy_from_slice(&ip.octets());
                a
            },
            scope: 0,
        };
        buf.len = std::mem::size_of::<SockV6>() as i32;
        unsafe {
            std::ptr::write_unaligned(buf.bytes.as_mut_ptr() as *mut SockV6, v6);
        }
    } else {
        let v4 = SockV4 {
            family: AF_INET as u16,
            port,
            addr: u32::from(ip).to_be(),
            zero: [0; 8],
        };
        buf.len = std::mem::size_of::<SockV4>() as i32;
        unsafe {
            std::ptr::write_unaligned(buf.bytes.as_mut_ptr() as *mut SockV4, v4);
        }
    }
    Some(buf)
}

fn socket_error(s: SOCKET) -> i32 {
    let mut err = 0i32;
    let mut len = 4i32;
    let rc = unsafe {
        getsockopt(
            s,
            SOL_SOCKET,
            SO_ERROR,
            &mut err as *mut _ as *mut _,
            &mut len,
        )
    };
    if rc != 0 {
        unsafe { WSAGetLastError() }
    } else {
        err
    }
}

fn wait_socket(s: SOCKET, write: bool, timeout_ms: u32) -> bool {
    unsafe {
        let mut set = std::mem::zeroed::<windows_sys::Win32::Networking::WinSock::FD_SET>();
        set.fd_count = 1;
        set.fd_array[0] = s;
        let mut tv = windows_sys::Win32::Networking::WinSock::TIMEVAL {
            tv_sec: (timeout_ms / 1000) as i32,
            tv_usec: ((timeout_ms % 1000) * 1000) as i32,
        };
        let rc = if write {
            select(
                0,
                std::ptr::null_mut(),
                &mut set,
                std::ptr::null_mut(),
                &mut tv,
            )
        } else {
            select(
                0,
                &mut set,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut tv,
            )
        };
        rc > 0
    }
}

unsafe fn send_all(s: SOCKET, buf: &[u8], timeout_ms: u32) -> bool {
    let mut off = 0usize;
    while off < buf.len() {
        if !wait_socket(s, true, timeout_ms) {
            return false;
        }
        type Fn = unsafe extern "system" fn(SOCKET, *const u8, i32, i32) -> i32;
        let f: Fn = std::mem::transmute(api().send);
        let n = f(s, buf[off..].as_ptr(), (buf.len() - off) as i32, 0);
        if n == SOCKET_ERROR {
            let err = WSAGetLastError();
            if err == 10035 {
                continue;
            }
            return false;
        }
        if n <= 0 {
            return false;
        }
        off += n as usize;
    }
    true
}

unsafe fn recv_exact(s: SOCKET, buf: &mut [u8], timeout_ms: u32) -> bool {
    let mut off = 0usize;
    while off < buf.len() {
        if !wait_socket(s, false, timeout_ms) {
            return false;
        }
        type Fn = unsafe extern "system" fn(SOCKET, *mut u8, i32, i32) -> i32;
        let f: Fn = std::mem::transmute(api().recv);
        let n = f(s, buf[off..].as_mut_ptr(), (buf.len() - off) as i32, 0);
        if n == SOCKET_ERROR {
            let err = WSAGetLastError();
            if err == 10035 {
                continue;
            }
            return false;
        }
        if n <= 0 {
            return false;
        }
        off += n as usize;
    }
    true
}

unsafe fn handshake(s: SOCKET, host: &str, port: u16, timeout_ms: u32) -> bool {
    let cfg = config();
    if cfg.proxy.is_http() {
        let authority = format!("{host}:{port}");
        let req = proto::http_connect_request(&authority);
        if !send_all(s, req.as_bytes(), timeout_ms) {
            return false;
        }
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while buf.len() < 2048 {
            if !recv_exact(s, &mut byte, timeout_ms) {
                return false;
            }
            buf.push(byte[0]);
            match proto::http_connect_status(&buf) {
                Ok(true) => return true,
                Ok(false) => continue,
                Err(err) => {
                    log::warn(&err);
                    return false;
                }
            }
        }
        return false;
    }
    if !send_all(s, &proto::socks5_greeting(), timeout_ms) {
        return false;
    }
    let mut greet = [0u8; 2];
    if !recv_exact(s, &mut greet, timeout_ms) || !proto::socks5_greeting_ok(&greet) {
        log::warn("SOCKS5 握手失败");
        return false;
    }
    let target = SocksTarget::Domain(host.to_string());
    let req = proto::socks5_connect_request(&target, port);
    if !send_all(s, &req, timeout_ms) {
        return false;
    }
    let mut hdr = [0u8; 4];
    if !recv_exact(s, &mut hdr, timeout_ms) {
        return false;
    }
    if proto::socks5_reply_ok(&hdr).is_err() {
        log::warn(&format!("SOCKS5 握手失败, status={:02X}", hdr[1]));
        return false;
    }
    let mut domain_len = None;
    if hdr[3] == 0x03 {
        let mut len = [0u8; 1];
        if !recv_exact(s, &mut len, timeout_ms) {
            return false;
        }
        domain_len = Some(len[0]);
    }
    let Some(tail) = proto::socks5_bind_tail(hdr[3], domain_len) else {
        return false;
    };
    let mut drain = vec![0u8; tail];
    recv_exact(s, &mut drain, timeout_ms)
}

unsafe fn udp_connect(
    s: SOCKET,
    ep: &OwnedEp,
    name: *const core::ffi::c_void,
    namelen: i32,
) -> i32 {
    if ensure_udp(s).is_err() {
        if config()
            .proxy_rules
            .udp_fallback
            .eq_ignore_ascii_case("direct")
        {
            return raw_connect(s, name, namelen);
        }
        WSASetLastError(10061);
        return SOCKET_ERROR;
    }
    let relay = {
        let mut map = UDP.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ctx) = map.get_mut(&s) {
            ctx.host = ep.domain.clone();
            ctx.port = ep.port;
            ctx.v4 = ep.v4.map(|ip| ip.to_be_bytes());
            ctx.v6 = ep.v6;
            ctx.relay
        } else {
            WSASetLastError(10061);
            return SOCKET_ERROR;
        }
    };
    raw_connect(s, relay.bytes.as_ptr() as *const _, relay.len)
}

fn ensure_udp(s: SOCKET) -> Result<(), ()> {
    if UDP
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&s)
    {
        return Ok(());
    }
    let cfg = config();
    let ip: Ipv4Addr = cfg.proxy.host.parse().map_err(|_| ())?;
    unsafe {
        type SocketFn = unsafe extern "system" fn(i32, i32, i32) -> SOCKET;
        let socket_fn: SocketFn = std::mem::transmute(api().socket);
        let control = socket_fn(AF_INET as i32, SOCK_STREAM, IPPROTO_TCP);
        if control == INVALID_SOCKET {
            return Err(());
        }
        let buf = proxy_buf(AF_INET as i32).ok_or(())?;
        if raw_connect(control, buf.bytes.as_ptr() as *const _, buf.len) != 0 {
            type CloseFn = unsafe extern "system" fn(SOCKET) -> i32;
            let close: CloseFn = std::mem::transmute(api().closesocket);
            close(control);
            return Err(());
        }
        let timeout = cfg.timeout.connect.max(1000);
        if !send_all(control, &proto::socks5_greeting(), timeout)
            || !{
                let mut g = [0u8; 2];
                recv_exact(control, &mut g, timeout) && proto::socks5_greeting_ok(&g)
            }
            || !send_all(control, &proto::socks5_udp_associate_request(), timeout)
        {
            type CloseFn = unsafe extern "system" fn(SOCKET) -> i32;
            let close: CloseFn = std::mem::transmute(api().closesocket);
            close(control);
            return Err(());
        }
        let mut hdr = [0u8; 4];
        if !recv_exact(control, &mut hdr, timeout) || proto::socks5_reply_ok(&hdr).is_err() {
            type CloseFn = unsafe extern "system" fn(SOCKET) -> i32;
            let close: CloseFn = std::mem::transmute(api().closesocket);
            close(control);
            return Err(());
        }
        let mut domain_len = None;
        if hdr[3] == 0x03 {
            let mut len = [0u8; 1];
            if !recv_exact(control, &mut len, timeout) {
                return Err(());
            }
            domain_len = Some(len[0]);
        }
        let tail_len = proto::socks5_bind_tail(hdr[3], domain_len).ok_or(())?;
        let mut tail = vec![0u8; tail_len];
        if !recv_exact(control, &mut tail, timeout) {
            return Err(());
        }
        let relay = relay_buf(hdr[3], &tail, ip).ok_or(())?;
        UDP.lock().unwrap_or_else(|e| e.into_inner()).insert(
            s,
            UdpCtx {
                control,
                relay,
                host: None,
                port: 0,
                v4: None,
                v6: None,
            },
        );
        Ok(())
    }
}

fn relay_buf(atyp: u8, tail: &[u8], proxy_ip: Ipv4Addr) -> Option<SockAddrBuf> {
    let mut buf = SockAddrBuf {
        bytes: [0; 128],
        len: 0,
    };
    match atyp {
        0x01 if tail.len() >= 6 => {
            let mut addr = u32::from_ne_bytes(tail[0..4].try_into().ok()?);
            if addr == 0 {
                addr = u32::from(proxy_ip).to_be();
            }
            let v4 = SockV4 {
                family: AF_INET as u16,
                port: u16::from_ne_bytes(tail[4..6].try_into().ok()?),
                addr,
                zero: [0; 8],
            };
            buf.len = std::mem::size_of::<SockV4>() as i32;
            unsafe { std::ptr::write_unaligned(buf.bytes.as_mut_ptr() as *mut SockV4, v4) };
            Some(buf)
        }
        _ => {
            let port = u16::from_be_bytes([*tail.get(tail.len().wrapping_sub(2))?, *tail.last()?]);
            let v4 = SockV4 {
                family: AF_INET as u16,
                port: port.to_be(),
                addr: u32::from(proxy_ip).to_be(),
                zero: [0; 8],
            };
            buf.len = std::mem::size_of::<SockV4>() as i32;
            unsafe { std::ptr::write_unaligned(buf.bytes.as_mut_ptr() as *mut SockV4, v4) };
            Some(buf)
        }
    }
}

pub unsafe extern "system" fn hook_send(s: SOCKET, buf: *const u8, len: i32, flags: i32) -> i32 {
    if let Some(packet) = wrap_connected(s, buf, len) {
        type Fn = unsafe extern "system" fn(SOCKET, *const u8, i32, i32) -> i32;
        let f: Fn = std::mem::transmute(api().send);
        let n = f(s, packet.as_ptr(), packet.len() as i32, flags);
        return if n < 0 { n } else { len };
    }
    type Fn = unsafe extern "system" fn(SOCKET, *const u8, i32, i32) -> i32;
    let f: Fn = std::mem::transmute(api().send);
    f(s, buf, len, flags)
}

pub unsafe extern "system" fn hook_recv(s: SOCKET, buf: *mut u8, len: i32, flags: i32) -> i32 {
    if !UDP
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&s)
    {
        type Fn = unsafe extern "system" fn(SOCKET, *mut u8, i32, i32) -> i32;
        let f: Fn = std::mem::transmute(api().recv);
        return f(s, buf, len, flags);
    }
    let mut storage = vec![0u8; len.max(0) as usize + 64];
    type Fn = unsafe extern "system" fn(SOCKET, *mut u8, i32, i32) -> i32;
    let f: Fn = std::mem::transmute(api().recv);
    let n = f(s, storage.as_mut_ptr(), storage.len() as i32, flags);
    if n <= 0 {
        return n;
    }
    copy_unwrapped(&storage[..n as usize], buf, len)
}

fn wrap_connected(s: SOCKET, buf: *const u8, len: i32) -> Option<Vec<u8>> {
    if buf.is_null() || len < 0 {
        return None;
    }
    let map = UDP.lock().unwrap_or_else(|e| e.into_inner());
    let ctx = map.get(&s)?;
    let target = if let Some(host) = &ctx.host {
        SocksTarget::Domain(host.clone())
    } else if let Some(ip) = ctx.v4 {
        SocksTarget::V4(ip)
    } else {
        ctx.v6.map(SocksTarget::V6)?
    };
    let payload = unsafe { std::slice::from_raw_parts(buf, len as usize) };
    Some(proto::socks5_udp_packet(&target, ctx.port, payload))
}

fn copy_unwrapped(packet: &[u8], buf: *mut u8, len: i32) -> i32 {
    let payload = proto::socks5_udp_unwrap(packet)
        .map(|(_, _, p)| p.to_vec())
        .unwrap_or_else(|| packet.to_vec());
    let n = payload.len().min(len.max(0) as usize);
    unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), buf, n) };
    n as i32
}

pub unsafe extern "system" fn hook_sendto(
    s: SOCKET,
    buf: *const u8,
    len: i32,
    flags: i32,
    to: *const core::ffi::c_void,
    tolen: i32,
) -> i32 {
    if to.is_null() || !network_enabled() || socket_proto(s) != Proto::Udp {
        type Fn = unsafe extern "system" fn(
            SOCKET,
            *const u8,
            i32,
            i32,
            *const core::ffi::c_void,
            i32,
        ) -> i32;
        let f: Fn = std::mem::transmute(api().sendto);
        return f(s, buf, len, flags, to, tolen);
    }
    let Some(ep) = endpoint_of(to, Proto::Udp) else {
        type Fn = unsafe extern "system" fn(
            SOCKET,
            *const u8,
            i32,
            i32,
            *const core::ffi::c_void,
            i32,
        ) -> i32;
        let f: Fn = std::mem::transmute(api().sendto);
        return f(s, buf, len, flags, to, tolen);
    };
    match routing::decide(config(), &ep.view(), DecideOpts::WINDOWS) {
        Action::Direct => {
            type Fn = unsafe extern "system" fn(
                SOCKET,
                *const u8,
                i32,
                i32,
                *const core::ffi::c_void,
                i32,
            ) -> i32;
            let f: Fn = std::mem::transmute(api().sendto);
            f(s, buf, len, flags, to, tolen)
        }
        Action::Block => {
            WSASetLastError(10013);
            SOCKET_ERROR
        }
        Action::Proxy => {
            if ensure_udp(s).is_err() {
                if config()
                    .proxy_rules
                    .udp_fallback
                    .eq_ignore_ascii_case("direct")
                {
                    type Fn = unsafe extern "system" fn(
                        SOCKET,
                        *const u8,
                        i32,
                        i32,
                        *const core::ffi::c_void,
                        i32,
                    ) -> i32;
                    let f: Fn = std::mem::transmute(api().sendto);
                    return f(s, buf, len, flags, to, tolen);
                }
                WSASetLastError(10061);
                return SOCKET_ERROR;
            }
            let target = if let Some(host) = &ep.domain {
                SocksTarget::Domain(host.clone())
            } else if let Some(ip) = ep.v4 {
                SocksTarget::V4(ip.to_be_bytes())
            } else if let Some(ip) = ep.v6 {
                SocksTarget::V6(ip)
            } else {
                WSASetLastError(10022);
                return SOCKET_ERROR;
            };
            let payload = std::slice::from_raw_parts(buf, len.max(0) as usize);
            let packet = proto::socks5_udp_packet(&target, ep.port, payload);
            let relay = UDP
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&s)
                .map(|c| c.relay);
            let Some(relay) = relay else {
                WSASetLastError(10061);
                return SOCKET_ERROR;
            };
            type Fn = unsafe extern "system" fn(
                SOCKET,
                *const u8,
                i32,
                i32,
                *const core::ffi::c_void,
                i32,
            ) -> i32;
            let f: Fn = std::mem::transmute(api().sendto);
            let n = f(
                s,
                packet.as_ptr(),
                packet.len() as i32,
                flags,
                relay.bytes.as_ptr() as *const _,
                relay.len,
            );
            if n < 0 {
                n
            } else {
                len
            }
        }
    }
}

pub unsafe extern "system" fn hook_recvfrom(
    s: SOCKET,
    buf: *mut u8,
    len: i32,
    flags: i32,
    from: *mut core::ffi::c_void,
    fromlen: *mut i32,
) -> i32 {
    if !UDP
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&s)
    {
        type Fn = unsafe extern "system" fn(
            SOCKET,
            *mut u8,
            i32,
            i32,
            *mut core::ffi::c_void,
            *mut i32,
        ) -> i32;
        let f: Fn = std::mem::transmute(api().recvfrom);
        return f(s, buf, len, flags, from, fromlen);
    }
    let mut storage = vec![0u8; len.max(0) as usize + 64];
    let mut ignore = [0u8; 128];
    let mut ignore_len = ignore.len() as i32;
    type Fn = unsafe extern "system" fn(
        SOCKET,
        *mut u8,
        i32,
        i32,
        *mut core::ffi::c_void,
        *mut i32,
    ) -> i32;
    let f: Fn = std::mem::transmute(api().recvfrom);
    let n = f(
        s,
        storage.as_mut_ptr(),
        storage.len() as i32,
        flags,
        ignore.as_mut_ptr() as *mut _,
        &mut ignore_len,
    );
    if n <= 0 {
        return n;
    }
    let _ = (from, fromlen);
    copy_unwrapped(&storage[..n as usize], buf, len)
}

pub unsafe extern "system" fn hook_wsa_send_to(
    s: SOCKET,
    buffers: *const WsaBuf,
    count: u32,
    sent: *mut u32,
    flags: u32,
    to: *const core::ffi::c_void,
    tolen: i32,
    overlapped: *mut OVERLAPPED,
    routine: usize,
) -> i32 {
    if !overlapped.is_null() || count != 1 || buffers.is_null() {
        note_overlapped_udp();
        if !overlapped.is_null() && overlapped_should_block() {
            WSASetLastError(10013);
            return SOCKET_ERROR;
        }
        type Fn = unsafe extern "system" fn(
            SOCKET,
            *const WsaBuf,
            u32,
            *mut u32,
            u32,
            *const core::ffi::c_void,
            i32,
            *mut OVERLAPPED,
            usize,
        ) -> i32;
        let f: Fn = std::mem::transmute(api().wsa_send_to);
        return f(
            s, buffers, count, sent, flags, to, tolen, overlapped, routine,
        );
    }
    let buf = &*buffers;
    let n = hook_sendto(
        s,
        buf.buf as *const u8,
        buf.len as i32,
        flags as i32,
        to,
        tolen,
    );
    if n >= 0 && !sent.is_null() {
        *sent = n as u32;
        0
    } else {
        SOCKET_ERROR
    }
}

pub unsafe extern "system" fn hook_wsa_recv_from(
    s: SOCKET,
    buffers: *mut WsaBuf,
    count: u32,
    recvd: *mut u32,
    flags: *mut u32,
    from: *mut core::ffi::c_void,
    fromlen: *mut i32,
    overlapped: *mut OVERLAPPED,
    routine: usize,
) -> i32 {
    if !overlapped.is_null() || count != 1 || buffers.is_null() {
        note_overlapped_udp();
        if !overlapped.is_null() && overlapped_should_block() {
            WSASetLastError(10013);
            return SOCKET_ERROR;
        }
        type Fn = unsafe extern "system" fn(
            SOCKET,
            *mut WsaBuf,
            u32,
            *mut u32,
            *mut u32,
            *mut core::ffi::c_void,
            *mut i32,
            *mut OVERLAPPED,
            usize,
        ) -> i32;
        let f: Fn = std::mem::transmute(api().wsa_recv_from);
        return f(
            s, buffers, count, recvd, flags, from, fromlen, overlapped, routine,
        );
    }
    let buf = &mut *buffers;
    let n = hook_recvfrom(s, buf.buf as *mut u8, buf.len as i32, 0, from, fromlen);
    if n >= 0 && !recvd.is_null() {
        *recvd = n as u32;
        0
    } else {
        SOCKET_ERROR
    }
}

fn overlapped_should_block() -> bool {
    let cfg = config();
    let action = routing::effective_udp_action(cfg, DecideOpts::WINDOWS);
    action == routing::UdpAction::Proxy
        && !cfg.proxy_rules.udp_fallback.eq_ignore_ascii_case("direct")
        || action == routing::UdpAction::Block
}

fn note_overlapped_udp() {
    let mut logged = OVERLAP_UDP_LOGGED.lock().unwrap_or_else(|e| e.into_inner());
    if !*logged {
        *logged = true;
        log::warn("重叠 UDP/QUIC 未逐包改写。udp_fallback=block 时这类调用会失败以迫使 TCP 回退；设为 direct 则原样放行");
    }
}

pub unsafe extern "system" fn hook_closesocket(s: SOCKET) -> i32 {
    if let Some(ctx) = UDP.lock().unwrap_or_else(|e| e.into_inner()).remove(&s) {
        type Fn = unsafe extern "system" fn(SOCKET) -> i32;
        let f: Fn = std::mem::transmute(api().closesocket);
        f(ctx.control);
    }
    CONNECTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|_, ctx| ctx.socket != s);
    type Fn = unsafe extern "system" fn(SOCKET) -> i32;
    let f: Fn = std::mem::transmute(api().closesocket);
    f(s)
}

pub unsafe extern "system" fn hook_wsaioctl(
    s: SOCKET,
    code: u32,
    in_buf: *mut core::ffi::c_void,
    in_len: u32,
    out_buf: *mut core::ffi::c_void,
    out_len: u32,
    bytes: *mut u32,
    overlapped: *mut OVERLAPPED,
    routine: usize,
) -> i32 {
    type Fn = unsafe extern "system" fn(
        SOCKET,
        u32,
        *mut core::ffi::c_void,
        u32,
        *mut core::ffi::c_void,
        u32,
        *mut u32,
        *mut OVERLAPPED,
        usize,
    ) -> i32;
    let f: Fn = std::mem::transmute(api().wsaioctl);
    let rc = f(
        s, code, in_buf, in_len, out_buf, out_len, bytes, overlapped, routine,
    );
    if rc == 0
        && code == 0xC800_0006
        && !out_buf.is_null()
        && out_len as usize >= std::mem::size_of::<usize>()
    {
        let slot = out_buf as *mut usize;
        if api().connect_ex == 0 {
            // The captured pointer is preferred; keep the provider pointer if startup missed it.
        }
        *slot = hook_connect_ex as usize;
    }
    rc
}

pub unsafe extern "system" fn hook_connect_ex(
    s: SOCKET,
    name: *const core::ffi::c_void,
    namelen: i32,
    send_buf: *const core::ffi::c_void,
    send_len: u32,
    bytes: *mut u32,
    overlapped: *mut OVERLAPPED,
) -> i32 {
    if api().connect_ex == 0 || name.is_null() || !network_enabled() {
        return raw_connect_ex(s, name, namelen, send_buf, send_len, bytes, overlapped);
    }
    let Some(ep) = endpoint_of(name, Proto::Tcp) else {
        return raw_connect_ex(s, name, namelen, send_buf, send_len, bytes, overlapped);
    };
    if routing::decide(config(), &ep.view(), DecideOpts::WINDOWS) != Action::Proxy {
        return raw_connect_ex(s, name, namelen, send_buf, send_len, bytes, overlapped);
    }
    let Some(proxy) = proxy_buf(ep.family) else {
        WSASetLastError(10022);
        return FALSE;
    };
    if ep.family == (AF_INET6 as i32) {
        let off = 0i32;
        setsockopt(
            s,
            IPPROTO_IPV6,
            IPV6_V6ONLY,
            &off as *const _ as *const _,
            4,
        );
    }
    let host = ep.domain.clone().unwrap_or_else(|| display_ep(&ep));
    if overlapped.is_null() {
        if tcp_proxy(s, &ep, name) != 0 {
            return FALSE;
        }
        if send_len > 0 && !send_buf.is_null() {
            let data = std::slice::from_raw_parts(send_buf as *const u8, send_len as usize);
            if !send_all(s, data, config().timeout.send.max(1000)) {
                return FALSE;
            }
        }
        if !bytes.is_null() {
            *bytes = send_len;
        }
        return TRUE;
    }
    let initial = if send_len > 0 && !send_buf.is_null() {
        std::slice::from_raw_parts(send_buf as *const u8, send_len as usize).to_vec()
    } else {
        Vec::new()
    };
    CONNECTEX.lock().unwrap_or_else(|e| e.into_inner()).insert(
        overlapped as usize,
        CxCtx {
            socket: s,
            host,
            port: ep.port,
            initial,
        },
    );
    raw_connect_ex(
        s,
        proxy.bytes.as_ptr() as *const _,
        proxy.len,
        std::ptr::null(),
        0,
        bytes,
        overlapped,
    )
}

unsafe fn raw_connect_ex(
    s: SOCKET,
    name: *const core::ffi::c_void,
    namelen: i32,
    send_buf: *const core::ffi::c_void,
    send_len: u32,
    bytes: *mut u32,
    overlapped: *mut OVERLAPPED,
) -> i32 {
    type Fn = unsafe extern "system" fn(
        SOCKET,
        *const core::ffi::c_void,
        i32,
        *const core::ffi::c_void,
        u32,
        *mut u32,
        *mut OVERLAPPED,
    ) -> i32;
    if api().connect_ex == 0 {
        return FALSE;
    }
    let f: Fn = std::mem::transmute(api().connect_ex);
    f(s, name, namelen, send_buf, send_len, bytes, overlapped)
}

fn finish_connectex(overlapped: *mut OVERLAPPED) {
    if overlapped.is_null() {
        return;
    }
    let ctx = CONNECTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&(overlapped as usize));
    let Some(ctx) = ctx else { return };
    unsafe {
        if !handshake(
            ctx.socket,
            &ctx.host,
            ctx.port,
            config().timeout.connect.max(1000),
        ) {
            log::error(&format!(
                "ConnectEx 握手失败, 目标={}:{}",
                ctx.host, ctx.port
            ));
            // The socket is already connected to the proxy; close it so the app sees failure.
            windows_sys::Win32::Networking::WinSock::shutdown(ctx.socket, SD_BOTH);
            return;
        }
        if !ctx.initial.is_empty() {
            let _ = send_all(ctx.socket, &ctx.initial, config().timeout.send.max(1000));
        }
        log::info(&format!(
            "SOCKS5: 隧道建立成功, 目标={}:{}",
            ctx.host, ctx.port
        ));
    }
}

pub unsafe extern "system" fn hook_gqcs(
    port: HANDLE,
    bytes: *mut u32,
    key: *mut usize,
    overlapped: *mut *mut OVERLAPPED,
    timeout: u32,
) -> i32 {
    type Fn =
        unsafe extern "system" fn(HANDLE, *mut u32, *mut usize, *mut *mut OVERLAPPED, u32) -> i32;
    let f: Fn = std::mem::transmute(api().gqcs);
    let rc = f(port, bytes, key, overlapped, timeout);
    if rc == TRUE && !overlapped.is_null() && !(*overlapped).is_null() {
        finish_connectex(*overlapped);
    }
    rc
}

#[repr(C)]
pub(crate) struct OverlappedEntry {
    key: usize,
    overlapped: *mut OVERLAPPED,
    internal: usize,
    transferred: u32,
}

pub unsafe extern "system" fn hook_gqcs_ex(
    port: HANDLE,
    entries: *mut OverlappedEntry,
    count: u32,
    removed: *mut u32,
    timeout: u32,
    alertable: i32,
) -> i32 {
    type Fn =
        unsafe extern "system" fn(HANDLE, *mut OverlappedEntry, u32, *mut u32, u32, i32) -> i32;
    let f: Fn = std::mem::transmute(api().gqcs_ex);
    let rc = f(port, entries, count, removed, timeout, alertable);
    if rc == TRUE && !removed.is_null() && !entries.is_null() {
        let n = *removed;
        for i in 0..n {
            finish_connectex((*entries.add(i as usize)).overlapped);
        }
    }
    rc
}

pub unsafe extern "system" fn hook_create_process_w(
    app: *const u16,
    cmd: *mut u16,
    proc_attr: *mut core::ffi::c_void,
    thread_attr: *mut core::ffi::c_void,
    inherit: i32,
    flags: u32,
    env: *mut core::ffi::c_void,
    cwd: *const u16,
    startup: *mut core::ffi::c_void,
    info: *mut PROCESS_INFORMATION,
) -> i32 {
    spawn(
        true,
        app as *const _,
        cmd as *mut _,
        proc_attr,
        thread_attr,
        inherit,
        flags,
        env,
        cwd as *const _,
        startup,
        info,
    )
}

pub unsafe extern "system" fn hook_create_process_a(
    app: *const u8,
    cmd: *mut u8,
    proc_attr: *mut core::ffi::c_void,
    thread_attr: *mut core::ffi::c_void,
    inherit: i32,
    flags: u32,
    env: *mut core::ffi::c_void,
    cwd: *const u8,
    startup: *mut core::ffi::c_void,
    info: *mut PROCESS_INFORMATION,
) -> i32 {
    spawn(
        false,
        app as *const _,
        cmd as *mut _,
        proc_attr,
        thread_attr,
        inherit,
        flags,
        env,
        cwd as *const _,
        startup,
        info,
    )
}

unsafe fn spawn(
    wide_api: bool,
    app: *const core::ffi::c_void,
    cmd: *mut core::ffi::c_void,
    proc_attr: *mut core::ffi::c_void,
    thread_attr: *mut core::ffi::c_void,
    inherit: i32,
    flags: u32,
    env: *mut core::ffi::c_void,
    cwd: *const core::ffi::c_void,
    startup: *mut core::ffi::c_void,
    info: *mut PROCESS_INFORMATION,
) -> i32 {
    let cfg = config();
    let suspend = cfg.child_injection && (flags & CREATE_SUSPENDED) == 0;
    let mut used = flags;
    if suspend {
        used |= CREATE_SUSPENDED;
    }
    let rc = if wide_api {
        type Fn = unsafe extern "system" fn(
            *const u16,
            *mut u16,
            *mut core::ffi::c_void,
            *mut core::ffi::c_void,
            i32,
            u32,
            *mut core::ffi::c_void,
            *const u16,
            *mut core::ffi::c_void,
            *mut PROCESS_INFORMATION,
        ) -> i32;
        let f: Fn = std::mem::transmute(api().create_process_w);
        f(
            app as *const u16,
            cmd as *mut u16,
            proc_attr,
            thread_attr,
            inherit,
            used,
            env,
            cwd as *const u16,
            startup,
            info,
        )
    } else {
        type Fn = unsafe extern "system" fn(
            *const u8,
            *mut u8,
            *mut core::ffi::c_void,
            *mut core::ffi::c_void,
            i32,
            u32,
            *mut core::ffi::c_void,
            *const u8,
            *mut core::ffi::c_void,
            *mut PROCESS_INFORMATION,
        ) -> i32;
        let f: Fn = std::mem::transmute(api().create_process_a);
        f(
            app as *const u8,
            cmd as *mut u8,
            proc_attr,
            thread_attr,
            inherit,
            used,
            env,
            cwd as *const u8,
            startup,
            info,
        )
    };
    if rc == 0 || info.is_null() {
        return rc;
    }
    let exe = if wide_api {
        exe_name_w(app as *const u16, cmd as *const u16)
    } else {
        exe_name_a(app as *const u8, cmd as *const u8)
    };
    let inject_this = cfg.child_injection
        && !process::is_excluded(&exe, cfg)
        && process::is_targeted(&exe, cfg, HostPlatform::Windows, false);
    if inject_this {
        let dll = dll_path();
        match inject::inject_dll((*info).hProcess, &dll) {
            Ok(()) => log::info(&format!("[成功] 已注入目标进程: {exe}")),
            Err(err) => log::error(&format!("[失败] 注入目标进程失败: {exe} ({err})")),
        }
    } else if cfg.child_injection {
        log::debug(&format!("[跳过] 非目标进程: {exe}"));
    }
    if suspend {
        ResumeThread((*info).hThread);
    }
    rc
}

fn dll_path() -> String {
    let dir = super::module_dir(our_module());
    dir.join("version.dll").display().to_string()
}

fn exe_name_w(app: *const u16, cmd: *const u16) -> String {
    if !app.is_null() {
        return file_only(&lossy_wide(app));
    }
    file_only(&first_arg(&lossy_wide(cmd)))
}

fn exe_name_a(app: *const u8, cmd: *const u8) -> String {
    if !app.is_null() {
        return file_only(&cstr(app));
    }
    file_only(&first_arg(&cstr(cmd)))
}

fn first_arg(cmd: &str) -> String {
    let cmd = cmd.trim();
    if let Some(rest) = cmd.strip_prefix('"') {
        rest.split('"').next().unwrap_or(cmd).to_string()
    } else {
        cmd.split_whitespace().next().unwrap_or(cmd).to_string()
    }
}

fn file_only(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

// Silence a few intentional unused imports when the Windows SDK aliases differ.
#[allow(dead_code)]
fn _keep() {
    let _ = (FALSE, GetLastError);
}
