pub mod config;
pub mod endpoint;
pub mod fakeip;
pub mod ffi;
pub mod guard;
pub mod http;
pub mod inherit;
pub mod interceptor;
pub mod logger;
pub mod process;
pub mod route;
pub mod sockio;
pub mod socks5;
pub mod udp;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

struct Runtime {
    config: config::AppConfig,
    config_path: Option<PathBuf>,
    log_path: PathBuf,
}

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static BANNER: AtomicBool = AtomicBool::new(false);

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        let (cfg, path) = config::AppConfig::load();
        let log_path = logger::resolve_log_path(path.as_deref());
        let level = match cfg.log_level.to_ascii_lowercase().as_str() {
            "debug" => logger::LogLevel::Debug,
            "warn" => logger::LogLevel::Warn,
            "error" => logger::LogLevel::Error,
            _ => logger::LogLevel::Info,
        };
        logger::init(&log_path, level);
        if cfg.fake_ip.enabled {
            fakeip::init(&cfg.fake_ip.cidr);
        }
        for warning in &cfg.load_warnings {
            log_warn!("[配置] {warning}");
        }
        Runtime {
            config: cfg,
            config_path: path,
            log_path,
        }
    })
}

pub fn get_config() -> &'static config::AppConfig {
    &runtime().config
}

pub fn initialize() {
    let rt = runtime();
    if BANNER.swap(true, Ordering::Relaxed) {
        return;
    }
    let cfg = &rt.config;
    if !process::is_targeted_process(cfg) {
        return;
    }
    let proc_name = process::current_process_name();
    log_info!("==================================================");
    log_info!("Antigravity-Proxy Linux (Rust v2.5) 已加载");
    log_info!("目标进程: {} (PID={})", proc_name, unsafe {
        libc::getpid()
    });
    log_info!(
        "代理配置: {}://{}:{}",
        cfg.proxy.r#type,
        cfg.proxy.host,
        cfg.proxy.port
    );
    log_info!(
        "配置文件: {}",
        rt.config_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "(内置默认)".to_string())
    );
    log_info!("日志文件: {}", rt.log_path.display());
    log_info!(
        "FakeIP: {} ({})",
        if cfg.fake_ip.enabled {
            "已启用"
        } else {
            "未启用"
        },
        cfg.fake_ip.cidr
    );
    log_info!(
        "策略: ipv6_mode={} udp_mode={} udp_fallback={} dns_mode={} child_injection={} ({})",
        cfg.proxy_rules.ipv6_mode,
        cfg.proxy_rules.udp_mode,
        cfg.proxy_rules.udp_fallback,
        cfg.proxy_rules.dns_mode,
        if cfg.child_injection { "开" } else { "关" },
        cfg.child_injection_mode
    );
    log_info!("==================================================");
}

#[used]
#[link_section = ".init_array"]
static INIT: unsafe extern "C" fn() = init_constructor;

unsafe extern "C" fn init_constructor() {
    initialize();
}

#[no_mangle]
pub unsafe extern "C" fn connect(
    sockfd: libc::c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> libc::c_int {
    interceptor::handle_connect(sockfd, addr, addrlen)
}

#[no_mangle]
pub unsafe extern "C" fn getaddrinfo(
    node: *const libc::c_char,
    service: *const libc::c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> libc::c_int {
    interceptor::handle_getaddrinfo(node, service, hints, res)
}

#[no_mangle]
pub unsafe extern "C" fn freeaddrinfo(res: *mut libc::addrinfo) {
    interceptor::handle_freeaddrinfo(res);
}

#[no_mangle]
pub unsafe extern "C" fn gethostbyname(name: *const libc::c_char) -> *mut libc::hostent {
    interceptor::handle_gethostbyname(name)
}

#[no_mangle]
pub unsafe extern "C" fn send(
    fd: libc::c_int,
    buf: *const libc::c_void,
    len: libc::size_t,
    flags: libc::c_int,
) -> libc::ssize_t {
    if guard::in_hook() || !udp::inspect_udp() || !process::is_targeted_process(get_config()) {
        return ffi::real_send(fd, buf, len, flags);
    }
    let _guard = guard::Guard::enter();
    match udp::on_send(fd, buf, len, flags) {
        Some(n) => n,
        None => ffi::real_send(fd, buf, len, flags),
    }
}

#[no_mangle]
pub unsafe extern "C" fn sendto(
    fd: libc::c_int,
    buf: *const libc::c_void,
    len: libc::size_t,
    flags: libc::c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> libc::ssize_t {
    if guard::in_hook() || !udp::inspect_udp() || !process::is_targeted_process(get_config()) {
        return ffi::real_sendto(fd, buf, len, flags, addr, addrlen);
    }
    let _guard = guard::Guard::enter();
    match udp::on_sendto(fd, buf, len, flags, addr, addrlen) {
        Some(n) => n,
        None => ffi::real_sendto(fd, buf, len, flags, addr, addrlen),
    }
}

#[no_mangle]
pub unsafe extern "C" fn recv(
    fd: libc::c_int,
    buf: *mut libc::c_void,
    len: libc::size_t,
    flags: libc::c_int,
) -> libc::ssize_t {
    if guard::in_hook() || !udp::has_sessions() {
        return ffi::real_recv(fd, buf, len, flags);
    }
    let _guard = guard::Guard::enter();
    match udp::on_recv(fd, buf, len, flags) {
        Some(n) => n,
        None => ffi::real_recv(fd, buf, len, flags),
    }
}

#[no_mangle]
pub unsafe extern "C" fn recvfrom(
    fd: libc::c_int,
    buf: *mut libc::c_void,
    len: libc::size_t,
    flags: libc::c_int,
    addr: *mut libc::sockaddr,
    addrlen: *mut libc::socklen_t,
) -> libc::ssize_t {
    if guard::in_hook() || !udp::has_sessions() {
        return ffi::real_recvfrom(fd, buf, len, flags, addr, addrlen);
    }
    let _guard = guard::Guard::enter();
    match udp::on_recvfrom(fd, buf, len, flags, addr, addrlen) {
        Some(n) => n,
        None => ffi::real_recvfrom(fd, buf, len, flags, addr, addrlen),
    }
}

#[no_mangle]
pub unsafe extern "C" fn sendmsg(
    fd: libc::c_int,
    msg: *const libc::msghdr,
    flags: libc::c_int,
) -> libc::ssize_t {
    if guard::in_hook() || !udp::inspect_udp() || !process::is_targeted_process(get_config()) {
        return ffi::real_sendmsg(fd, msg, flags);
    }
    let _guard = guard::Guard::enter();
    match udp::on_sendmsg(fd, msg, flags) {
        Some(n) => n,
        None => ffi::real_sendmsg(fd, msg, flags),
    }
}

#[no_mangle]
pub unsafe extern "C" fn recvmsg(
    fd: libc::c_int,
    msg: *mut libc::msghdr,
    flags: libc::c_int,
) -> libc::ssize_t {
    if guard::in_hook() || !udp::has_sessions() {
        return ffi::real_recvmsg(fd, msg, flags);
    }
    let _guard = guard::Guard::enter();
    match udp::on_recvmsg(fd, msg, flags) {
        Some(n) => n,
        None => ffi::real_recvmsg(fd, msg, flags),
    }
}

#[no_mangle]
pub unsafe extern "C" fn sendmmsg(
    fd: libc::c_int,
    msgvec: *mut libc::mmsghdr,
    vlen: libc::c_uint,
    flags: libc::c_int,
) -> libc::c_int {
    if guard::in_hook() || !udp::inspect_udp() || !process::is_targeted_process(get_config()) {
        return ffi::real_sendmmsg(fd, msgvec, vlen, flags);
    }
    let _guard = guard::Guard::enter();
    match udp::on_sendmmsg(fd, msgvec, vlen, flags) {
        Some(n) => n,
        None => ffi::real_sendmmsg(fd, msgvec, vlen, flags),
    }
}

#[no_mangle]
pub unsafe extern "C" fn recvmmsg(
    fd: libc::c_int,
    msgvec: *mut libc::mmsghdr,
    vlen: libc::c_uint,
    flags: libc::c_int,
    timeout: *mut libc::timespec,
) -> libc::c_int {
    if guard::in_hook() || !udp::has_sessions() {
        return ffi::real_recvmmsg(fd, msgvec, vlen, flags, timeout);
    }
    let _guard = guard::Guard::enter();
    match udp::on_recvmmsg(fd, msgvec, vlen, flags) {
        Some(n) => n,
        None => ffi::real_recvmmsg(fd, msgvec, vlen, flags, timeout),
    }
}

#[no_mangle]
pub unsafe extern "C" fn close(fd: libc::c_int) -> libc::c_int {
    if guard::in_hook() || !udp::has_sessions() {
        return ffi::real_close(fd);
    }
    let _guard = guard::Guard::enter();
    udp::on_close(fd)
}

#[no_mangle]
pub unsafe extern "C" fn execve(
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> libc::c_int {
    inherit::hook_execve(path, argv, envp)
}

#[no_mangle]
pub unsafe extern "C" fn execv(
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
) -> libc::c_int {
    inherit::hook_execv(path, argv)
}

#[no_mangle]
pub unsafe extern "C" fn execvp(
    file: *const libc::c_char,
    argv: *const *const libc::c_char,
) -> libc::c_int {
    inherit::hook_execvp(file, argv)
}

#[no_mangle]
pub unsafe extern "C" fn execvpe(
    file: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> libc::c_int {
    inherit::hook_execvpe(file, argv, envp)
}

#[no_mangle]
pub unsafe extern "C" fn fexecve(
    fd: libc::c_int,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> libc::c_int {
    inherit::hook_fexecve(fd, argv, envp)
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawn(
    pid: *mut libc::pid_t,
    path: *const libc::c_char,
    file_actions: *const libc::c_void,
    attrp: *const libc::c_void,
    argv: *const *mut libc::c_char,
    envp: *const *mut libc::c_char,
) -> libc::c_int {
    inherit::hook_posix_spawn(pid, path, file_actions, attrp, argv, envp, false)
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawnp(
    pid: *mut libc::pid_t,
    file: *const libc::c_char,
    file_actions: *const libc::c_void,
    attrp: *const libc::c_void,
    argv: *const *mut libc::c_char,
    envp: *const *mut libc::c_char,
) -> libc::c_int {
    inherit::hook_posix_spawn(pid, file, file_actions, attrp, argv, envp, true)
}
