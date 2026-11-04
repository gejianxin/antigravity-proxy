pub mod ffi;
pub mod logger;
pub mod config;
pub mod process;
pub mod fakeip;
pub mod socks5;
pub mod http;
pub mod interceptor;

use std::sync::OnceLock;

static CONFIG: OnceLock<config::AppConfig> = OnceLock::new();

pub fn get_config() -> &'static config::AppConfig {
    CONFIG.get_or_init(|| {
        let (cfg, _path) = config::AppConfig::load();
        cfg
    })
}

pub fn initialize() {
    let cfg = get_config();
    let proc_name = process::current_process_name();
    let is_targeted = process::is_targeted_process(cfg);

    let log_level = match cfg.log_level.to_lowercase().as_str() {
        "debug" => logger::LogLevel::Debug,
        "warn" => logger::LogLevel::Warn,
        "error" => logger::LogLevel::Error,
        _ => logger::LogLevel::Info,
    };

    logger::init(Some("proxy.log"), log_level);

    if is_targeted {
        if cfg.fake_ip.enabled {
            fakeip::init(&cfg.fake_ip.cidr);
        }

        log_info!("==================================================");
        log_info!("Antigravity-Proxy Linux (Rust 重构版 v2.4) 已加载");
        log_info!("目标进程: {} (PID={})", proc_name, unsafe { libc::getpid() });
        log_info!(
            "代理配置: {}://{}:{}",
            cfg.proxy.r#type,
            cfg.proxy.host,
            cfg.proxy.port
        );
        log_info!(
            "FakeIP 系统: {} (CIDR: {})",
            if cfg.fake_ip.enabled { "已启用" } else { "未启用" },
            cfg.fake_ip.cidr
        );
        log_info!("==================================================");
    }
}

pub fn cleanup() {
    // Optional cleanup
}

#[used]
#[link_section = ".init_array"]
static INIT: unsafe extern "C" fn() = init_constructor;

unsafe extern "C" fn init_constructor() {
    initialize();
}

// -------------------------------------------------------------
// Intercepted C Exports
// -------------------------------------------------------------

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
