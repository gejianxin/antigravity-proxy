mod hooks;
mod iat;
mod inject;
mod log;
mod version;

use std::path::{Path, PathBuf};
use std::sync::Once;

use agy_core::config::{AppConfig, HostPlatform};
use agy_core::fakeip;
use agy_core::process;

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
};

static START: Once = Once::new();

pub fn startup() {
    START.call_once(|| {
        let module = our_module();
        let dir = module_dir(module);
        let (cfg, cfg_path) = load_config(&dir);
        log::init(&dir, &cfg);
        if cfg.fake_ip.enabled {
            fakeip::init(&cfg.fake_ip.cidr);
        }
        hooks::install(&cfg);
        let proc_name = current_process_name();
        log::info(&format!(
            "Antigravity-Proxy Windows DLL 已加载 (Rust v2.5) pid={} process={} targeted={} config={}",
            std::process::id(),
            proc_name,
            process::is_targeted(&proc_name, &cfg, HostPlatform::Windows, forced()),
            cfg_path
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(默认)".into())
        ));
        log::info(&format!(
            "代理配置: {}://{}:{} FakeIP={} ({}) ipv6_mode={} udp_mode={} child_injection={}",
            cfg.proxy.r#type,
            cfg.proxy.host,
            cfg.proxy.port,
            if cfg.fake_ip.enabled { "开" } else { "关" },
            cfg.fake_ip.cidr,
            cfg.proxy_rules.ipv6_mode,
            cfg.proxy_rules.udp_mode,
            if cfg.child_injection { "开" } else { "关" }
        ));
        if cfg.diagnostics.agent_ip_probe {
            log::info("diagnostics.agent_ip_probe 已解析；出口 IP 探测仍需在 Windows 上对照应用日志，本构建不主动外联诊断服务");
        }
    });
}

pub fn current_process_name() -> String {
    let mut buf = [0u16; 1024];
    let n = unsafe { GetModuleFileNameW(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 {
        return "unknown".into();
    }
    let path = String::from_utf16_lossy(&buf[..n as usize]);
    Path::new(&path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string()
}

pub fn forced() -> bool {
    std::env::var("ANTIGRAVITY_PROXY_FORCE").is_ok()
}

pub fn our_module() -> HMODULE {
    let mut module: HMODULE = std::ptr::null_mut();
    unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            startup as *const () as *const u16,
            &mut module,
        );
    }
    module
}

pub fn module_dir(module: HMODULE) -> PathBuf {
    let mut buf = [0u16; 1024];
    let n = unsafe { GetModuleFileNameW(module, buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 {
        return PathBuf::from(".");
    }
    let path = String::from_utf16_lossy(&buf[..n as usize]);
    Path::new(&path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn load_config(dll_dir: &Path) -> (AppConfig, Option<PathBuf>) {
    let mut candidates = Vec::new();
    if let Ok(env) = std::env::var("ANTIGRAVITY_PROXY_CONFIG") {
        candidates.push(PathBuf::from(env));
    }
    candidates.push(dll_dir.join("config.json"));
    candidates.push(PathBuf::from("config.json"));
    if let Ok(appdata) = std::env::var("APPDATA") {
        candidates.push(
            PathBuf::from(appdata)
                .join("antigravity-proxy")
                .join("config.json"),
        );
    }
    for path in candidates {
        if path.is_file() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                if let Ok(cfg) = AppConfig::parse_str(&text) {
                    return (cfg, Some(path));
                }
            }
        }
    }
    (AppConfig::default(), None)
}

pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn lossy_wide(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe {
        let mut n = 0usize;
        while n < 4096 && *ptr.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, n))
    }
}
