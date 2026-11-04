mod child;
mod hooks;
mod net;

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, Once};
use std::time::{SystemTime, UNIX_EPOCH};

use agy_core::config::{AppConfig, HostPlatform};
use agy_core::fakeip;
use agy_core::process;

static START: Once = Once::new();
static LOG: Mutex<Option<File>> = Mutex::new(None);
static START_DEPTH: AtomicUsize = AtomicUsize::new(0);

/// Run `startup` once. If a hook fires again while startup is still on this
/// call stack, return false so the hook can call libSystem directly.
pub fn try_startup() -> bool {
    if START.is_completed() {
        return true;
    }
    if START_DEPTH.fetch_add(1, Ordering::SeqCst) != 0 {
        START_DEPTH.fetch_sub(1, Ordering::SeqCst);
        return false;
    }
    startup();
    START_DEPTH.fetch_sub(1, Ordering::SeqCst);
    START.is_completed()
}

fn startup() {
    START.call_once(|| {
        let dir = dylib_dir();
        let (cfg, cfg_path) = load_config(dir.as_deref());
        open_log(dir.as_deref());
        if cfg.fake_ip.enabled {
            fakeip::init(&cfg.fake_ip.cidr);
        }
        hooks::install(cfg);
        let name = current_process_name();
        log(&format!(
            "Antigravity-Proxy macOS dylib 已加载 (Rust v2.5) pid={} process={} config={}",
            std::process::id(),
            name,
            cfg_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(默认)".into())
        ));
    });
}

pub fn current_process_name() -> String {
    if let Ok(path) = std::env::current_exe() {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    std::env::args()
        .next()
        .as_deref()
        .and_then(|arg| Path::new(arg).file_name().and_then(|n| n.to_str()))
        .unwrap_or("unknown")
        .to_string()
}

pub fn is_targeted(cfg: &AppConfig) -> bool {
    let force = std::env::var("ANTIGRAVITY_PROXY_FORCE").is_ok();
    process::is_targeted(&current_process_name(), cfg, HostPlatform::Macos, force)
}

fn dylib_dir() -> Option<PathBuf> {
    unsafe {
        let mut info: libc::Dl_info = std::mem::zeroed();
        if libc::dladdr(startup as *const () as *const libc::c_void, &mut info) == 0
            || info.dli_fname.is_null()
        {
            return None;
        }
        let text = std::ffi::CStr::from_ptr(info.dli_fname)
            .to_string_lossy()
            .into_owned();
        Path::new(&text).parent().map(|p| p.to_path_buf())
    }
}

fn load_config(dylib_dir: Option<&Path>) -> (AppConfig, Option<PathBuf>) {
    let mut candidates = Vec::new();
    if let Ok(env) = std::env::var("ANTIGRAVITY_PROXY_CONFIG") {
        candidates.push(PathBuf::from(env));
    }
    if let Some(dir) = dylib_dir {
        candidates.push(dir.join("config.json"));
    }
    candidates.push(PathBuf::from("config.json"));
    if let Ok(home) = std::env::var("HOME") {
        let home = PathBuf::from(home);
        candidates.push(
            home.join("Library/Application Support/antigravity-proxy/config.json"),
        );
        candidates.push(home.join(".config/antigravity-proxy/config.json"));
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

fn open_log(dylib_dir: Option<&Path>) {
    let day = utc_day();
    let name = format!("proxy-{day}.log");
    let mut paths = Vec::new();
    if let Some(dir) = dylib_dir {
        paths.push(dir.join("logs").join(&name));
    }
    if let Ok(home) = std::env::var("HOME") {
        paths.push(
            PathBuf::from(home)
                .join("Library/Logs/antigravity-proxy")
                .join(&name),
        );
    }
    for path in paths {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(file) = OpenOptions::new().create(true).append(true).open(&path) {
            *LOG.lock().unwrap_or_else(|e| e.into_inner()) = Some(file);
            return;
        }
    }
}

fn utc_day() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}{m:02}{d:02}")
}

pub fn log(msg: &str) {
    let line = format!("[macOS] {msg}\n");
    if let Some(file) = LOG.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        let _ = file.write_all(line.as_bytes());
        let _ = file.flush();
    }
    if std::env::var("ANTIGRAVITY_PROXY_DEBUG").is_ok() {
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
}
