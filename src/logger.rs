use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::SystemTime;

const LOG_ROTATE_BYTES: u64 = 5 * 1024 * 1024;

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, PartialOrd, Debug)]
pub enum LogLevel {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
}

static CURRENT_LEVEL: AtomicU8 = AtomicU8::new(LogLevel::Info as u8);
static LOG_FILE: Mutex<Option<File>> = Mutex::new(None);
static STDERR_ECHO: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn resolve_log_path(config_path: Option<&Path>) -> PathBuf {
    if let Ok(path) = std::env::var("ANTIGRAVITY_PROXY_LOG") {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }
    if let Some(cfg) = config_path {
        if let Some(dir) = cfg.parent() {
            if !dir.as_os_str().is_empty() {
                return dir.join("proxy.log");
            }
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let dir = PathBuf::from(home).join(".config/antigravity-proxy");
        let _ = fs::create_dir_all(&dir);
        return dir.join("proxy.log");
    }
    if let Some(dir) = crate::ffi::get_so_directory() {
        return dir.join("proxy.log");
    }
    PathBuf::from("proxy.log")
}

pub fn init(log_path: &Path, level: LogLevel) {
    CURRENT_LEVEL.store(level as u8, Ordering::Relaxed);
    if std::env::var("ANTIGRAVITY_PROXY_DEBUG").is_ok() || level == LogLevel::Debug {
        STDERR_ECHO.store(true, Ordering::Relaxed);
    }
    rotate_if_big(log_path);
    if let Some(parent) = log_path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = fs::create_dir_all(parent);
        }
    }
    if let Ok(file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let mut guard = LOG_FILE.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(file);
    }
}

fn rotate_if_big(path: &Path) {
    let Ok(meta) = fs::metadata(path) else {
        return;
    };
    if meta.len() <= LOG_ROTATE_BYTES {
        return;
    }
    let backup = path.with_extension("log.1");
    let _ = fs::rename(path, backup);
}

pub fn log(level: LogLevel, proc_name: &str, pid: u32, msg: &str) {
    if (level as u8) < CURRENT_LEVEL.load(Ordering::Relaxed) {
        return;
    }

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();

    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        let t = secs as libc::time_t;
        libc::localtime_r(&t, &mut tm);
    }

    let time_str = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        millis
    );

    let level_str = match level {
        LogLevel::Debug => "调试",
        LogLevel::Info => "信息",
        LogLevel::Warn => "警告",
        LogLevel::Error => "错误",
    };

    let line = format!(
        "[{}] [{}] [{}:{}] {}\n",
        time_str, level_str, proc_name, pid, msg
    );

    let mut guard = LOG_FILE.lock().unwrap_or_else(|err| err.into_inner());
    if let Some(ref mut file) = *guard {
        let _ = file.write_all(line.as_bytes());
        let _ = file.flush();
    }

    if STDERR_ECHO.load(Ordering::Relaxed) {
        let prefix_line = format!("[Antigravity-Proxy-Rust] {}", line);
        let _ = std::io::stderr().write_all(prefix_line.as_bytes());
    }
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        $crate::logger::log($crate::logger::LogLevel::Debug, $crate::process::current_process_name(), unsafe { libc::getpid() as u32 }, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::logger::log($crate::logger::LogLevel::Info, $crate::process::current_process_name(), unsafe { libc::getpid() as u32 }, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        $crate::logger::log($crate::logger::LogLevel::Warn, $crate::process::current_process_name(), unsafe { libc::getpid() as u32 }, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::logger::log($crate::logger::LogLevel::Error, $crate::process::current_process_name(), unsafe { libc::getpid() as u32 }, &format!($($arg)*))
    };
}
