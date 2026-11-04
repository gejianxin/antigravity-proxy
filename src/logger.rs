use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::SystemTime;

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

pub fn init(log_path: Option<&str>, level: LogLevel) {
    CURRENT_LEVEL.store(level as u8, Ordering::Relaxed);
    if std::env::var("ANTIGRAVITY_PROXY_DEBUG").is_ok() || level == LogLevel::Debug {
        STDERR_ECHO.store(true, Ordering::Relaxed);
    }

    if let Some(path) = log_path {
        if let Ok(file) = OpenOptions::new().create(true).append(true).open(path) {
            let mut guard = LOG_FILE.lock().unwrap();
            *guard = Some(file);
        }
    }
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

    let line = format!("[{}] [{}] [{}:{}] {}\n", time_str, level_str, proc_name, pid, msg);

    if let Ok(mut guard) = LOG_FILE.lock() {
        if let Some(ref mut file) = *guard {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        }
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
