use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use agy_core::config::AppConfig;

static FILE: Mutex<Option<File>> = Mutex::new(None);
static LEVEL: Mutex<u8> = Mutex::new(1);

fn lock_file() -> std::sync::MutexGuard<'static, Option<File>> {
    FILE.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn init(dll_dir: &Path, cfg: &AppConfig) {
    let level = match cfg.log_level.to_ascii_lowercase().as_str() {
        "debug" => 0,
        "warn" => 2,
        "error" => 3,
        _ => 1,
    };
    *LEVEL.lock().unwrap_or_else(|e| e.into_inner()) = level;
    let day = utc_day();
    let name = format!("proxy-{day}.log");
    let primary = dll_dir.join("logs");
    let file = open_in(&primary, &name).or_else(|_| {
        let temp = std::env::temp_dir().join("antigravity-proxy-logs");
        open_in(&temp, &name)
    });
    if let Ok(file) = file {
        *lock_file() = Some(file);
    }
}

fn open_in(dir: &Path, name: &str) -> std::io::Result<File> {
    std::fs::create_dir_all(dir)?;
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(name))
}

fn utc_stamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let tod = secs % 86_400;
    format!(
        "{} {:02}:{:02}:{:02}Z",
        utc_day_from(secs),
        tod / 3600,
        (tod / 60) % 60,
        tod % 60
    )
}

fn utc_day() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    utc_day_from(secs)
}

fn utc_day_from(secs: u64) -> String {
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

fn enabled(level: u8) -> bool {
    level >= *LEVEL.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn write(level: u8, msg: &str) {
    if !enabled(level) {
        return;
    }
    let tag = match level {
        0 => "调试",
        1 => "信息",
        2 => "警告",
        _ => "错误",
    };
    let line = format!("[{}] [{tag}] {msg}\n", utc_stamp());
    if let Some(file) = lock_file().as_mut() {
        let _ = file.write_all(line.as_bytes());
        let _ = file.flush();
    }
}

pub fn info(msg: &str) {
    write(1, msg);
}

pub fn warn(msg: &str) {
    write(2, msg);
}

pub fn debug(msg: &str) {
    write(0, msg);
}

pub fn error(msg: &str) {
    write(3, msg);
}
