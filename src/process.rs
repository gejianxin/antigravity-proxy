use std::path::Path;
use std::sync::OnceLock;

static PROCESS_NAME: OnceLock<String> = OnceLock::new();

extern "C" {
    static program_invocation_short_name: *const libc::c_char;
}

pub fn current_process_name() -> &'static str {
    PROCESS_NAME.get_or_init(|| {
        unsafe {
            if !program_invocation_short_name.is_null() {
                let c_str = std::ffi::CStr::from_ptr(program_invocation_short_name);
                if let Ok(s) = c_str.to_str() {
                    if !s.is_empty() {
                        return s.to_string();
                    }
                }
            }
        }

        if let Ok(exe_link) = std::fs::read_link("/proc/self/exe") {
            if let Some(file_name) = exe_link.file_name().and_then(|n| n.to_str()) {
                return file_name.to_string();
            }
        }

        if let Ok(cmdline) = std::fs::read_to_string("/proc/self/cmdline") {
            if let Some(first_arg) = cmdline.split('\0').next() {
                if let Some(file_name) = Path::new(first_arg).file_name().and_then(|n| n.to_str()) {
                    if !file_name.is_empty() {
                        return file_name.to_string();
                    }
                }
            }
        }

        "unknown".to_string()
    })
}

fn match_pattern(proc_name: &str, pattern: &str) -> bool {
    let p_clean = pattern.trim_end_matches(".exe");
    proc_name.to_lowercase().contains(&p_clean.to_lowercase())
}

pub fn is_targeted_process(config: &crate::config::AppConfig) -> bool {
    if std::env::var("ANTIGRAVITY_PROXY_FORCE").is_ok() {
        return true;
    }

    let proc = current_process_name();

    // Check exclusion
    for excl in &config.child_injection_exclude {
        if match_pattern(proc, excl) {
            return false;
        }
    }

    if config.child_injection_mode.eq_ignore_ascii_case("inherit") {
        return true;
    }

    if config.target_processes.is_empty() {
        return true;
    }

    for target in &config.target_processes {
        if match_pattern(proc, target) {
            return true;
        }
    }

    // Also check resolved /proc/self/exe
    if let Ok(exe_link) = std::fs::read_link("/proc/self/exe") {
        if let Some(file_name) = exe_link.file_name().and_then(|n| n.to_str()) {
            for target in &config.target_processes {
                if match_pattern(file_name, target) {
                    return true;
                }
            }
        }
    }

    false
}
