use crate::config::{AppConfig, HostPlatform};

pub fn name_matches(proc_name: &str, pattern: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    let pattern = pattern
        .strip_suffix(".exe")
        .or_else(|| pattern.strip_suffix(".EXE"))
        .unwrap_or(pattern);
    proc_name
        .to_ascii_lowercase()
        .contains(&pattern.to_ascii_lowercase())
}

pub fn is_excluded(proc_name: &str, cfg: &AppConfig) -> bool {
    cfg.child_injection_exclude
        .iter()
        .any(|pattern| name_matches(proc_name, pattern))
}

/// `force` is the `ANTIGRAVITY_PROXY_FORCE` override used by the Linux smoke test.
pub fn is_targeted(proc_name: &str, cfg: &AppConfig, platform: HostPlatform, force: bool) -> bool {
    if force {
        return true;
    }
    if is_excluded(proc_name, cfg) {
        return false;
    }
    if cfg.child_injection_mode.eq_ignore_ascii_case("inherit") {
        return true;
    }
    let targets = cfg.targets(platform);
    if targets.is_empty() {
        return true;
    }
    targets
        .iter()
        .any(|pattern| name_matches(proc_name, pattern))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;

    #[test]
    fn windows_exe_names_match_without_extension() {
        let mut cfg = AppConfig::default();
        cfg.target_processes = Some(vec!["language_server".into(), "Antigravity IDE.exe".into()]);
        assert!(is_targeted(
            "language_server_windows_x64.exe",
            &cfg,
            HostPlatform::Windows,
            false
        ));
        assert!(is_targeted(
            "Antigravity IDE.exe",
            &cfg,
            HostPlatform::Windows,
            false
        ));
        assert!(!is_targeted("git.exe", &cfg, HostPlatform::Windows, false));
    }

    #[test]
    fn macos_helper_name_matches_antigravity() {
        let cfg = AppConfig::default();
        assert!(is_targeted(
            "Antigravity Helper",
            &cfg,
            HostPlatform::Macos,
            false
        ));
        assert!(is_targeted(
            "language_server",
            &cfg,
            HostPlatform::Macos,
            false
        ));
        assert!(!is_targeted("git", &cfg, HostPlatform::Macos, false));
    }

    #[test]
    fn exclude_beats_inherit() {
        let mut cfg = AppConfig::default();
        cfg.child_injection_mode = "inherit".into();
        cfg.child_injection_exclude = vec!["git".into()];
        assert!(!is_targeted("git", &cfg, HostPlatform::Linux, false));
        assert!(is_targeted("node", &cfg, HostPlatform::Linux, false));
    }
}
