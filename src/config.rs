use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

fn default_true() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_child_injection_mode() -> String {
    "filtered".to_string()
}

fn default_target_processes() -> Vec<String> {
    vec![
        "antigravity".to_string(),
        "language_server".to_string(),
        "language_server_linux".to_string(),
        "language_server_linux_x64".to_string(),
        "language_server_linux_arm64".to_string(),
        "agy".to_string(),
        "node".to_string(),
    ]
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyConfig {
    #[serde(default = "default_proxy_host")]
    pub host: String,
    #[serde(default = "default_proxy_port")]
    pub port: u16,
    #[serde(default = "default_proxy_type")]
    pub r#type: String,
}

fn default_proxy_host() -> String {
    "127.0.0.1".to_string()
}

fn default_proxy_port() -> u16 {
    7898
}

fn default_proxy_type() -> String {
    "socks5".to_string()
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            host: default_proxy_host(),
            port: default_proxy_port(),
            r#type: default_proxy_type(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FakeIpConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_fake_ip_cidr")]
    pub cidr: String,
}

fn default_fake_ip_cidr() -> String {
    "198.18.0.0/15".to_string()
}

impl Default for FakeIpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cidr: default_fake_ip_cidr(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TimeoutConfig {
    #[serde(default = "default_timeout_ms")]
    pub connect: u32,
    #[serde(default = "default_timeout_ms")]
    pub send: u32,
    #[serde(default = "default_timeout_ms")]
    pub recv: u32,
}

fn default_timeout_ms() -> u32 {
    5000
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            connect: default_timeout_ms(),
            send: default_timeout_ms(),
            recv: default_timeout_ms(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RoutingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub use_default_private: bool,
    #[serde(default = "default_action_proxy")]
    pub default_action: String,
}

fn default_action_proxy() -> String {
    "proxy".to_string()
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            use_default_private: true,
            default_action: default_action_proxy(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyRulesConfig {
    #[serde(default = "default_allowed_ports")]
    pub allowed_ports: Vec<u16>,
    #[serde(default = "default_dns_mode")]
    pub dns_mode: String,
    #[serde(default)]
    pub routing: RoutingConfig,
}

fn default_allowed_ports() -> Vec<u16> {
    vec![80, 443]
}

fn default_dns_mode() -> String {
    "direct".to_string()
}

impl Default for ProxyRulesConfig {
    fn default() -> Self {
        Self {
            allowed_ports: default_allowed_ports(),
            dns_mode: default_dns_mode(),
            routing: RoutingConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub traffic_logging: bool,
    #[serde(default = "default_true")]
    pub child_injection: bool,
    #[serde(default = "default_child_injection_mode")]
    pub child_injection_mode: String,
    #[serde(default)]
    pub child_injection_exclude: Vec<String>,
    #[serde(default = "default_target_processes")]
    pub target_processes: Vec<String>,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub fake_ip: FakeIpConfig,
    #[serde(default)]
    pub timeout: TimeoutConfig,
    #[serde(default)]
    pub proxy_rules: ProxyRulesConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            traffic_logging: false,
            child_injection: true,
            child_injection_mode: default_child_injection_mode(),
            child_injection_exclude: Vec::new(),
            target_processes: default_target_processes(),
            proxy: ProxyConfig::default(),
            fake_ip: FakeIpConfig::default(),
            timeout: TimeoutConfig::default(),
            proxy_rules: ProxyRulesConfig::default(),
        }
    }
}

impl AppConfig {
    pub fn load() -> (Self, Option<PathBuf>) {
        let candidates = [
            std::env::var("ANTIGRAVITY_PROXY_CONFIG").ok().map(PathBuf::from),
            Some(PathBuf::from("config.json")),
            crate::ffi::get_so_directory().map(|d| d.join("config.json")),
            std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".config/antigravity-proxy/config.json")),
            Some(PathBuf::from("/etc/antigravity-proxy/config.json")),
        ];

        for opt in candidates.into_iter().flatten() {
            if opt.is_file() {
                if let Ok(content) = fs::read_to_string(&opt) {
                    if let Ok(cfg) = serde_json::from_str::<AppConfig>(&content) {
                        return (cfg, Some(opt));
                    }
                }
            }
        }

        (AppConfig::default(), None)
    }
}
