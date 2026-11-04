use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_child_injection_mode() -> String {
    "filtered".to_string()
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

fn default_fake_ip_cidr() -> String {
    "198.18.0.0/15".to_string()
}

fn default_timeout_ms() -> u32 {
    5000
}

fn default_action_proxy() -> String {
    "proxy".to_string()
}

fn default_allowed_ports() -> Vec<u16> {
    vec![80, 443]
}

fn default_dns_mode() -> String {
    "direct".to_string()
}

fn default_ipv6_mode() -> String {
    "proxy".to_string()
}

fn default_udp_mode() -> String {
    "auto".to_string()
}

fn default_udp_fallback() -> String {
    "block".to_string()
}

fn default_priority_mode() -> String {
    "order".to_string()
}

/// Which built-in `target_processes` list to use when the key is omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPlatform {
    Linux,
    Windows,
}

pub fn default_target_processes(platform: HostPlatform) -> Vec<String> {
    match platform {
        HostPlatform::Linux => vec![
            "antigravity".to_string(),
            "language_server".to_string(),
            "language_server_linux".to_string(),
            "language_server_linux_x64".to_string(),
            "language_server_linux_arm64".to_string(),
            "agy".to_string(),
            "node".to_string(),
        ],
        HostPlatform::Windows => vec![
            "agy.exe".to_string(),
            "language_server.exe".to_string(),
            "language_server_windows".to_string(),
            "Antigravity.exe".to_string(),
            "Antigravity IDE.exe".to_string(),
            "node.exe".to_string(),
        ],
    }
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

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            host: default_proxy_host(),
            port: default_proxy_port(),
            r#type: default_proxy_type(),
        }
    }
}

impl ProxyConfig {
    pub fn is_http(&self) -> bool {
        let t = self.r#type.to_ascii_lowercase();
        t == "http" || t == "https"
    }

    pub fn is_socks5(&self) -> bool {
        !self.is_http()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FakeIpConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_fake_ip_cidr")]
    pub cidr: String,
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
pub struct RouteRule {
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_action_proxy")]
    pub action: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub ip_cidrs_v4: Vec<String>,
    #[serde(default)]
    pub ip_cidrs_v6: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub protocols: Vec<String>,
}

impl Default for RouteRule {
    fn default() -> Self {
        Self {
            name: String::new(),
            action: default_action_proxy(),
            priority: 0,
            ip_cidrs_v4: Vec::new(),
            ip_cidrs_v6: Vec::new(),
            domains: Vec::new(),
            ports: Vec::new(),
            protocols: Vec::new(),
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
    #[serde(default = "default_priority_mode")]
    pub priority_mode: String,
    #[serde(default)]
    pub rules: Vec<RouteRule>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            use_default_private: true,
            default_action: default_action_proxy(),
            priority_mode: default_priority_mode(),
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyRulesConfig {
    #[serde(default = "default_allowed_ports")]
    pub allowed_ports: Vec<u16>,
    #[serde(default = "default_dns_mode")]
    pub dns_mode: String,
    #[serde(default = "default_ipv6_mode")]
    pub ipv6_mode: String,
    #[serde(default = "default_udp_mode")]
    pub udp_mode: String,
    #[serde(default = "default_udp_fallback")]
    pub udp_fallback: String,
    #[serde(default)]
    pub routing: RoutingConfig,
}

impl Default for ProxyRulesConfig {
    fn default() -> Self {
        Self {
            allowed_ports: default_allowed_ports(),
            dns_mode: default_dns_mode(),
            ipv6_mode: default_ipv6_mode(),
            udp_mode: default_udp_mode(),
            udp_fallback: default_udp_fallback(),
            routing: RoutingConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DiagnosticsConfig {
    #[serde(default)]
    pub agent_ip_probe: bool,
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
    /// `None` means the key was omitted and the platform default list applies.
    /// `Some(empty)` means every process (still subject to the exclude list).
    #[serde(default)]
    pub target_processes: Option<Vec<String>>,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub fake_ip: FakeIpConfig,
    #[serde(default)]
    pub timeout: TimeoutConfig,
    #[serde(default)]
    pub proxy_rules: ProxyRulesConfig,
    #[serde(default)]
    pub diagnostics: DiagnosticsConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            traffic_logging: false,
            child_injection: true,
            child_injection_mode: default_child_injection_mode(),
            child_injection_exclude: Vec::new(),
            target_processes: None,
            proxy: ProxyConfig::default(),
            fake_ip: FakeIpConfig::default(),
            timeout: TimeoutConfig::default(),
            proxy_rules: ProxyRulesConfig::default(),
            diagnostics: DiagnosticsConfig::default(),
        }
    }
}

impl AppConfig {
    pub fn parse_str(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }

    pub fn targets(&self, platform: HostPlatform) -> Vec<String> {
        match &self.target_processes {
            Some(list) => list.clone(),
            None => default_target_processes(platform),
        }
    }

    pub fn port_allowed(&self, port: u16) -> bool {
        self.proxy_rules.allowed_ports.is_empty() || self.proxy_rules.allowed_ports.contains(&port)
    }

    pub fn dns_is_direct(&self) -> bool {
        let mode = self.proxy_rules.dns_mode.to_ascii_lowercase();
        mode.is_empty() || mode == "direct"
    }
}
