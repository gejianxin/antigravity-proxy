use serde::{Deserialize, Deserializer, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::route::{self, CompiledRoutes, RuleSpec};

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

fn de_string_or_number_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<serde_json::Value>::deserialize(deserializer)?;
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        match value {
            serde_json::Value::String(s) => out.push(s),
            serde_json::Value::Number(n) => out.push(n.to_string()),
            _ => {}
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RoutingRuleConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
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
    #[serde(default, deserialize_with = "de_string_or_number_list")]
    pub ports: Vec<String>,
    #[serde(default)]
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RoutingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_priority_mode")]
    pub priority_mode: String,
    #[serde(default = "default_true")]
    pub use_default_private: bool,
    #[serde(default = "default_action_proxy")]
    pub default_action: String,
    #[serde(default)]
    pub rules: Vec<RoutingRuleConfig>,
}

fn default_priority_mode() -> String {
    "order".to_string()
}

fn default_action_proxy() -> String {
    "proxy".to_string()
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            priority_mode: default_priority_mode(),
            use_default_private: true,
            default_action: default_action_proxy(),
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

fn default_ipv6_mode() -> String {
    "proxy".to_string()
}

fn default_udp_mode() -> String {
    "auto".to_string()
}

fn default_udp_fallback() -> String {
    "block".to_string()
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
            ipv6_mode: default_ipv6_mode(),
            udp_mode: default_udp_mode(),
            udp_fallback: default_udp_fallback(),
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
    #[serde(skip)]
    pub compiled_routes: CompiledRoutes,
    #[serde(skip)]
    pub load_warnings: Vec<String>,
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
            compiled_routes: CompiledRoutes::default(),
            load_warnings: Vec::new(),
        }
    }
}

impl AppConfig {
    pub fn finalize(&mut self) {
        if self.child_injection_mode.trim().is_empty() {
            self.child_injection_mode = default_child_injection_mode();
        }
        let mode = self.child_injection_mode.to_ascii_lowercase();
        if mode != "filtered" && mode != "inherit" {
            self.load_warnings.push(format!(
                "child_injection_mode 无效 ({})，已回退为 filtered",
                self.child_injection_mode
            ));
            self.child_injection_mode = default_child_injection_mode();
        } else {
            self.child_injection_mode = mode;
        }

        let specs: Vec<RuleSpec> = self
            .proxy_rules
            .routing
            .rules
            .iter()
            .map(|rule| RuleSpec {
                name: rule.name.clone(),
                enabled: rule.enabled,
                action: rule.action.clone(),
                priority: rule.priority,
                ip_cidrs_v4: rule.ip_cidrs_v4.clone(),
                ip_cidrs_v6: rule.ip_cidrs_v6.clone(),
                domains: rule.domains.clone(),
                ports: rule.ports.clone(),
                protocols: rule.protocols.clone(),
            })
            .collect();
        let compiled = route::compile_routes(
            self.proxy_rules.routing.enabled,
            &self.proxy_rules.routing.priority_mode,
            &self.proxy_rules.routing.default_action,
            self.proxy_rules.routing.use_default_private,
            &specs,
        );
        self.load_warnings.extend(compiled.warnings.clone());
        self.compiled_routes = compiled;
    }

    pub fn from_json_str(text: &str) -> Result<Self, serde_json::Error> {
        let mut cfg: Self = serde_json::from_str(text)?;
        cfg.finalize();
        Ok(cfg)
    }

    pub fn udp_action(&self) -> route::UdpAction {
        route::resolve_udp_action(
            &self.proxy_rules.udp_mode,
            &self.proxy.r#type,
            &self.proxy_rules.udp_fallback,
        )
    }

    pub fn port_allowed(&self, port: u16) -> bool {
        self.proxy_rules.allowed_ports.is_empty() || self.proxy_rules.allowed_ports.contains(&port)
    }
}

impl AppConfig {
    pub fn load() -> (Self, Option<PathBuf>) {
        let candidates = [
            std::env::var("ANTIGRAVITY_PROXY_CONFIG")
                .ok()
                .map(PathBuf::from),
            Some(PathBuf::from("config.json")),
            crate::ffi::get_so_directory().map(|d| d.join("config.json")),
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".config/antigravity-proxy/config.json")),
            Some(PathBuf::from("/etc/antigravity-proxy/config.json")),
        ];

        for opt in candidates.into_iter().flatten() {
            if !opt.is_file() {
                continue;
            }
            match fs::read_to_string(&opt) {
                Ok(content) => match Self::from_json_str(&content) {
                    Ok(cfg) => return (cfg, Some(opt)),
                    Err(err) => {
                        eprintln!(
                            "[Antigravity-Proxy] 配置文件解析失败，使用内置默认值: {opt:?}: {err}"
                        );
                        let mut cfg = AppConfig::default();
                        cfg.finalize();
                        cfg.load_warnings
                            .push(format!("配置文件解析失败 ({opt:?}): {err}"));
                        return (cfg, Some(opt));
                    }
                },
                Err(err) => {
                    eprintln!("[Antigravity-Proxy] 无法读取配置文件 {opt:?}: {err}");
                }
            }
        }

        let mut cfg = AppConfig::default();
        cfg.finalize();
        (cfg, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_routing_rules_and_udp_defaults() {
        let cfg = AppConfig::from_json_str(
            r#"{
                "proxy_rules": {
                    "ipv6_mode": "block",
                    "udp_mode": "auto",
                    "routing": {
                        "rules": [{
                            "name": "bypass",
                            "action": "direct",
                            "domains": ["direct.example"],
                            "ports": [443, "80"]
                        }]
                    }
                }
            }"#,
        )
        .unwrap();
        assert_eq!(cfg.proxy_rules.ipv6_mode, "block");
        assert_eq!(cfg.udp_action(), crate::route::UdpAction::Proxy);
        let hit = cfg
            .compiled_routes
            .decide(crate::route::Query {
                host: "direct.example",
                ip_v4: None,
                ip_v6: None,
                port: 443,
                protocol: "tcp",
            })
            .unwrap();
        assert_eq!(hit.action, crate::route::Action::Direct);
        assert_eq!(hit.rule.as_deref(), Some("bypass"));
    }
}
