use std::net::{Ipv4Addr, Ipv6Addr};

use crate::config::{AppConfig, RouteRule};
use crate::fakeip::{self, is_ipv4_loopback, is_private_ipv4};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Direct,
    Proxy,
    Block,
}

/// Platform knobs that keep the Linux preload behavior stable.
#[derive(Debug, Clone, Copy)]
pub struct DecideOpts {
    /// Existing Linux builds proxy a FakeIP even when the port is outside
    /// `allowed_ports`. The Windows runtime applies the whitelist.
    pub fake_ip_bypasses_port_filter: bool,
    /// Existing Linux builds leave datagrams alone unless UDP mode is explicit.
    /// `auto` therefore stays direct on Linux and means "proxy if SOCKS5" on Windows.
    pub udp_auto_is_direct: bool,
}

impl DecideOpts {
    pub const LINUX: Self = Self {
        fake_ip_bypasses_port_filter: true,
        udp_auto_is_direct: true,
    };
    pub const WINDOWS: Self = Self {
        fake_ip_bypasses_port_filter: false,
        udp_auto_is_direct: false,
    };
}

#[derive(Debug, Clone)]
pub struct Endpoint<'a> {
    pub domain: Option<&'a str>,
    pub ipv4: Option<u32>,
    pub ipv6: Option<[u8; 16]>,
    pub port: u16,
    pub proto: Proto,
    pub is_fake_ip: bool,
}

impl<'a> Endpoint<'a> {
    pub fn dns(domain: &'a str, port: u16) -> Self {
        Self {
            domain: Some(domain),
            ipv4: None,
            ipv6: None,
            port,
            proto: Proto::Tcp,
            is_fake_ip: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpAction {
    Direct,
    Proxy,
    Block,
}

pub fn effective_udp_action(cfg: &AppConfig, opts: DecideOpts) -> UdpAction {
    let mode = cfg.proxy_rules.udp_mode.to_ascii_lowercase();
    match mode.as_str() {
        "direct" => UdpAction::Direct,
        "block" => UdpAction::Block,
        "proxy" => UdpAction::Proxy,
        _ => {
            if opts.udp_auto_is_direct {
                UdpAction::Direct
            } else if cfg.proxy.is_socks5() {
                UdpAction::Proxy
            } else if cfg.proxy_rules.udp_fallback.eq_ignore_ascii_case("direct") {
                UdpAction::Direct
            } else {
                UdpAction::Block
            }
        }
    }
}

/// Whether `getaddrinfo` should hand out a FakeIP. The port whitelist is applied
/// later, at connect time, so a lookup with no service still receives a mapping.
pub fn should_fake_dns(cfg: &AppConfig, domain: &str) -> bool {
    if !cfg.fake_ip.enabled || domain.is_empty() {
        return false;
    }
    if is_ip_literal(domain) || is_loopback_name(domain) {
        return false;
    }
    let ep = Endpoint::dns(domain, 0);
    if let Some(action) = match_user_rules(cfg, &ep) {
        return action == Action::Proxy;
    }
    if cfg.proxy_rules.routing.enabled {
        let action = cfg.proxy_rules.routing.default_action.as_str();
        if action.eq_ignore_ascii_case("direct")
            || action.eq_ignore_ascii_case("block")
            || action.eq_ignore_ascii_case("reject")
        {
            return false;
        }
    }
    true
}

fn is_loopback_name(domain: &str) -> bool {
    let host = normalize_host(domain);
    host == "localhost" || host == "localhost.localdomain"
}

fn is_ip_literal(domain: &str) -> bool {
    let host = normalize_host(domain);
    host.parse::<Ipv4Addr>().is_ok() || host.parse::<Ipv6Addr>().is_ok()
}

pub fn decide(cfg: &AppConfig, ep: &Endpoint<'_>, opts: DecideOpts) -> Action {
    if is_loopback(ep) {
        return Action::Direct;
    }
    if is_proxy_self(cfg, ep) {
        return Action::Direct;
    }

    if ep.proto == Proto::Udp {
        if ep.port == 53 && cfg.dns_is_direct() {
            return Action::Direct;
        }
        match effective_udp_action(cfg, opts) {
            UdpAction::Direct => return Action::Direct,
            UdpAction::Block => return Action::Block,
            UdpAction::Proxy => {}
        }
    }

    if let Some(action) = pure_ipv6_action(cfg, ep) {
        return action;
    }

    if let Some(action) = match_user_rules(cfg, ep) {
        return finalize_proxy(cfg, ep, opts, action);
    }

    if cfg.proxy_rules.routing.use_default_private && is_builtin_private(ep) {
        return Action::Direct;
    }

    if cfg.proxy_rules.routing.enabled
        && cfg
            .proxy_rules
            .routing
            .default_action
            .eq_ignore_ascii_case("direct")
        && !ep.is_fake_ip
    {
        return Action::Direct;
    }
    if cfg.proxy_rules.routing.enabled
        && (cfg
            .proxy_rules
            .routing
            .default_action
            .eq_ignore_ascii_case("block")
            || cfg
                .proxy_rules
                .routing
                .default_action
                .eq_ignore_ascii_case("reject"))
    {
        return Action::Block;
    }

    finalize_proxy(cfg, ep, opts, Action::Proxy)
}

fn finalize_proxy(cfg: &AppConfig, ep: &Endpoint<'_>, opts: DecideOpts, action: Action) -> Action {
    if action != Action::Proxy {
        return action;
    }
    if ep.proto == Proto::Tcp && ep.port == 53 && cfg.dns_is_direct() && !ep.is_fake_ip {
        return Action::Direct;
    }
    let bypass = opts.fake_ip_bypasses_port_filter && ep.is_fake_ip;
    if ep.proto == Proto::Tcp && !bypass && !cfg.port_allowed(ep.port) {
        return Action::Direct;
    }
    Action::Proxy
}

fn pure_ipv6_action(cfg: &AppConfig, ep: &Endpoint<'_>) -> Option<Action> {
    let addr = ep.ipv6?;
    if fakeip::ipv4_from_mapped_v6(&addr).is_some() {
        return None;
    }
    if ep.ipv4.is_some() {
        return None;
    }
    let mode = cfg.proxy_rules.ipv6_mode.to_ascii_lowercase();
    match mode.as_str() {
        "direct" => Some(Action::Direct),
        "proxy" => None,
        _ => Some(Action::Block),
    }
}

fn is_loopback(ep: &Endpoint<'_>) -> bool {
    if let Some(ip) = ep.ipv4 {
        if is_ipv4_loopback(ip) {
            return true;
        }
    }
    if let Some(addr) = ep.ipv6 {
        if is_ipv6_loopback(&addr) {
            return true;
        }
        if let Some(v4) = fakeip::ipv4_from_mapped_v6(&addr) {
            if is_ipv4_loopback(v4) {
                return true;
            }
        }
    }
    if let Some(domain) = ep.domain {
        let host = normalize_host(domain);
        if host == "localhost" || host == "localhost.localdomain" {
            return true;
        }
    }
    false
}

fn is_ipv6_loopback(addr: &[u8; 16]) -> bool {
    addr[0..15].iter().all(|b| *b == 0) && addr[15] == 1
}

fn is_proxy_self(cfg: &AppConfig, ep: &Endpoint<'_>) -> bool {
    if cfg.proxy.port == 0 || ep.port != cfg.proxy.port {
        return false;
    }
    if let Ok(ip) = cfg.proxy.host.parse::<Ipv4Addr>() {
        let host = u32::from(ip);
        if ep.ipv4 == Some(host) {
            return true;
        }
        if let Some(addr) = ep.ipv6 {
            if fakeip::ipv4_from_mapped_v6(&addr) == Some(host) {
                return true;
            }
        }
    }
    if let Some(domain) = ep.domain {
        if normalize_host(domain) == normalize_host(&cfg.proxy.host) {
            return true;
        }
    }
    false
}

fn is_builtin_private(ep: &Endpoint<'_>) -> bool {
    if ep.is_fake_ip {
        return false;
    }
    if let Some(ip) = ep.ipv4 {
        if is_private_ipv4(ip) || is_ipv4_loopback(ip) {
            return true;
        }
    }
    if let Some(addr) = ep.ipv6 {
        if let Some(v4) = fakeip::ipv4_from_mapped_v6(&addr) {
            return is_private_ipv4(v4) || is_ipv4_loopback(v4);
        }
        if is_ula(&addr) || is_link_local_v6(&addr) || is_ipv6_loopback(&addr) {
            return true;
        }
    }
    false
}

fn is_ula(addr: &[u8; 16]) -> bool {
    (addr[0] & 0xfe) == 0xfc
}

fn is_link_local_v6(addr: &[u8; 16]) -> bool {
    addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80
}

fn match_user_rules(cfg: &AppConfig, ep: &Endpoint<'_>) -> Option<Action> {
    if !cfg.proxy_rules.routing.enabled {
        return None;
    }
    let rules = ordered_rules(cfg);
    for rule in rules {
        if rule_matches(&rule, ep) {
            return Some(action_from_str(&rule.action));
        }
    }
    None
}

fn ordered_rules(cfg: &AppConfig) -> Vec<RouteRule> {
    let mut rules = cfg.proxy_rules.routing.rules.clone();
    if cfg
        .proxy_rules
        .routing
        .priority_mode
        .eq_ignore_ascii_case("number")
    {
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }
    rules
}

fn action_from_str(action: &str) -> Action {
    if action.eq_ignore_ascii_case("direct") {
        Action::Direct
    } else if action.eq_ignore_ascii_case("block") || action.eq_ignore_ascii_case("reject") {
        Action::Block
    } else {
        Action::Proxy
    }
}

fn rule_matches(rule: &RouteRule, ep: &Endpoint<'_>) -> bool {
    if !rule.protocols.is_empty() {
        let want = match ep.proto {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        };
        if !rule.protocols.iter().any(|p| p.eq_ignore_ascii_case(want)) {
            return false;
        }
    }
    if !rule.ports.is_empty() && !rule.ports.contains(&ep.port) {
        return false;
    }
    let domain_ok = rule.domains.is_empty()
        || ep
            .domain
            .map(|d| rule.domains.iter().any(|pat| domain_match(d, pat)))
            .unwrap_or(false);
    if !domain_ok {
        return false;
    }
    let v4_ok = rule.ip_cidrs_v4.is_empty()
        || ep
            .ipv4
            .map(|ip| rule.ip_cidrs_v4.iter().any(|c| cidr_v4_match(ip, c)))
            .unwrap_or(false);
    if !v4_ok {
        return false;
    }
    let v6_ok = rule.ip_cidrs_v6.is_empty()
        || ep
            .ipv6
            .map(|ip| rule.ip_cidrs_v6.iter().any(|c| cidr_v6_match(&ip, c)))
            .unwrap_or(false);
    if !v6_ok {
        return false;
    }
    let has_constraint = !rule.protocols.is_empty()
        || !rule.ports.is_empty()
        || !rule.domains.is_empty()
        || !rule.ip_cidrs_v4.is_empty()
        || !rule.ip_cidrs_v6.is_empty();
    has_constraint
}

pub fn domain_match(host: &str, pattern: &str) -> bool {
    let host = normalize_host(host);
    let pattern = normalize_host(pattern);
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    if let Some(suffix) = pattern.strip_prefix('.') {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    host == pattern
}

fn normalize_host(host: &str) -> String {
    let mut host = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    while host.ends_with('.') {
        host.pop();
    }
    host
}

fn cidr_v4_match(ip: u32, cidr: &str) -> bool {
    let Some((addr, prefix)) = parse_v4_cidr(cidr) else {
        return false;
    };
    if prefix == 0 {
        return true;
    }
    let mask = (!0u32).checked_shl(32 - prefix).unwrap_or(0);
    (ip & mask) == (addr & mask)
}

fn parse_v4_cidr(cidr: &str) -> Option<(u32, u32)> {
    let (ip, prefix) = cidr.split_once('/')?;
    let addr = ip.trim().parse::<Ipv4Addr>().ok()?;
    let prefix: u32 = prefix.trim().parse().ok()?;
    if prefix > 32 {
        return None;
    }
    Some((u32::from(addr), prefix))
}

fn cidr_v6_match(ip: &[u8; 16], cidr: &str) -> bool {
    let Some((net, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(net) = net.trim().parse::<Ipv6Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix.trim().parse::<u32>() else {
        return false;
    };
    if prefix > 128 {
        return false;
    }
    let ip = u128::from_be_bytes(*ip);
    let net = u128::from(net);
    if prefix == 0 {
        return true;
    }
    let mask = (!0u128).checked_shl(128 - prefix).unwrap_or(0);
    (ip & mask) == (net & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyRulesConfig, RouteRule, RoutingConfig};

    fn cfg() -> AppConfig {
        AppConfig::default()
    }

    fn ep_v4(ip: Ipv4Addr, port: u16) -> Endpoint<'static> {
        Endpoint {
            domain: None,
            ipv4: Some(u32::from(ip)),
            ipv6: None,
            port,
            proto: Proto::Tcp,
            is_fake_ip: false,
        }
    }

    #[test]
    fn linux_defaults_match_existing_connect_policy() {
        let cfg = cfg();
        let fake = Endpoint {
            domain: Some("oauth2.googleapis.com"),
            ipv4: Some(u32::from(Ipv4Addr::new(198, 18, 0, 2))),
            ipv6: None,
            port: 22,
            proto: Proto::Tcp,
            is_fake_ip: true,
        };
        assert_eq!(decide(&cfg, &fake, DecideOpts::LINUX), Action::Proxy);
        assert_eq!(
            decide(&cfg, &fake, DecideOpts::WINDOWS),
            Action::Direct,
            "windows applies the port whitelist to fake-ip flows"
        );
        assert_eq!(
            decide(
                &cfg,
                &ep_v4(Ipv4Addr::new(1, 2, 3, 4), 443),
                DecideOpts::LINUX
            ),
            Action::Proxy
        );
        assert_eq!(
            decide(
                &cfg,
                &ep_v4(Ipv4Addr::new(1, 2, 3, 4), 22),
                DecideOpts::LINUX
            ),
            Action::Direct
        );
        assert_eq!(
            decide(
                &cfg,
                &ep_v4(Ipv4Addr::new(10, 1, 2, 3), 443),
                DecideOpts::LINUX
            ),
            Action::Direct
        );
        assert_eq!(
            decide(
                &cfg,
                &ep_v4(Ipv4Addr::new(127, 0, 0, 1), 443),
                DecideOpts::LINUX
            ),
            Action::Direct
        );
    }

    #[test]
    fn ipv6_mode_and_udp_policy() {
        let mut cfg = cfg();
        let v6 = Endpoint {
            domain: None,
            ipv4: None,
            ipv6: Some(Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 0x8888).octets()),
            port: 443,
            proto: Proto::Tcp,
            is_fake_ip: false,
        };
        assert_eq!(decide(&cfg, &v6, DecideOpts::LINUX), Action::Proxy);
        cfg.proxy_rules.ipv6_mode = "block".into();
        assert_eq!(decide(&cfg, &v6, DecideOpts::LINUX), Action::Block);
        cfg.proxy_rules.ipv6_mode = "direct".into();
        assert_eq!(decide(&cfg, &v6, DecideOpts::LINUX), Action::Direct);

        cfg.proxy_rules.ipv6_mode = "proxy".into();
        let udp = Endpoint {
            proto: Proto::Udp,
            ..ep_v4(Ipv4Addr::new(1, 2, 3, 4), 443)
        };
        assert_eq!(
            effective_udp_action(&cfg, DecideOpts::LINUX),
            UdpAction::Direct
        );
        assert_eq!(decide(&cfg, &udp, DecideOpts::LINUX), Action::Direct);
        assert_eq!(
            effective_udp_action(&cfg, DecideOpts::WINDOWS),
            UdpAction::Proxy
        );
        assert_eq!(decide(&cfg, &udp, DecideOpts::WINDOWS), Action::Proxy);
        cfg.proxy.r#type = "http".into();
        assert_eq!(
            effective_udp_action(&cfg, DecideOpts::WINDOWS),
            UdpAction::Block
        );
        cfg.proxy_rules.udp_mode = "block".into();
        let dns = Endpoint {
            proto: Proto::Udp,
            port: 53,
            ..ep_v4(Ipv4Addr::new(8, 8, 8, 8), 53)
        };
        assert_eq!(decide(&cfg, &dns, DecideOpts::WINDOWS), Action::Direct);
    }

    #[test]
    fn domain_and_priority_rules() {
        let mut cfg = cfg();
        cfg.proxy_rules.routing.rules = vec![
            RouteRule {
                name: "corp".into(),
                action: "direct".into(),
                domains: vec!["*.corp.example.com".into(), ".local".into()],
                protocols: vec!["tcp".into()],
                ..RouteRule::default()
            },
            RouteRule {
                name: "lan".into(),
                action: "direct".into(),
                ip_cidrs_v4: vec!["10.8.0.0/16".into()],
                ..RouteRule::default()
            },
        ];
        let corp = Endpoint {
            domain: Some("a.corp.example.com"),
            ..ep_v4(Ipv4Addr::new(1, 2, 3, 4), 443)
        };
        assert_eq!(decide(&cfg, &corp, DecideOpts::WINDOWS), Action::Direct);
        assert!(domain_match("printer.local", ".local"));
        assert_eq!(
            decide(
                &cfg,
                &ep_v4(Ipv4Addr::new(10, 8, 1, 9), 443),
                DecideOpts::WINDOWS
            ),
            Action::Direct
        );

        cfg.proxy_rules.routing.priority_mode = "number".into();
        cfg.proxy_rules.routing.rules = vec![
            RouteRule {
                name: "low".into(),
                action: "direct".into(),
                priority: 1,
                domains: vec!["example.com".into()],
                ..RouteRule::default()
            },
            RouteRule {
                name: "high".into(),
                action: "proxy".into(),
                priority: 10,
                domains: vec!["example.com".into()],
                ..RouteRule::default()
            },
        ];
        let host = Endpoint {
            domain: Some("example.com"),
            ..ep_v4(Ipv4Addr::new(1, 2, 3, 4), 443)
        };
        assert_eq!(decide(&cfg, &host, DecideOpts::WINDOWS), Action::Proxy);
    }

    #[test]
    fn dns_fakeip_ignores_port_whitelist() {
        let cfg = cfg();
        assert!(should_fake_dns(&cfg, "oauth2.googleapis.com"));
        assert!(!should_fake_dns(&cfg, "localhost"));
        assert!(!should_fake_dns(&cfg, "127.0.0.1"));
        assert!(!should_fake_dns(&cfg, "2001:db8::1"));
        let mut direct = cfg.clone();
        direct.proxy_rules.routing.default_action = "direct".into();
        assert!(!should_fake_dns(&direct, "oauth2.googleapis.com"));
    }

    #[test]
    fn parses_shipped_linux_config_shape() {
        let raw = include_str!("../../../config.json");
        let cfg = AppConfig::parse_str(raw).expect("config.json");
        assert!(cfg.fake_ip.enabled);
        assert_eq!(cfg.proxy.port, 7898);
        assert_eq!(cfg.proxy_rules.ipv6_mode, "proxy");
        assert_eq!(cfg.proxy_rules.udp_mode, "auto");
        assert!(cfg.diagnostics.agent_ip_probe == false);
        let _ = ProxyRulesConfig::default();
        let _ = RoutingConfig::default();
    }
}
