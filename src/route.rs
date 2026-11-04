//! Routing and UDP policy.
//!
//! Decision order follows the upstream Windows proxy
//! (yuaotian/antigravity-proxy): a matching `direct` rule wins immediately,
//! the default action is used when nothing matches, and port / DNS filters are
//! applied by the caller after a proxy decision.

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Direct,
    Proxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpAction {
    Block,
    Direct,
    Proxy,
}

#[derive(Debug, Clone)]
pub struct RuleSpec {
    pub name: String,
    pub enabled: bool,
    pub action: String,
    pub priority: i32,
    pub ip_cidrs_v4: Vec<String>,
    pub ip_cidrs_v6: Vec<String>,
    pub domains: Vec<String>,
    pub ports: Vec<String>,
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone)]
struct Cidr4 {
    network: u32,
    mask: u32,
}

#[derive(Debug, Clone)]
struct Cidr6 {
    network: [u8; 16],
    prefix: u8,
}

#[derive(Debug, Clone)]
struct PortRange {
    start: u16,
    end: u16,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    name: String,
    enabled: bool,
    action: Action,
    v4: Vec<Cidr4>,
    v6: Vec<Cidr6>,
    domains: Vec<String>,
    ports: Vec<PortRange>,
    protocols: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CompiledRoutes {
    pub enabled: bool,
    pub default_action: Action,
    rules: Vec<CompiledRule>,
    order: Vec<usize>,
    pub warnings: Vec<String>,
}

impl Default for CompiledRoutes {
    fn default() -> Self {
        Self {
            enabled: true,
            default_action: Action::Proxy,
            rules: Vec::new(),
            order: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Query<'a> {
    pub host: &'a str,
    pub ip_v4: Option<u32>,
    pub ip_v6: Option<[u8; 16]>,
    pub port: u16,
    pub protocol: &'a str,
}

/// Owned match result so callers can log the rule name after the borrow ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedMatch {
    pub action: Action,
    pub rule: Option<String>,
}

impl CompiledRoutes {
    pub fn decide(&self, query: Query<'_>) -> Option<OwnedMatch> {
        if !self.enabled {
            return None;
        }

        let host = normalize_host(query.host);
        let (parsed_v4, parsed_v6) = parse_host_ip(&host);
        let ip_v4 = query.ip_v4.or(parsed_v4);
        let ip_v6 = query.ip_v6.or(parsed_v6);
        let proto = query.protocol.to_ascii_lowercase();

        for &idx in &self.order {
            let rule = &self.rules[idx];
            if !rule.enabled {
                continue;
            }
            if !rule.protocols.is_empty() && !rule.protocols.iter().any(|p| p == &proto) {
                continue;
            }
            if !port_matches(query.port, &rule.ports) {
                continue;
            }

            let domain_hit = !rule.domains.is_empty()
                && !host.is_empty()
                && rule
                    .domains
                    .iter()
                    .any(|pattern| domain_match(pattern, &host));
            let v4_hit = ip_v4
                .map(|ip| rule.v4.iter().any(|c| (ip & c.mask) == c.network))
                .unwrap_or(false);
            let v6_hit = ip_v6
                .map(|ip| rule.v6.iter().any(|c| cidr6_match(&ip, c)))
                .unwrap_or(false);

            if domain_hit || v4_hit || v6_hit {
                return Some(OwnedMatch {
                    action: rule.action,
                    rule: Some(rule.name.clone()),
                });
            }
        }

        Some(OwnedMatch {
            action: self.default_action,
            rule: None,
        })
    }
}

pub fn compile_routes(
    enabled: bool,
    priority_mode: &str,
    default_action: &str,
    use_default_private: bool,
    rules: &[RuleSpec],
) -> CompiledRoutes {
    let mut warnings = Vec::new();
    let default_action = parse_action(default_action).unwrap_or_else(|| {
        warnings.push(format!(
            "routing.default_action 无效 ({default_action})，已回退为 proxy"
        ));
        Action::Proxy
    });

    let mut compiled = Vec::new();
    if enabled && use_default_private {
        compiled.push(CompiledRule {
            name: "default-private".to_string(),
            enabled: true,
            action: Action::Direct,
            v4: vec![
                must_cidr4("10.0.0.0/8"),
                must_cidr4("172.16.0.0/12"),
                must_cidr4("192.168.0.0/16"),
                must_cidr4("127.0.0.0/8"),
                must_cidr4("169.254.0.0/16"),
            ],
            v6: vec![
                must_cidr6("fc00::/7"),
                must_cidr6("fe80::/10"),
                must_cidr6("::1/128"),
            ],
            domains: Vec::new(),
            ports: Vec::new(),
            protocols: vec!["tcp".to_string(), "udp".to_string()],
        });
    }

    for spec in rules {
        let mut rule = CompiledRule {
            name: if spec.name.trim().is_empty() {
                "(unnamed)".to_string()
            } else {
                spec.name.trim().to_string()
            },
            enabled: spec.enabled,
            action: parse_action(&spec.action).unwrap_or(default_action),
            v4: Vec::new(),
            v6: Vec::new(),
            domains: Vec::new(),
            ports: Vec::new(),
            protocols: Vec::new(),
        };
        if parse_action(&spec.action).is_none() && !spec.action.trim().is_empty() {
            warnings.push(format!(
                "路由规则 action 无效 ({})，rule={}，已使用默认动作",
                spec.action, rule.name
            ));
        }
        for cidr in &spec.ip_cidrs_v4 {
            match parse_cidr4(cidr) {
                Some(c) => rule.v4.push(c),
                None => warnings.push(format!(
                    "路由规则 IPv4 CIDR 无效 ({cidr})，rule={}",
                    rule.name
                )),
            }
        }
        for cidr in &spec.ip_cidrs_v6 {
            match parse_cidr6(cidr) {
                Some(c) => rule.v6.push(c),
                None => warnings.push(format!(
                    "路由规则 IPv6 CIDR 无效 ({cidr})，rule={}",
                    rule.name
                )),
            }
        }
        for domain in &spec.domains {
            let norm = normalize_host(domain);
            if !norm.is_empty() {
                rule.domains.push(norm);
            }
        }
        for token in &spec.ports {
            match parse_port_range(token) {
                Some(range) => rule.ports.push(range),
                None => warnings.push(format!("路由规则端口无效 ({token})，rule={}", rule.name)),
            }
        }
        for proto in &spec.protocols {
            let p = proto.trim().to_ascii_lowercase();
            if !p.is_empty() {
                rule.protocols.push(p);
            }
        }
        compiled.push(rule);
    }

    let mut order: Vec<usize> = (0..compiled.len()).collect();
    if priority_mode.eq_ignore_ascii_case("number") {
        order.sort_by(|&a, &b| {
            let pa = rules_priority(rules, &compiled, a);
            let pb = rules_priority(rules, &compiled, b);
            pb.cmp(&pa)
        });
    } else if !priority_mode.trim().is_empty() && !priority_mode.eq_ignore_ascii_case("order") {
        warnings.push(format!(
            "routing.priority_mode 无效 ({priority_mode})，已回退为 order"
        ));
    }

    CompiledRoutes {
        enabled,
        default_action,
        rules: compiled,
        order,
        warnings,
    }
}

fn rules_priority(specs: &[RuleSpec], compiled: &[CompiledRule], idx: usize) -> i32 {
    let name = &compiled[idx].name;
    if name == "default-private" {
        return 0;
    }
    specs
        .iter()
        .find(|s| {
            let n = if s.name.trim().is_empty() {
                "(unnamed)"
            } else {
                s.name.trim()
            };
            n == name
        })
        .map(|s| s.priority)
        .unwrap_or(0)
}

pub fn resolve_udp_action(mode: &str, proxy_type: &str, fallback: &str) -> UdpAction {
    if mode.eq_ignore_ascii_case("direct") {
        return UdpAction::Direct;
    }
    if mode.eq_ignore_ascii_case("proxy") {
        return UdpAction::Proxy;
    }
    if mode.eq_ignore_ascii_case("auto") {
        if proxy_type.eq_ignore_ascii_case("socks5") {
            return UdpAction::Proxy;
        }
        return if fallback.eq_ignore_ascii_case("direct") {
            UdpAction::Direct
        } else {
            UdpAction::Block
        };
    }
    UdpAction::Block
}

pub fn normalize_host(host: &str) -> String {
    let mut s = host.trim().to_ascii_lowercase();
    while s.ends_with('.') {
        s.pop();
    }
    if s.len() >= 2 && s.starts_with('[') && s.ends_with(']') {
        s = s[1..s.len() - 1].to_string();
    }
    s
}

pub fn is_loopback_host(host: &str) -> bool {
    let host = normalize_host(host);
    if host == "localhost" || host == "localhost.localdomain" {
        return true;
    }
    if let Some(ip) = parse_v4(&host) {
        return (ip >> 24) == 127;
    }
    if let Some(ip) = parse_v6(&host) {
        return is_v6_loopback(&ip);
    }
    false
}

pub fn is_ip_literal(host: &str) -> bool {
    let host = normalize_host(host);
    parse_v4(&host).is_some() || parse_v6(&host).is_some()
}

pub fn is_private_v4(ip: u32) -> bool {
    (ip >> 24) == 10
        || (ip >> 24) == 127
        || (ip & 0xFFF0_0000) == 0xAC10_0000
        || (ip & 0xFFFF_0000) == 0xC0A8_0000
        || (ip & 0xFFFF_0000) == 0xA9FE_0000
}

pub fn is_private_v6(ip: &[u8; 16]) -> bool {
    is_v6_loopback(ip) || (ip[0] & 0xFE) == 0xFC || (ip[0] == 0xFE && (ip[1] & 0xC0) == 0x80)
}

pub fn is_v4_mapped(ip: &[u8; 16]) -> Option<u32> {
    if ip[..10] == [0u8; 10] && ip[10] == 0xFF && ip[11] == 0xFF {
        Some(u32::from_be_bytes([ip[12], ip[13], ip[14], ip[15]]))
    } else {
        None
    }
}

fn is_v6_loopback(ip: &[u8; 16]) -> bool {
    if *ip == Ipv6Addr::LOCALHOST.octets() {
        return true;
    }
    if let Some(v4) = is_v4_mapped(ip) {
        return (v4 >> 24) == 127;
    }
    false
}

fn parse_host_ip(host: &str) -> (Option<u32>, Option<[u8; 16]>) {
    if let Some(v4) = parse_v4(host) {
        return (Some(v4), None);
    }
    if let Some(v6) = parse_v6(host) {
        if let Some(v4) = is_v4_mapped(&v6) {
            return (Some(v4), None);
        }
        return (None, Some(v6));
    }
    (None, None)
}

fn parse_v4(host: &str) -> Option<u32> {
    let ip: Ipv4Addr = host.parse().ok()?;
    Some(u32::from(ip))
}

fn parse_v6(host: &str) -> Option<[u8; 16]> {
    let ip: Ipv6Addr = host.parse().ok()?;
    Some(ip.octets())
}

fn parse_action(action: &str) -> Option<Action> {
    if action.eq_ignore_ascii_case("direct") {
        Some(Action::Direct)
    } else if action.eq_ignore_ascii_case("proxy") || action.trim().is_empty() {
        Some(Action::Proxy)
    } else {
        None
    }
}

fn parse_cidr4(cidr: &str) -> Option<Cidr4> {
    let (ip, bits) = split_cidr(cidr)?;
    if bits > 32 {
        return None;
    }
    let addr = parse_v4(ip)?;
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    Some(Cidr4 {
        network: addr & mask,
        mask,
    })
}

fn parse_cidr6(cidr: &str) -> Option<Cidr6> {
    let (ip, bits) = split_cidr(cidr)?;
    if bits > 128 {
        return None;
    }
    let mut network = parse_v6(ip)?;
    apply_v6_mask(&mut network, bits as u8);
    Some(Cidr6 {
        network,
        prefix: bits as u8,
    })
}

fn must_cidr4(cidr: &str) -> Cidr4 {
    parse_cidr4(cidr).unwrap_or(Cidr4 {
        network: 0,
        mask: 0,
    })
}

fn must_cidr6(cidr: &str) -> Cidr6 {
    parse_cidr6(cidr).unwrap_or(Cidr6 {
        network: [0; 16],
        prefix: 0,
    })
}

fn split_cidr(cidr: &str) -> Option<(&str, u32)> {
    let (ip, bits) = cidr.trim().split_once('/')?;
    let bits: u32 = bits.trim().parse().ok()?;
    Some((ip.trim(), bits))
}

fn apply_v6_mask(addr: &mut [u8; 16], bits: u8) {
    if bits >= 128 {
        return;
    }
    let full = (bits / 8) as usize;
    let rem = bits % 8;
    if rem == 0 {
        for byte in addr.iter_mut().skip(full) {
            *byte = 0;
        }
    } else {
        let mask = 0xFFu8 << (8 - rem);
        addr[full] &= mask;
        for byte in addr.iter_mut().skip(full + 1) {
            *byte = 0;
        }
    }
}

fn cidr6_match(ip: &[u8; 16], rule: &Cidr6) -> bool {
    let bits = rule.prefix;
    let full = (bits / 8) as usize;
    if ip[..full] != rule.network[..full] {
        return false;
    }
    let rem = bits % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - rem);
    (ip[full] & mask) == (rule.network[full] & mask)
}

fn parse_port_range(token: &str) -> Option<PortRange> {
    let t: String = token.chars().filter(|c| !c.is_whitespace()).collect();
    if t.is_empty() {
        return None;
    }
    if let Some((a, b)) = t.split_once('-') {
        let start: u32 = a.parse().ok()?;
        let end: u32 = b.parse().ok()?;
        if start > 65535 || end > 65535 || start > end {
            return None;
        }
        Some(PortRange {
            start: start as u16,
            end: end as u16,
        })
    } else {
        let v: u32 = t.parse().ok()?;
        if v > 65535 {
            return None;
        }
        Some(PortRange {
            start: v as u16,
            end: v as u16,
        })
    }
}

fn port_matches(port: u16, ranges: &[PortRange]) -> bool {
    if ranges.is_empty() {
        return true;
    }
    if port == 0 {
        return false;
    }
    ranges.iter().any(|r| port >= r.start && port <= r.end)
}

fn domain_match(pattern: &str, host: &str) -> bool {
    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    let has_wild = pattern.contains('*') || pattern.contains('?');
    if !has_wild && pattern.starts_with('.') {
        let root = &pattern[1..];
        return host == root || host.ends_with(pattern);
    }
    if !has_wild {
        return host == pattern;
    }
    glob_match(pattern, host)
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let mut pi = 0;
    let mut ti = 0;
    let mut star: Option<usize> = None;
    let mut match_at = 0;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            pi += 1;
            match_at = ti;
        } else if let Some(star_at) = star {
            pi = star_at + 1;
            match_at += 1;
            ti = match_at;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_domain(name: &str, action: &str, domain: &str, priority: i32) -> RuleSpec {
        RuleSpec {
            name: name.into(),
            enabled: true,
            action: action.into(),
            priority,
            ip_cidrs_v4: Vec::new(),
            ip_cidrs_v6: Vec::new(),
            domains: vec![domain.into()],
            ports: Vec::new(),
            protocols: vec!["tcp".into()],
        }
    }

    #[test]
    fn private_v4_is_direct_by_default() {
        let routes = compile_routes(true, "order", "proxy", true, &[]);
        let hit = routes
            .decide(Query {
                host: "192.168.1.9",
                ip_v4: Some(u32::from(Ipv4Addr::new(192, 168, 1, 9))),
                ip_v6: None,
                port: 443,
                protocol: "tcp",
            })
            .unwrap();
        assert_eq!(hit.action, Action::Direct);
        assert_eq!(hit.rule.as_deref(), Some("default-private"));
    }

    #[test]
    fn order_mode_private_rule_beats_later_user_rule() {
        let user = RuleSpec {
            name: "force-proxy-lan".into(),
            enabled: true,
            action: "proxy".into(),
            priority: 100,
            ip_cidrs_v4: vec!["10.0.0.0/8".into()],
            ip_cidrs_v6: Vec::new(),
            domains: Vec::new(),
            ports: Vec::new(),
            protocols: vec!["tcp".into()],
        };
        let routes = compile_routes(true, "order", "proxy", true, &[user]);
        let hit = routes
            .decide(Query {
                host: "10.1.2.3",
                ip_v4: Some(u32::from(Ipv4Addr::new(10, 1, 2, 3))),
                ip_v6: None,
                port: 443,
                protocol: "tcp",
            })
            .unwrap();
        assert_eq!(hit.rule.as_deref(), Some("default-private"));
    }

    #[test]
    fn number_mode_higher_priority_overrides_private() {
        let user = RuleSpec {
            name: "force-proxy-lan".into(),
            enabled: true,
            action: "proxy".into(),
            priority: 10,
            ip_cidrs_v4: vec!["10.0.0.0/8".into()],
            ip_cidrs_v6: Vec::new(),
            domains: Vec::new(),
            ports: Vec::new(),
            protocols: vec!["tcp".into()],
        };
        let routes = compile_routes(true, "number", "proxy", true, &[user]);
        let hit = routes
            .decide(Query {
                host: "10.1.2.3",
                ip_v4: Some(u32::from(Ipv4Addr::new(10, 1, 2, 3))),
                ip_v6: None,
                port: 443,
                protocol: "tcp",
            })
            .unwrap();
        assert_eq!(hit.action, Action::Proxy);
        assert_eq!(hit.rule.as_deref(), Some("force-proxy-lan"));
    }

    #[test]
    fn domain_glob_and_dot_suffix() {
        let routes = compile_routes(
            true,
            "order",
            "proxy",
            false,
            &[
                spec_domain("google", "proxy", "*.googleapis.com", 0),
                spec_domain("ex", "direct", ".example.com", 0),
            ],
        );
        let google = routes
            .decide(Query {
                host: "OAuth2.GoogleAPIs.com.",
                ip_v4: None,
                ip_v6: None,
                port: 443,
                protocol: "tcp",
            })
            .unwrap();
        assert_eq!(google.rule.as_deref(), Some("google"));

        let apex = routes
            .decide(Query {
                host: "example.com",
                ip_v4: None,
                ip_v6: None,
                port: 443,
                protocol: "tcp",
            })
            .unwrap();
        assert_eq!(apex.action, Action::Direct);

        let sub = routes
            .decide(Query {
                host: "a.example.com",
                ip_v4: None,
                ip_v6: None,
                port: 443,
                protocol: "tcp",
            })
            .unwrap();
        assert_eq!(sub.action, Action::Direct);

        let miss = routes
            .decide(Query {
                host: "notexample.com",
                ip_v4: None,
                ip_v6: None,
                port: 443,
                protocol: "tcp",
            })
            .unwrap();
        assert_eq!(miss.action, Action::Proxy);
        assert!(miss.rule.is_none());
    }

    #[test]
    fn protocol_and_port_filters() {
        let rule = RuleSpec {
            name: "dns".into(),
            enabled: true,
            action: "direct".into(),
            priority: 0,
            ip_cidrs_v4: Vec::new(),
            ip_cidrs_v6: Vec::new(),
            domains: vec!["dns.example".into()],
            ports: vec!["53".into(), "853".into()],
            protocols: vec!["udp".into()],
        };
        let routes = compile_routes(true, "order", "proxy", false, &[rule]);
        let tcp = routes
            .decide(Query {
                host: "dns.example",
                ip_v4: None,
                ip_v6: None,
                port: 53,
                protocol: "tcp",
            })
            .unwrap();
        assert!(tcp.rule.is_none());
        let udp = routes
            .decide(Query {
                host: "dns.example",
                ip_v4: None,
                ip_v6: None,
                port: 853,
                protocol: "udp",
            })
            .unwrap();
        assert_eq!(udp.action, Action::Direct);
    }

    #[test]
    fn ula_and_mapped_loopback() {
        assert!(is_private_v6(&parse_v6("fd12::1").unwrap()));
        assert!(is_private_v6(&parse_v6("fe80::1").unwrap()));
        assert!(!is_private_v6(&parse_v6("2001:db8::1").unwrap()));
        assert!(is_loopback_host("::ffff:127.0.0.1"));
        assert!(is_ip_literal("[2001:db8::2]"));
        assert!(!is_ip_literal("oauth2.googleapis.com"));
    }

    #[test]
    fn udp_action_matrix() {
        assert_eq!(
            resolve_udp_action("auto", "socks5", "block"),
            UdpAction::Proxy
        );
        assert_eq!(
            resolve_udp_action("auto", "http", "block"),
            UdpAction::Block
        );
        assert_eq!(
            resolve_udp_action("auto", "http", "direct"),
            UdpAction::Direct
        );
        assert_eq!(
            resolve_udp_action("direct", "socks5", "block"),
            UdpAction::Direct
        );
        assert_eq!(
            resolve_udp_action("nope", "socks5", "direct"),
            UdpAction::Block
        );
    }

    #[test]
    fn disabled_routing_returns_none() {
        let routes = compile_routes(false, "order", "direct", true, &[]);
        assert!(routes
            .decide(Query {
                host: "10.0.0.1",
                ip_v4: Some(u32::from(Ipv4Addr::new(10, 0, 0, 1))),
                ip_v6: None,
                port: 80,
                protocol: "tcp",
            })
            .is_none());
    }
}
