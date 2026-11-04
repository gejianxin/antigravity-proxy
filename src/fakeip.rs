use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

struct MapEntry {
    key: String,
    original: String,
}

pub struct FakeIpPool {
    base: u32,
    mask: u32,
    network_size: u32,
    cursor: u32,
    domain_to_ip: HashMap<String, u32>,
    ip_to_domain: HashMap<u32, MapEntry>,
}

impl FakeIpPool {
    pub fn new(cidr: &str) -> Self {
        let (base, mask, network_size) =
            parse_cidr(cidr).unwrap_or_else(|| parse_cidr("198.18.0.0/15").unwrap());
        Self {
            base,
            mask,
            network_size,
            cursor: 1,
            domain_to_ip: HashMap::new(),
            ip_to_domain: HashMap::new(),
        }
    }

    pub fn network_size(&self) -> u32 {
        self.network_size
    }

    pub fn is_fake_ip(&self, ip_host_order: u32) -> bool {
        self.network_size > 2 && (ip_host_order & self.mask) == self.base
    }

    /// Allocate a stable virtual address for `domain`.
    ///
    /// The pool is a ring over the CIDR, skipping the network and broadcast
    /// addresses. When an address is reused, the previous domain mapping is
    /// removed in both directions so a wrapped pool cannot alias two names.
    pub fn get_or_create(&mut self, domain: &str) -> u32 {
        let original = domain.trim().trim_end_matches('.').to_string();
        if original.is_empty() {
            return 0;
        }
        let key = original.to_ascii_lowercase();
        if let Some(&ip) = self.domain_to_ip.get(&key) {
            return ip;
        }
        if self.network_size <= 2 {
            return 0;
        }

        let offset = self.cursor;
        self.cursor = self.cursor.saturating_add(1);
        if self.cursor >= self.network_size - 1 {
            self.cursor = 1;
        }
        let ip = self.base | offset;

        if let Some(old) = self.ip_to_domain.remove(&ip) {
            if self.domain_to_ip.get(&old.key).copied() == Some(ip) {
                self.domain_to_ip.remove(&old.key);
            }
        }

        self.domain_to_ip.insert(key.clone(), ip);
        self.ip_to_domain.insert(ip, MapEntry { key, original });
        ip
    }

    pub fn get_domain(&self, ip_host_order: u32) -> Option<String> {
        self.ip_to_domain
            .get(&ip_host_order)
            .map(|e| e.original.clone())
    }
}

fn parse_cidr(cidr: &str) -> Option<(u32, u32, u32)> {
    let (ip_str, bits_str) = cidr.trim().split_once('/')?;
    let bits: u32 = bits_str.trim().parse().ok()?;
    if bits == 0 || bits > 32 {
        return None;
    }
    let addr = ip_str.trim().parse::<Ipv4Addr>().ok()?;
    let mask = u32::MAX << (32 - bits);
    let base = u32::from(addr) & mask;
    let network_size = 1u32 << (32 - bits);
    Some((base, mask, network_size))
}

static POOL: RwLock<Option<FakeIpPool>> = RwLock::new(None);

fn read_pool() -> RwLockReadGuard<'static, Option<FakeIpPool>> {
    POOL.read().unwrap_or_else(|e| e.into_inner())
}

fn write_pool() -> RwLockWriteGuard<'static, Option<FakeIpPool>> {
    POOL.write().unwrap_or_else(|e| e.into_inner())
}

pub fn init(cidr: &str) {
    let pool = FakeIpPool::new(cidr);
    *write_pool() = Some(pool);
}

pub fn is_fakeip(ip_host_order: u32) -> bool {
    read_pool()
        .as_ref()
        .map(|p| p.is_fake_ip(ip_host_order))
        .unwrap_or(false)
}

pub fn get_or_create(domain: &str) -> u32 {
    let mut guard = write_pool();
    match guard.as_mut() {
        Some(pool) => pool.get_or_create(domain),
        None => 0,
    }
}

pub fn get_domain(ip_host_order: u32) -> Option<String> {
    read_pool()
        .as_ref()
        .and_then(|p| p.get_domain(ip_host_order))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeats_return_the_same_address() {
        let mut pool = FakeIpPool::new("198.18.0.0/15");
        let a = pool.get_or_create("Example.COM");
        let b = pool.get_or_create("example.com.");
        assert_eq!(a, b);
        assert_eq!(pool.get_domain(a).as_deref(), Some("Example.COM"));
        assert!(pool.is_fake_ip(a));
        assert!(!pool.is_fake_ip(u32::from(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn wrap_evicts_the_previous_domain() {
        let mut pool = FakeIpPool::new("198.18.0.0/30");
        assert_eq!(pool.network_size(), 4);
        let a = pool.get_or_create("a.example");
        let b = pool.get_or_create("b.example");
        assert_ne!(a, b);
        let c = pool.get_or_create("c.example");
        assert_eq!(c, a);
        assert_eq!(pool.get_domain(a).as_deref(), Some("c.example"));
        assert!(pool.get_domain(b).is_some());
        let a_again = pool.get_or_create("a.example");
        assert_ne!(a_again, c);
        assert_eq!(pool.get_domain(a_again).as_deref(), Some("a.example"));
        assert_ne!(pool.get_domain(c).as_deref(), Some("a.example"));
    }

    #[test]
    fn tiny_prefix_refuses_to_allocate() {
        let mut pool = FakeIpPool::new("198.18.0.1/32");
        assert_eq!(pool.get_or_create("a.example"), 0);
        let mut pool = FakeIpPool::new("not-a-cidr");
        let ip = pool.get_or_create("a.example");
        assert!(pool.is_fake_ip(ip));
        assert_eq!(Ipv4Addr::from(ip), Ipv4Addr::new(198, 18, 0, 1));
    }
}
