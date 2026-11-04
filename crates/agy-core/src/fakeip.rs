use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::RwLock;

/// Virtual-IP pool with ring eviction.
///
/// The first usable address is `network + 2` (for `198.18.0.0/15` that is
/// `198.18.0.2`), matching the existing Linux build. Offset 0 and the last
/// address of the prefix are reserved. When the cursor wraps, the recycled
/// address is detached from its previous domain before being reused.
#[derive(Debug)]
pub struct FakeIpPool {
    network: u32,
    mask: u32,
    capacity: u32,
    cursor: u32,
    domain_to_ip: HashMap<String, u32>,
    ip_to_domain: HashMap<u32, String>,
}

impl FakeIpPool {
    pub fn new(cidr: &str) -> Self {
        parse_pool(cidr).unwrap_or_else(|| parse_pool("198.18.0.0/15").expect("builtin cidr"))
    }

    pub fn is_fake_ip(&self, ip_host_order: u32) -> bool {
        (ip_host_order & self.mask) == self.network
    }

    pub fn get_or_create(&mut self, domain: &str) -> u32 {
        let key = domain.to_ascii_lowercase();
        if key.is_empty() {
            return 0;
        }
        if let Some(&ip) = self.domain_to_ip.get(&key) {
            return ip;
        }
        if self.capacity <= 3 {
            return 0;
        }

        let offset = self.cursor;
        self.cursor = self.cursor.saturating_add(1);
        if self.cursor >= self.capacity.saturating_sub(1) {
            self.cursor = 2;
        }

        let ip = self.network.wrapping_add(offset);
        if let Some(old) = self.ip_to_domain.insert(ip, domain.to_string()) {
            self.domain_to_ip.remove(&old.to_ascii_lowercase());
        }
        self.domain_to_ip.insert(key, ip);
        ip
    }

    pub fn get_domain(&self, ip_host_order: u32) -> Option<String> {
        self.ip_to_domain.get(&ip_host_order).cloned()
    }
}

fn parse_pool(cidr: &str) -> Option<FakeIpPool> {
    let (ip_str, prefix_str) = cidr.split_once('/')?;
    let base = ip_str.trim().parse::<Ipv4Addr>().ok()?;
    let prefix: u32 = prefix_str.trim().parse().ok()?;
    if prefix == 0 || prefix > 30 {
        return None;
    }
    let mask = (!0u32).checked_shl(32 - prefix)?;
    let network = u32::from(base) & mask;
    let capacity = 1u32 << (32 - prefix);
    Some(FakeIpPool {
        network,
        mask,
        capacity,
        cursor: 2,
        domain_to_ip: HashMap::new(),
        ip_to_domain: HashMap::new(),
    })
}

pub fn ipv4_from_mapped_v6(addr: &[u8; 16]) -> Option<u32> {
    if addr[0..10].iter().all(|b| *b == 0) && addr[10] == 0xff && addr[11] == 0xff {
        Some(u32::from_be_bytes([addr[12], addr[13], addr[14], addr[15]]))
    } else {
        None
    }
}

pub fn is_ipv4_loopback(ip: u32) -> bool {
    (ip >> 24) == 127
}

pub fn is_private_ipv4(ip: u32) -> bool {
    (ip & 0xFF00_0000) == 0x0A00_0000
        || (ip & 0xFFF0_0000) == 0xAC10_0000
        || (ip & 0xFFFF_0000) == 0xC0A8_0000
        || (ip & 0xFFFF_0000) == 0xA9FE_0000
}

static POOL: RwLock<Option<FakeIpPool>> = RwLock::new(None);

fn write_pool() -> std::sync::RwLockWriteGuard<'static, Option<FakeIpPool>> {
    POOL.write().unwrap_or_else(|e| e.into_inner())
}

fn read_pool() -> std::sync::RwLockReadGuard<'static, Option<FakeIpPool>> {
    POOL.read().unwrap_or_else(|e| e.into_inner())
}

pub fn init(cidr: &str) {
    *write_pool() = Some(FakeIpPool::new(cidr));
}

pub fn reset_for_tests(cidr: &str) {
    init(cidr);
}

pub fn is_fakeip(ip_host_order: u32) -> bool {
    read_pool()
        .as_ref()
        .map(|p| p.is_fake_ip(ip_host_order))
        .unwrap_or(false)
}

pub fn get_or_create(domain: &str) -> u32 {
    match write_pool().as_mut() {
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
    fn first_address_matches_linux_smoke() {
        let mut pool = FakeIpPool::new("198.18.0.0/15");
        let ip = pool.get_or_create("oauth2.googleapis.com");
        assert_eq!(ip, u32::from(Ipv4Addr::new(198, 18, 0, 2)));
        assert_eq!(pool.get_or_create("OAuth2.GoogleAPIs.com"), ip);
        assert_eq!(
            pool.get_domain(ip).as_deref(),
            Some("oauth2.googleapis.com")
        );
        assert!(pool.is_fake_ip(ip));
        assert!(!pool.is_fake_ip(u32::from(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn ring_evicts_oldest_mapping() {
        // /28 has 16 addresses. Cursor starts at 2 and wraps before the last.
        let mut pool = FakeIpPool::new("198.18.0.0/28");
        let mut issued = Vec::new();
        for i in 0..13 {
            let domain = format!("h{i}.example");
            issued.push(pool.get_or_create(&domain));
        }
        assert_eq!(issued[0], u32::from(Ipv4Addr::new(198, 18, 0, 2)));
        let recycled = pool.get_or_create("fresh.example");
        assert_eq!(recycled, issued[0]);
        assert!(pool.get_domain(issued[0]).unwrap().starts_with("fresh"));
        assert!(
            pool.get_or_create("h0.example") != issued[0]
                || pool.get_domain(issued[0]).unwrap() == "h0.example"
        );
        assert_eq!(pool.get_domain(recycled).as_deref(), Some("fresh.example"));
        // The evicted name must not keep the recycled address.
        let again = pool.get_or_create("h0.example");
        assert_ne!(again, recycled);
        assert_eq!(pool.get_domain(again).as_deref(), Some("h0.example"));
    }

    #[test]
    fn mapped_v6_extracts_v4() {
        let mut addr = [0u8; 16];
        addr[10] = 0xff;
        addr[11] = 0xff;
        addr[12] = 198;
        addr[13] = 18;
        addr[14] = 0;
        addr[15] = 2;
        assert_eq!(
            ipv4_from_mapped_v6(&addr),
            Some(u32::from(Ipv4Addr::new(198, 18, 0, 2)))
        );
    }
}
