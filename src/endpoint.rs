use std::net::{Ipv4Addr, Ipv6Addr};

use crate::fakeip;
use crate::route;

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub ip_v4: Option<u32>,
    pub ip_v6: Option<[u8; 16]>,
    pub is_fake: bool,
    pub fake_missing: bool,
}

impl Endpoint {
    pub fn is_loopback(&self) -> bool {
        if route::is_loopback_host(&self.host) {
            return true;
        }
        if self.ip_v4.map(route::is_private_v4).unwrap_or(false)
            && self.ip_v4.unwrap_or(0) >> 24 == 127
        {
            return true;
        }
        self.ip_v6
            .map(|ip| route::is_private_v6(&ip) && ip == Ipv6Addr::LOCALHOST.octets())
            .unwrap_or(false)
    }

    pub fn is_lan(&self) -> bool {
        if let Some(ip) = self.ip_v4 {
            return route::is_private_v4(ip);
        }
        if let Some(ip) = self.ip_v6 {
            return route::is_private_v6(&ip);
        }
        false
    }
}

pub unsafe fn from_sockaddr(addr: *const libc::sockaddr) -> Option<Endpoint> {
    if addr.is_null() {
        return None;
    }
    let family = (*addr).sa_family as libc::c_int;
    if family == libc::AF_INET {
        let sin = &*(addr as *const libc::sockaddr_in);
        let ip = u32::from_be(sin.sin_addr.s_addr);
        let port = u16::from_be(sin.sin_port);
        return Some(from_v4(ip, port));
    }
    if family == libc::AF_INET6 {
        let sin6 = &*(addr as *const libc::sockaddr_in6);
        let octets = sin6.sin6_addr.s6_addr;
        let port = u16::from_be(sin6.sin6_port);
        if let Some(v4) = route::is_v4_mapped(&octets) {
            return Some(from_v4(v4, port));
        }
        let host = Ipv6Addr::from(octets).to_string();
        return Some(Endpoint {
            host,
            port,
            ip_v4: None,
            ip_v6: Some(octets),
            is_fake: false,
            fake_missing: false,
        });
    }
    None
}

fn from_v4(ip: u32, port: u16) -> Endpoint {
    if fakeip::is_fakeip(ip) {
        if let Some(domain) = fakeip::get_domain(ip) {
            return Endpoint {
                host: domain,
                port,
                ip_v4: Some(ip),
                ip_v6: None,
                is_fake: true,
                fake_missing: false,
            };
        }
        return Endpoint {
            host: Ipv4Addr::from(ip).to_string(),
            port,
            ip_v4: Some(ip),
            ip_v6: None,
            is_fake: true,
            fake_missing: true,
        };
    }
    Endpoint {
        host: Ipv4Addr::from(ip).to_string(),
        port,
        ip_v4: Some(ip),
        ip_v6: None,
        is_fake: false,
        fake_missing: false,
    }
}
