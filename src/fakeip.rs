use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::RwLock;

pub const FAKE_IP_MAGIC: u64 = 0x41475950524F5859; // "AGYPROXY"

pub struct FakeIpPool {
    net_ip: u32,
    net_mask: u32,
    current_alloc: u32,
    domain_to_ip: HashMap<String, u32>,
    ip_to_domain: HashMap<u32, String>,
}

impl FakeIpPool {
    pub fn new(cidr: &str) -> Self {
        let (base, prefix) = match cidr.split_once('/') {
            Some((ip_str, p_str)) => (
                Ipv4Addr::from_str(ip_str).unwrap_or(Ipv4Addr::new(198, 18, 0, 0)),
                p_str.parse::<u32>().unwrap_or(15),
            ),
            None => (Ipv4Addr::new(198, 18, 0, 0), 15),
        };

        let net_ip = u32::from(base);
        let net_mask = if prefix == 0 {
            0
        } else {
            (!0u32).checked_shl(32 - prefix).unwrap_or(0)
        };

        let start_alloc = (net_ip & net_mask) + 2;

        Self {
            net_ip,
            net_mask,
            current_alloc: start_alloc,
            domain_to_ip: HashMap::new(),
            ip_to_domain: HashMap::new(),
        }
    }

    pub fn is_fake_ip(&self, ip_host_order: u32) -> bool {
        (ip_host_order & self.net_mask) == (self.net_ip & self.net_mask)
    }

    pub fn get_or_create(&mut self, domain: &str) -> u32 {
        let key = domain.to_lowercase();
        if let Some(&ip) = self.domain_to_ip.get(&key) {
            return ip;
        }

        let mut alloc = self.current_alloc;
        self.current_alloc = self.current_alloc.wrapping_add(1);

        // Check if exceeded CIDR pool range, wrap around
        if (alloc & self.net_mask) != (self.net_ip & self.net_mask) {
            self.current_alloc = (self.net_ip & self.net_mask) + 2;
            alloc = self.current_alloc;
            self.current_alloc = self.current_alloc.wrapping_add(1);
        }

        self.domain_to_ip.insert(key.clone(), alloc);
        self.ip_to_domain.insert(alloc, domain.to_string());
        alloc
    }

    pub fn get_domain(&self, ip_host_order: u32) -> Option<String> {
        self.ip_to_domain.get(&ip_host_order).cloned()
    }
}

static POOL: RwLock<Option<FakeIpPool>> = RwLock::new(None);

pub fn init(cidr: &str) {
    let pool = FakeIpPool::new(cidr);
    let mut guard = POOL.write().unwrap();
    *guard = Some(pool);
}

pub fn is_fakeip(ip_host_order: u32) -> bool {
    let guard = POOL.read().unwrap();
    if let Some(ref p) = *guard {
        p.is_fake_ip(ip_host_order)
    } else {
        false
    }
}

pub fn get_or_create(domain: &str) -> u32 {
    let mut guard = POOL.write().unwrap();
    if let Some(ref mut p) = *guard {
        p.get_or_create(domain)
    } else {
        0
    }
}

pub fn get_domain(ip_host_order: u32) -> Option<String> {
    let guard = POOL.read().unwrap();
    if let Some(ref p) = *guard {
        p.get_domain(ip_host_order)
    } else {
        None
    }
}

#[repr(C)]
pub struct FakeAiContainer {
    pub magic: u64,
    pub ai: libc::addrinfo,
    pub sin: libc::sockaddr_in,
}

pub fn create_fake_addrinfo(
    fake_ip_host_order: u32,
    port: u16,
    hints: Option<&libc::addrinfo>,
) -> *mut libc::addrinfo {
    let mut container = Box::new(FakeAiContainer {
        magic: FAKE_IP_MAGIC,
        ai: unsafe { std::mem::zeroed() },
        sin: unsafe { std::mem::zeroed() },
    });

    container.sin.sin_family = libc::AF_INET as libc::sa_family_t;
    container.sin.sin_port = port.to_be();
    container.sin.sin_addr.s_addr = fake_ip_host_order.to_be();

    container.ai.ai_flags = hints.map(|h| h.ai_flags).unwrap_or(0);
    container.ai.ai_family = libc::AF_INET;
    container.ai.ai_socktype = hints
        .and_then(|h| if h.ai_socktype != 0 { Some(h.ai_socktype) } else { None })
        .unwrap_or(libc::SOCK_STREAM);
    container.ai.ai_protocol = hints
        .and_then(|h| if h.ai_protocol != 0 { Some(h.ai_protocol) } else { None })
        .unwrap_or(libc::IPPROTO_TCP);
    container.ai.ai_addrlen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    container.ai.ai_addr = &mut container.sin as *mut _ as *mut libc::sockaddr;
    container.ai.ai_canonname = std::ptr::null_mut();
    container.ai.ai_next = std::ptr::null_mut();

    let raw_ptr = Box::into_raw(container);
    unsafe { &mut (*raw_ptr).ai as *mut libc::addrinfo }
}

pub fn is_fake_addrinfo(ai: *const libc::addrinfo) -> bool {
    if ai.is_null() {
        return false;
    }
    unsafe {
        let offset = std::mem::offset_of!(FakeAiContainer, ai);
        let container_ptr = (ai as *const u8).sub(offset) as *const FakeAiContainer;
        (*container_ptr).magic == FAKE_IP_MAGIC
    }
}

pub fn free_fake_addrinfo(ai: *mut libc::addrinfo) {
    if ai.is_null() {
        return;
    }
    unsafe {
        let offset = std::mem::offset_of!(FakeAiContainer, ai);
        let container_ptr = (ai as *mut u8).sub(offset) as *mut FakeAiContainer;
        if (*container_ptr).magic == FAKE_IP_MAGIC {
            (*container_ptr).magic = 0;
            drop(Box::from_raw(container_ptr));
        }
    }
}

pub fn create_fake_hostent(domain: &str, fake_ip_host_order: u32) -> *mut libc::hostent {
    struct HostentStorage {
        h: libc::hostent,
        addrs: [u32; 2],
        addr_ptrs: [*mut libc::c_char; 2],
        aliases: [*mut libc::c_char; 1],
        name_buf: Vec<u8>,
    }

    std::thread_local! {
        static STORAGE: std::cell::RefCell<HostentStorage> = std::cell::RefCell::new(HostentStorage {
            h: unsafe { std::mem::zeroed() },
            addrs: [0, 0],
            addr_ptrs: [std::ptr::null_mut(), std::ptr::null_mut()],
            aliases: [std::ptr::null_mut()],
            name_buf: Vec::new(),
        });
    }

    STORAGE.with(|cell| {
        let mut st = cell.borrow_mut();
        st.name_buf = domain.as_bytes().to_vec();
        st.name_buf.push(0);

        st.addrs[0] = fake_ip_host_order.to_be();
        st.addrs[1] = 0;
        st.addr_ptrs[0] = st.addrs.as_mut_ptr() as *mut libc::c_char;
        st.addr_ptrs[1] = std::ptr::null_mut();
        st.aliases[0] = std::ptr::null_mut();

        st.h.h_name = st.name_buf.as_mut_ptr() as *mut libc::c_char;
        st.h.h_aliases = st.aliases.as_mut_ptr();
        st.h.h_addrtype = libc::AF_INET;
        st.h.h_length = 4;
        st.h.h_addr_list = st.addr_ptrs.as_mut_ptr();

        &mut st.h as *mut libc::hostent
    })
}
