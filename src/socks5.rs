use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::sockio::{recv_exact, send_all};

pub fn append_socks_target(buf: &mut Vec<u8>, host: &str, port: u16) -> Result<()> {
    let host = host.trim().trim_matches(|c| c == '[' || c == ']');
    if host.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, "empty SOCKS target"));
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        buf.push(0x01);
        buf.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
        buf.push(0x04);
        buf.extend_from_slice(&ip.octets());
    } else {
        let bytes = host.as_bytes();
        if bytes.len() > 255 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "SOCKS domain longer than 255 bytes",
            ));
        }
        buf.push(0x03);
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    buf.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

pub fn wrap_udp(host: &str, port: u16, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(payload.len() + 262);
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    append_socks_target(&mut out, host, port)?;
    out.extend_from_slice(payload);
    Ok(out)
}

pub struct UnwrappedUdp<'a> {
    pub src: Option<(IpAddr, u16)>,
    pub payload: &'a [u8],
}

pub fn unwrap_udp(packet: &[u8]) -> Result<UnwrappedUdp<'_>> {
    if packet.len() < 10 || packet[0] != 0 || packet[1] != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "truncated SOCKS5 UDP header",
        ));
    }
    if packet[2] != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "fragmented SOCKS5 UDP is not supported",
        ));
    }
    let atyp = packet[3];
    let mut pos = 4usize;
    let src = match atyp {
        0x01 => {
            if packet.len() < pos + 6 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "truncated SOCKS5 IPv4 UDP header",
                ));
            }
            let ip = Ipv4Addr::new(
                packet[pos],
                packet[pos + 1],
                packet[pos + 2],
                packet[pos + 3],
            );
            pos += 4;
            let port = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
            pos += 2;
            Some((IpAddr::V4(ip), port))
        }
        0x04 => {
            if packet.len() < pos + 18 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "truncated SOCKS5 IPv6 UDP header",
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[pos..pos + 16]);
            pos += 16;
            let port = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
            pos += 2;
            Some((IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        0x03 => {
            if packet.len() < pos + 1 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "truncated SOCKS5 domain UDP header",
                ));
            }
            let dlen = packet[pos] as usize;
            pos += 1;
            if packet.len() < pos + dlen + 2 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "truncated SOCKS5 domain UDP header",
                ));
            }
            pos += dlen;
            pos += 2;
            None
        }
        _ => return Err(Error::new(ErrorKind::InvalidData, "unknown SOCKS5 ATYP")),
    };
    Ok(UnwrappedUdp {
        src,
        payload: &packet[pos..],
    })
}

fn sockaddr_host_port(addr: *const libc::sockaddr) -> Result<(String, u16)> {
    if addr.is_null() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "missing target address",
        ));
    }
    unsafe {
        if (*addr).sa_family == libc::AF_INET as libc::sa_family_t {
            let sin = &*(addr as *const libc::sockaddr_in);
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            return Ok((ip.to_string(), u16::from_be(sin.sin_port)));
        }
        if (*addr).sa_family == libc::AF_INET6 as libc::sa_family_t {
            let sin6 = &*(addr as *const libc::sockaddr_in6);
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            return Ok((ip.to_string(), u16::from_be(sin6.sin6_port)));
        }
    }
    Err(Error::new(
        ErrorKind::InvalidInput,
        "unsupported address family",
    ))
}

pub fn socks5_handshake(
    fd: libc::c_int,
    dest_host: Option<&str>,
    dest_port: u16,
    orig_addr: *const libc::sockaddr,
    send_timeout_ms: u32,
    recv_timeout_ms: u32,
) -> Result<()> {
    let greeting = [0x05u8, 0x01, 0x00];
    send_all(fd, &greeting, send_timeout_ms)?;

    let mut greeting_resp = [0u8; 2];
    recv_exact(fd, &mut greeting_resp, recv_timeout_ms)?;
    if greeting_resp[0] != 0x05 || greeting_resp[1] != 0x00 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "SOCKS5 server rejected auth: {:02X} {:02X}",
                greeting_resp[0], greeting_resp[1]
            ),
        ));
    }

    let mut req = vec![0x05, 0x01, 0x00];
    if let Some(host) = dest_host {
        append_socks_target(&mut req, host, dest_port)?;
    } else {
        let (host, port) = sockaddr_host_port(orig_addr)?;
        append_socks_target(&mut req, &host, port)?;
    }
    send_all(fd, &req, send_timeout_ms)?;

    let mut resp_hdr = [0u8; 4];
    recv_exact(fd, &mut resp_hdr, recv_timeout_ms)?;
    if resp_hdr[0] != 0x05 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "invalid SOCKS5 version in reply",
        ));
    }
    if resp_hdr[1] != 0x00 {
        return Err(Error::new(
            ErrorKind::ConnectionRefused,
            format!(
                "SOCKS5 connect failed with status code 0x{:02X}",
                resp_hdr[1]
            ),
        ));
    }

    let to_drain = match resp_hdr[3] {
        0x01 => 6,
        0x04 => 18,
        0x03 => {
            let mut dlen = [0u8; 1];
            recv_exact(fd, &mut dlen, recv_timeout_ms)?;
            dlen[0] as usize + 2
        }
        other => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unknown ATYP 0x{other:02X}"),
            ));
        }
    };
    let mut drain = vec![0u8; to_drain];
    recv_exact(fd, &mut drain, recv_timeout_ms)?;
    Ok(())
}

pub struct UdpRelay {
    pub storage: libc::sockaddr_storage,
    pub len: libc::socklen_t,
}

/// SOCKS5 UDP ASSOCIATE on an already-connected TCP control socket.
/// A zero bind address (`0.0.0.0:0`) is replaced with the TCP peer address.
pub fn udp_associate(
    fd: libc::c_int,
    send_timeout_ms: u32,
    recv_timeout_ms: u32,
) -> Result<UdpRelay> {
    let greeting = [0x05u8, 0x01, 0x00];
    send_all(fd, &greeting, send_timeout_ms)?;
    let mut greeting_resp = [0u8; 2];
    recv_exact(fd, &mut greeting_resp, recv_timeout_ms)?;
    if greeting_resp[0] != 0x05 || greeting_resp[1] != 0x00 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "SOCKS5 UDP associate authentication was rejected",
        ));
    }

    let req = [0x05u8, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    send_all(fd, &req, send_timeout_ms)?;

    let mut hdr = [0u8; 4];
    recv_exact(fd, &mut hdr, recv_timeout_ms)?;
    if hdr[0] != 0x05 || hdr[2] != 0x00 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "invalid SOCKS5 UDP associate header",
        ));
    }
    if hdr[1] != 0x00 {
        return Err(Error::new(
            ErrorKind::ConnectionRefused,
            format!("SOCKS5 UDP associate rejected with status 0x{:02X}", hdr[1]),
        ));
    }

    let (mut storage, mut len, unspecified, port) = match hdr[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            recv_exact(fd, &mut rest, recv_timeout_ms)?;
            let ip = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
            let port = u16::from_be_bytes([rest[4], rest[5]]);
            let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = port.to_be();
            sin.sin_addr.s_addr = u32::from(ip).to_be();
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin as *const _ as *const u8,
                    &mut storage as *mut _ as *mut u8,
                    std::mem::size_of::<libc::sockaddr_in>(),
                );
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                ip.is_unspecified(),
                port,
            )
        }
        0x04 => {
            let mut rest = [0u8; 18];
            recv_exact(fd, &mut rest, recv_timeout_ms)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&rest[..16]);
            let port = u16::from_be_bytes([rest[16], rest[17]]);
            let ip = Ipv6Addr::from(octets);
            let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = port.to_be();
            sin6.sin6_addr.s6_addr = octets;
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin6 as *const _ as *const u8,
                    &mut storage as *mut _ as *mut u8,
                    std::mem::size_of::<libc::sockaddr_in6>(),
                );
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                ip.is_unspecified(),
                port,
            )
        }
        0x03 => {
            let mut dlen = [0u8; 1];
            recv_exact(fd, &mut dlen, recv_timeout_ms)?;
            let mut name = vec![0u8; dlen[0] as usize + 2];
            recv_exact(fd, &mut name, recv_timeout_ms)?;
            let port = u16::from_be_bytes([name[name.len() - 2], name[name.len() - 1]]);
            let storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            (storage, 0, true, port)
        }
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "unknown UDP associate ATYP",
            ))
        }
    };

    if unspecified {
        storage = peer_with_port(fd, port)?;
        len = sockaddr_len(&storage);
    }
    if len == 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "UDP associate returned an empty relay address",
        ));
    }
    Ok(UdpRelay { storage, len })
}

fn sockaddr_len(storage: &libc::sockaddr_storage) -> libc::socklen_t {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        libc::AF_INET6 => std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        _ => 0,
    }
}

fn peer_with_port(fd: libc::c_int, port: u16) -> Result<libc::sockaddr_storage> {
    unsafe {
        let mut storage: libc::sockaddr_storage = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        if libc::getpeername(fd, &mut storage as *mut _ as *mut libc::sockaddr, &mut len) != 0 {
            return Err(Error::last_os_error());
        }
        if storage.ss_family as libc::c_int == libc::AF_INET {
            let sin = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in);
            sin.sin_port = port.to_be();
        } else if storage.ss_family as libc::c_int == libc::AF_INET6 {
            let sin6 = &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6);
            sin6.sin6_port = port.to_be();
        } else {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "proxy peer has an unknown family",
            ));
        }
        Ok(storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_domain_and_unwraps_ipv4() {
        let packet = wrap_udp("dns.google", 53, b"hi").unwrap();
        assert_eq!(&packet[..3], &[0, 0, 0]);
        assert_eq!(packet[3], 0x03);
        assert_eq!(packet[4], b"dns.google".len() as u8);
        assert!(packet.ends_with(b"hi"));

        let mut raw = vec![0, 0, 0, 1, 1, 2, 3, 4, 0x01, 0xBB];
        raw.extend_from_slice(b"pong");
        let parsed = unwrap_udp(&raw).unwrap();
        assert_eq!(parsed.payload, b"pong");
        assert_eq!(
            parsed.src,
            Some((IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443))
        );
    }

    #[test]
    fn rejects_fragments() {
        let packet = [0u8, 0, 1, 1, 0, 0, 0, 0, 0, 0];
        assert!(unwrap_udp(&packet).is_err());
    }

    #[test]
    fn associate_rewrites_unspecified_relay_to_peer() {
        use std::io::{Read, Write};
        use std::net::{Ipv4Addr, TcpListener, TcpStream};
        use std::os::fd::AsRawFd;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut greet = [0u8; 3];
            sock.read_exact(&mut greet).unwrap();
            sock.write_all(&[0x05, 0x00]).unwrap();
            let mut req = [0u8; 10];
            sock.read_exact(&mut req).unwrap();
            assert_eq!(req[0], 0x05);
            assert_eq!(req[1], 0x03);
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 9])
                .unwrap();
            let _ = sock.read(&mut req);
        });

        let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let relay = udp_associate(client.as_raw_fd(), 1000, 1000).unwrap();
        unsafe {
            let sin = &*(&relay.storage as *const _ as *const libc::sockaddr_in);
            assert_eq!(sin.sin_family as libc::c_int, libc::AF_INET);
            assert_eq!(u16::from_be(sin.sin_port), 9);
            assert_eq!(
                Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)),
                Ipv4Addr::new(127, 0, 0, 1)
            );
        }
    }
}
