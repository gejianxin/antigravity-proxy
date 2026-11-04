//! SOCKS5 and HTTP CONNECT codecs. Platforms own the socket reads and writes.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksTarget {
    Domain(String),
    V4([u8; 4]),
    V6([u8; 16]),
}

pub fn socks5_greeting() -> [u8; 3] {
    [0x05, 0x01, 0x00]
}

pub fn socks5_greeting_ok(resp: &[u8]) -> bool {
    resp.len() >= 2 && resp[0] == 0x05 && resp[1] == 0x00
}

pub fn socks5_request(cmd: u8, target: &SocksTarget, port: u16) -> Vec<u8> {
    let mut req = Vec::with_capacity(300);
    req.extend_from_slice(&[0x05, cmd, 0x00]);
    match target {
        SocksTarget::Domain(host) => {
            let bytes = host.as_bytes();
            let len = bytes.len().min(255) as u8;
            req.push(0x03);
            req.push(len);
            req.extend_from_slice(&bytes[..len as usize]);
        }
        SocksTarget::V4(octets) => {
            req.push(0x01);
            req.extend_from_slice(octets);
        }
        SocksTarget::V6(octets) => {
            req.push(0x04);
            req.extend_from_slice(octets);
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    req
}

pub fn socks5_connect_request(target: &SocksTarget, port: u16) -> Vec<u8> {
    socks5_request(0x01, target, port)
}

pub fn socks5_udp_associate_request() -> Vec<u8> {
    socks5_request(0x03, &SocksTarget::V4([0, 0, 0, 0]), 0)
}

/// Bytes still to read after the 4-byte SOCKS5 reply header.
/// For a domain address, `domain_len` is the next byte (not yet consumed).
pub fn socks5_bind_tail(atyp: u8, domain_len: Option<u8>) -> Option<usize> {
    match atyp {
        0x01 => Some(6),
        0x04 => Some(18),
        0x03 => Some(domain_len? as usize + 2),
        _ => None,
    }
}

pub fn socks5_reply_ok(hdr: &[u8]) -> Result<(), String> {
    if hdr.len() < 4 {
        return Err("short socks5 reply".into());
    }
    if hdr[0] != 0x05 {
        return Err("invalid socks5 version".into());
    }
    if hdr[1] != 0x00 {
        return Err(format!("socks5 status 0x{:02X}", hdr[1]));
    }
    Ok(())
}

/// SOCKS5 UDP request header + payload. `frag` is 0 for a standalone datagram.
pub fn socks5_udp_packet(target: &SocksTarget, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(payload.len() + 22);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
    match target {
        SocksTarget::Domain(host) => {
            let bytes = host.as_bytes();
            let len = bytes.len().min(255) as u8;
            pkt.push(0x03);
            pkt.push(len);
            pkt.extend_from_slice(&bytes[..len as usize]);
        }
        SocksTarget::V4(octets) => {
            pkt.push(0x01);
            pkt.extend_from_slice(octets);
        }
        SocksTarget::V6(octets) => {
            pkt.push(0x04);
            pkt.extend_from_slice(octets);
        }
    }
    pkt.extend_from_slice(&port.to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

/// Split a SOCKS5 UDP packet into destination and user payload.
pub fn socks5_udp_unwrap(packet: &[u8]) -> Option<(SocksTarget, u16, &[u8])> {
    if packet.len() < 4 || packet[2] != 0 {
        return None;
    }
    let (target, rest) = match packet[3] {
        0x01 => {
            if packet.len() < 10 {
                return None;
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&packet[4..8]);
            (SocksTarget::V4(ip), &packet[8..])
        }
        0x04 => {
            if packet.len() < 22 {
                return None;
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&packet[4..20]);
            (SocksTarget::V6(ip), &packet[20..])
        }
        0x03 => {
            let len = *packet.get(4)? as usize;
            let start = 5 + len;
            if packet.len() < start + 2 {
                return None;
            }
            let host = std::str::from_utf8(&packet[5..5 + len]).ok()?.to_string();
            (SocksTarget::Domain(host), &packet[start..])
        }
        _ => return None,
    };
    if rest.len() < 2 {
        return None;
    }
    let port = u16::from_be_bytes([rest[0], rest[1]]);
    Some((target, port, &rest[2..]))
}

pub fn http_connect_request(authority: &str) -> String {
    format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: Antigravity-Proxy-Rust/2.5\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    )
}

/// `Ok(true)` once headers end in a 2xx status. `Ok(false)` if headers are incomplete.
pub fn http_connect_status(buf: &[u8]) -> Result<bool, String> {
    if !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        return Ok(false);
    }
    let text = String::from_utf8_lossy(buf);
    let line = text.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let _http = parts.next();
    let code = parts
        .next()
        .ok_or_else(|| format!("HTTP CONNECT rejected: {line}"))?;
    let code: u16 = code
        .parse()
        .map_err(|_| format!("HTTP CONNECT rejected: {line}"))?;
    if (200..300).contains(&code) {
        Ok(true)
    } else {
        Err(format!("HTTP CONNECT rejected: {line}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks5_domain_connect_layout() {
        let req = socks5_connect_request(&SocksTarget::Domain("example.com".into()), 443);
        assert_eq!(&req[..4], &[0x05, 0x01, 0x00, 0x03]);
        assert_eq!(req[4], 11);
        assert_eq!(&req[5..16], b"example.com");
        assert_eq!(&req[16..], &443u16.to_be_bytes());
        assert!(socks5_greeting_ok(&[0x05, 0x00]));
        assert!(socks5_reply_ok(&[0x05, 0x00, 0x00, 0x01]).is_ok());
        assert_eq!(socks5_bind_tail(0x01, None), Some(6));
        assert_eq!(socks5_bind_tail(0x03, Some(4)), Some(6));
    }

    #[test]
    fn udp_packet_roundtrip() {
        let pkt = socks5_udp_packet(&SocksTarget::V4([1, 2, 3, 4]), 443, b"quic");
        let (target, port, payload) = socks5_udp_unwrap(&pkt).unwrap();
        assert_eq!(target, SocksTarget::V4([1, 2, 3, 4]));
        assert_eq!(port, 443);
        assert_eq!(payload, b"quic");
    }

    #[test]
    fn http_connect_parses_200() {
        let req = http_connect_request("example.com:443");
        assert!(req.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert_eq!(
            http_connect_status(b"HTTP/1.1 200 Connection Established\r\n\r\n").unwrap(),
            true
        );
        assert!(http_connect_status(b"HTTP/1.1 403 Nope\r\n\r\n").is_err());
        assert_eq!(http_connect_status(b"HTTP/1.1 200").unwrap(), false);
    }
}
