//! SOCKS5 and HTTP CONNECT codecs. Platforms own the socket reads and writes.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksTarget {
    Domain(String),
    V4([u8; 4]),
    V6([u8; 16]),
}

pub const SOCKS5_AUTH_NONE: u8 = 0x00;
pub const SOCKS5_AUTH_USERPASS: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5AuthChoice {
    None,
    UserPass,
}

pub fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub fn socks5_greeting() -> [u8; 3] {
    [0x05, 0x01, SOCKS5_AUTH_NONE]
}

pub fn socks5_greeting_for_auth(has_auth: bool) -> Vec<u8> {
    if has_auth {
        vec![0x05, 0x02, SOCKS5_AUTH_NONE, SOCKS5_AUTH_USERPASS]
    } else {
        vec![0x05, 0x01, SOCKS5_AUTH_NONE]
    }
}

pub fn socks5_greeting_ok(resp: &[u8]) -> bool {
    resp.len() >= 2 && resp[0] == 0x05 && resp[1] == SOCKS5_AUTH_NONE
}

pub fn socks5_check_greeting(resp: &[u8], has_auth: bool) -> Result<Socks5AuthChoice, String> {
    if resp.len() < 2 {
        return Err("SOCKS5 认证响应过短".into());
    }
    if resp[0] != 0x05 {
        if resp[0] == b'H' {
            return Err(
                "SOCKS5 认证响应协议版本无效 (首字节 'H')：对端返回 HTTP 响应，该端口可能是 HTTP 代理端口，请把 proxy.type 改为 http 或改用混合/SOCKS5 端口"
                    .into(),
            );
        }
        return Err(format!(
            "SOCKS5 认证响应协议版本无效: VER=0x{:02X}, METHOD=0x{:02X}",
            resp[0], resp[1]
        ));
    }
    match resp[1] {
        SOCKS5_AUTH_NONE => Ok(Socks5AuthChoice::None),
        SOCKS5_AUTH_USERPASS => {
            if has_auth {
                Ok(Socks5AuthChoice::UserPass)
            } else {
                Err(
                    "SOCKS5 代理要求用户名密码认证 (METHOD=0x02)，请在 config.json 中配置 proxy.username 和 proxy.password"
                        .into(),
                )
            }
        }
        0xFF => {
            if has_auth {
                Err("SOCKS5 代理拒绝协商认证方式 (METHOD=0xFF)".into())
            } else {
                Err(
                    "SOCKS5 代理拒绝免密连接 (METHOD=0xFF)，该代理可能需要认证，请在 config.json 中配置 proxy.username 和 proxy.password"
                        .into(),
                )
            }
        }
        other => Err(format!("SOCKS5 不支持的认证方式: METHOD=0x{other:02X}")),
    }
}

pub fn socks5_userpass_request(username: &str, password: &str) -> Result<Vec<u8>, String> {
    let u = username.as_bytes();
    let p = password.as_bytes();
    if u.len() > 255 || p.len() > 255 {
        return Err("SOCKS5 用户名或密码长度不能超过 255 字节".into());
    }
    let mut buf = Vec::with_capacity(3 + u.len() + p.len());
    buf.push(0x01); // RFC 1929 subnegotiation version
    buf.push(u.len() as u8);
    buf.extend_from_slice(u);
    buf.push(p.len() as u8);
    buf.extend_from_slice(p);
    Ok(buf)
}

pub fn socks5_userpass_ok(resp: &[u8]) -> Result<(), String> {
    if resp.len() < 2 {
        return Err("SOCKS5 账密认证响应过短".into());
    }
    if resp[0] != 0x01 {
        return Err(format!("SOCKS5 账密认证响应版本无效: 0x{:02X}", resp[0]));
    }
    if resp[1] != 0x00 {
        return Err(format!(
            "SOCKS5 用户名或密码认证失败 (status=0x{:02X})，请检查 config.json 中的 proxy.username 和 proxy.password",
            resp[1]
        ));
    }
    Ok(())
}

pub fn socks5_mismatch_hint_for_io() -> &'static str {
    "（提示：代理未按 SOCKS5 应答，该端口可能是 HTTP 代理端口：请把 proxy.type 改为 http，或改用代理软件的 SOCKS5 / 混合端口）"
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
    http_connect_request_with_auth(authority, "", "")
}

pub fn http_connect_request_with_auth(authority: &str, username: &str, password: &str) -> String {
    let mut req = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: Antigravity-Proxy-Rust/2.6\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if !username.is_empty() || !password.is_empty() {
        let cred = format!("{username}:{password}");
        let encoded = base64_encode(cred.as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    req.push_str("\r\n");
    req
}

pub fn http_mismatch_hint_for_io() -> &'static str {
    "（提示：代理收到 HTTP CONNECT 后断开或无应答，该端口可能是 SOCKS5 端口：请把 proxy.type 改为 socks5，或改用代理软件的 HTTP / 混合端口）"
}

/// `Ok(true)` once headers end in a 2xx status. `Ok(false)` if headers are incomplete.
pub fn http_connect_status(buf: &[u8]) -> Result<bool, String> {
    if !buf.is_empty() && buf[0] == 0x05 {
        return Err(
            "HTTP CONNECT 失败：该端口按 SOCKS5 协议应答 (0x05)，是 SOCKS5 端口，请把 proxy.type 改为 socks5"
                .into(),
        );
    }
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
    } else if code == 407 {
        Err(format!(
            "HTTP CONNECT 代理需要身份认证或认证失败 (407 Proxy Authentication Required: {line})，请检查 config.json 中的 proxy.username 和 proxy.password"
        ))
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
    fn socks5_auth_and_mismatch_hints() {
        assert_eq!(socks5_greeting_for_auth(false), vec![0x05, 0x01, 0x00]);
        assert_eq!(socks5_greeting_for_auth(true), vec![0x05, 0x02, 0x00, 0x02]);
        assert_eq!(
            socks5_check_greeting(&[0x05, 0x00], true).unwrap(),
            Socks5AuthChoice::None
        );
        assert_eq!(
            socks5_check_greeting(&[0x05, 0x02], true).unwrap(),
            Socks5AuthChoice::UserPass
        );
        assert!(socks5_check_greeting(&[0x05, 0x02], false).is_err());

        let http_err = socks5_check_greeting(b"HT", false).unwrap_err();
        assert!(http_err.contains("HTTP"));

        let up = socks5_userpass_request("alice", "s3cr3t").unwrap();
        assert_eq!(up, b"\x01\x05alice\x06s3cr3t");
        assert!(socks5_userpass_ok(&[0x01, 0x00]).is_ok());
        assert!(socks5_userpass_ok(&[0x01, 0x01]).is_err());
    }

    #[test]
    fn base64_and_http_basic_auth() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"alice:s3cr3t"), "YWxpY2U6czNjcjN0");

        let req = http_connect_request_with_auth("example.com:443", "alice", "s3cr3t");
        assert!(req.contains("Proxy-Authorization: Basic YWxpY2U6czNjcjN0\r\n"));

        let err_407 = http_connect_status(b"HTTP/1.1 407 Proxy Auth Required\r\n\r\n").unwrap_err();
        assert!(err_407.contains("407"));

        let err_socks = http_connect_status(&[0x05, 0x00]).unwrap_err();
        assert!(err_socks.contains("SOCKS5"));
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
        assert!(!req.contains("Proxy-Authorization:"));
        assert_eq!(
            http_connect_status(b"HTTP/1.1 200 Connection Established\r\n\r\n").unwrap(),
            true
        );
        assert!(http_connect_status(b"HTTP/1.1 403 Nope\r\n\r\n").is_err());
        assert_eq!(http_connect_status(b"HTTP/1.1 200").unwrap(), false);
    }
}
