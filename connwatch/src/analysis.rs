use crate::model::{ApplicationProtocol, ConnectionDirection, HttpRequest};
use chrono::Utc;
use std::net::IpAddr;

pub fn infer_direction(
    local_ips: &[IpAddr],
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> ConnectionDirection {
    if local_ips.contains(&src_ip) && !local_ips.contains(&dst_ip) {
        ConnectionDirection::Outgoing
    } else if local_ips.contains(&dst_ip) && !local_ips.contains(&src_ip) {
        ConnectionDirection::Incoming
    } else {
        ConnectionDirection::Unknown
    }
}

pub fn detect_application_protocol(
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<ApplicationProtocol> {
    if src_port == 22 || dst_port == 22 {
        if payload.starts_with(b"SSH-") {
            return Some(ApplicationProtocol::Ssh);
        }
    }

    if src_port == 443 || dst_port == 443 {
        if payload.windows(3).any(|w| w == b"SNI") {
            return Some(ApplicationProtocol::Https);
        }
    }

    if is_http_port(src_port) || is_http_port(dst_port) {
        if looks_like_http(payload) {
            return Some(ApplicationProtocol::Http);
        }
    }

    None
}

pub fn parse_http_request(payload: &[u8], log_auth_headers: bool) -> Option<HttpRequest> {
    let text = std::str::from_utf8(payload).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().map(|s| s.to_string());
    let path = parts.next().map(|s| s.to_string());
    let version = parts.next().map(|s| s.to_string());

    let mut host = None;
    let mut authorization = None;
    let mut user_agent = None;

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.strip_prefix("Host:") {
            host = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("Authorization:") {
            if log_auth_headers {
                authorization = Some(value.trim().to_string());
            } else {
                authorization = Some("[REDACTED]".to_string());
            }
        } else if let Some(value) = line.strip_prefix("User-Agent:") {
            user_agent = Some(value.trim().to_string());
        }
    }

    Some(HttpRequest {
        ts: Utc::now(),
        method,
        host,
        path,
        http_version: version,
        authorization,
        user_agent,
    })
}

fn is_http_port(port: u16) -> bool {
    port == 80 || port == 8080
}

fn looks_like_http(payload: &[u8]) -> bool {
    const METHODS: [&[u8]; 5] = [b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE "];
    METHODS.iter().any(|m| payload.starts_with(m))
}
