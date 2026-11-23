use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use rand::RngCore;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use crate::config::env_value;

const DEFAULT_TELEMETRY_URL: &str = "https://monitor.reoos.ir/api/v2ray-session/telemetry";
const FALLBACK_TELEMETRY_URL: &str = "https://monitor.cspf.shop/api/v2ray-session/telemetry";

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct TelemetryResponse {
    #[serde(default)]
    pub known: bool,
    #[serde(default)]
    pub session_known: Option<bool>,
    #[serde(default)]
    pub locked: bool,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub active_sources: i64,
}

#[derive(Debug, Clone)]
pub struct SessionMeta {
    pub uuid: String,
    pub hash: String,
    pub ip: String,
    pub session_id: String,
}

#[derive(Clone)]
pub struct SessionGuard {
    pub enabled: bool,
    pub route: String,
    pub heartbeat: Duration,
    telemetry_url: String,
    telemetry_fallback: String,
    client: Client,
}

impl SessionGuard {
    pub fn new(route: &str) -> Self {
        let enabled = env_value("CONCURRENCY_GUARD", "").trim() != "0";
        let mut telemetry_url = env_value("SESSION_TELEMETRY_URL", "sessiontelemetryurl");
        if telemetry_url.is_empty() {
            telemetry_url = DEFAULT_TELEMETRY_URL.into();
        }
        let telemetry_fallback = if telemetry_url
            .trim()
            .eq_ignore_ascii_case(FALLBACK_TELEMETRY_URL)
        {
            String::new()
        } else {
            FALLBACK_TELEMETRY_URL.into()
        };
        let client = Client::builder()
            .timeout(Duration::from_millis(1800))
            .build()
            .expect("telemetry client");

        Self {
            enabled,
            route: route.trim().to_lowercase(),
            telemetry_url,
            telemetry_fallback,
            heartbeat: Duration::from_secs(5),
            client,
        }
    }

    pub fn new_meta(
        &self,
        headers: &HeaderMap,
        peer: SocketAddr,
        initial: &[u8],
    ) -> anyhow::Result<Option<SessionMeta>> {
        if !self.enabled {
            return Ok(None);
        }
        let ip = source_ip(headers, peer, &self.route);
        if ip.is_empty() {
            return Ok(None);
        }
        let uuid =
            uuid_from_header(initial).ok_or_else(|| anyhow::anyhow!("invalid_vless_uuid"))?;
        let hash = uuid_hash(&uuid);
        let mut random = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut random);
        let session_id = hex::encode(random);
        Ok(Some(SessionMeta {
            uuid,
            hash,
            ip,
            session_id,
        }))
    }

    pub async fn emit(&self, meta: &SessionMeta, event: &str) -> Option<TelemetryResponse> {
        if !self.enabled {
            return None;
        }
        let ts = unix_now();
        let payload = json!({
            "uuid_hash": meta.hash,
            "source_ip": meta.ip,
            "route": self.route,
            "event": event,
            "ts": ts,
            "session_id": meta.session_id,
            "proof": telemetry_proof(
                &meta.uuid,
                &meta.hash,
                &meta.ip,
                &self.route,
                event,
                ts,
                &meta.session_id,
            ),
        });

        let mut urls = vec![self.telemetry_url.as_str()];
        if !self.telemetry_fallback.is_empty() {
            urls.push(self.telemetry_fallback.as_str());
        }

        for endpoint in urls {
            let response = match self
                .client
                .post(endpoint)
                .header("content-type", "application/json")
                .json(&payload)
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => continue,
            };
            if !response.status().is_success() {
                continue;
            }
            if let Ok(body) = response.json::<TelemetryResponse>().await {
                return Some(body);
            }
        }
        None
    }
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn normalize_ip(raw: &str) -> Option<IpAddr> {
    let mut value = raw.trim();
    if let Some(stripped) = value.strip_prefix("::ffff:") {
        value = stripped;
    }
    if let Some(index) = value.find('%') {
        value = &value[..index];
    }
    value.parse::<IpAddr>().ok()
}

fn ip_candidates(raw: &str) -> Vec<IpAddr> {
    raw.split(',').filter_map(normalize_ip).collect()
}

fn is_non_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
            {
                return true;
            }
            let o = v4.octets();
            if o[0] == 100 && (64..=127).contains(&o[1]) {
                return true;
            }
            if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return true;
            }
            let s = v6.segments();
            let first = s[0];
            (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

pub fn source_ip(headers: &HeaderMap, peer: SocketAddr, route: &str) -> String {
    let get = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned()
    };

    let singles = if route.trim().eq_ignore_ascii_case("arvan") {
        vec![get("ar-real-ip"), get("x-client-ip"), get("x-real-ip")]
    } else {
        vec![get("x-real-ip"), get("x-client-ip"), get("ar-real-ip")]
    };

    let mut private_fallback = Vec::<IpAddr>::new();
    let mut seen = HashSet::<IpAddr>::new();
    let push_private = |ip: IpAddr, list: &mut Vec<IpAddr>, seen: &mut HashSet<IpAddr>| {
        if seen.insert(ip) {
            list.push(ip);
        }
    };

    for raw in singles {
        for ip in ip_candidates(&raw) {
            if !is_non_public(ip) {
                return ip.to_string();
            }
            push_private(ip, &mut private_fallback, &mut seen);
        }
    }

    let forwarded = ip_candidates(&get("x-forwarded-for"));
    for ip in forwarded.into_iter().rev() {
        if !is_non_public(ip) {
            return ip.to_string();
        }
        push_private(ip, &mut private_fallback, &mut seen);
    }

    let remote = peer.ip();
    if !is_non_public(remote) {
        return remote.to_string();
    }
    push_private(remote, &mut private_fallback, &mut seen);

    private_fallback
        .first()
        .map(ToString::to_string)
        .unwrap_or_default()
}

fn uuid_from_header(header: &[u8]) -> Option<String> {
    if header.len() < 17 {
        return None;
    }
    let hexv = hex::encode(&header[1..17]);
    if hexv.len() != 32 {
        return None;
    }
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hexv[0..8],
        &hexv[8..12],
        &hexv[12..16],
        &hexv[16..20],
        &hexv[20..32]
    ))
}

fn uuid_hash(uuid: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(uuid.to_lowercase().as_bytes());
    hex::encode(hasher.finalize())
}

fn telemetry_proof(
    uuid: &str,
    hash: &str,
    ip: &str,
    route: &str,
    event: &str,
    ts: i64,
    session_id: &str,
) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let message = format!("{}|{}|{}|{}|{}|{}", hash, ip, route, event, ts, session_id);
    let mut mac = HmacSha256::new_from_slice(uuid.as_bytes()).expect("hmac key");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::net::{IpAddr, Ipv4Addr};

    fn peer() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 1234)
    }

    #[test]
    fn pars_pack_prefers_x_real_ip() {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", HeaderValue::from_static("5.215.242.49"));
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("8.8.8.8, 5.215.242.49, 192.168.4.104"),
        );
        assert_eq!(source_ip(&h, peer(), "parspack"), "5.215.242.49");
    }

    #[test]
    fn rejects_spoofed_leftmost_xff() {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", HeaderValue::from_static("192.168.4.104"));
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("8.8.8.8, 5.215.242.49, 192.168.4.104"),
        );
        assert_eq!(source_ip(&h, peer(), "parspack"), "5.215.242.49");
    }

    #[test]
    fn parses_vless_uuid_from_first_17_bytes() {
        let mut bytes = vec![0u8; 17];
        bytes[1..17].copy_from_slice(&[
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
            0xcd, 0xef,
        ]);
        assert_eq!(
            uuid_from_header(&bytes).unwrap(),
            "12345678-90ab-cdef-1234-567890abcdef"
        );
    }
}

