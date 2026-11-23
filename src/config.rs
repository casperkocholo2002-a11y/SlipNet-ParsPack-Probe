use std::env;

#[derive(Clone, Debug)]
pub struct DirectConfig {
    pub host: String,
    pub port: u16,
    pub servername: String,
    pub path: String,
}

pub fn env_value(primary: &str, fallback: &str) -> String {
    let primary_value = env::var(primary).unwrap_or_default();
    if !primary_value.trim().is_empty() {
        return primary_value.trim().to_owned();
    }
    if fallback.is_empty() {
        return String::new();
    }
    env::var(fallback).unwrap_or_default().trim().to_owned()
}

pub fn env_int(primary: &str, fallback: &str) -> i64 {
    env_value(primary, fallback).parse::<i64>().unwrap_or(0)
}

fn normalize_route_path(value: String, default: &str) -> String {
    let owned;
    let raw = if value.trim().is_empty() {
        default
    } else {
        owned = value.trim().to_owned();
        &owned
    };
    let trimmed = raw.trim_matches('/');
    if trimmed.is_empty() {
        "/".into()
    } else {
        format!("/{trimmed}")
    }
}

pub fn relay_path() -> String {
    normalize_route_path(env_value("RELAY_PATH", "relaypath"), "/tunnel")
}

pub fn direct_relay_path() -> String {
    normalize_route_path(env_value("DIRECT_RELAY_PATH", "directrelaypath"), "/direct")
}

pub fn worker_direct_relay_path() -> String {
    normalize_route_path(
        env_value("WORKER_DIRECT_RELAY_PATH", "workerdirectrelaypath"),
        "/pw/6b7a4e1c9d8f2a35f4b20caa7e9d3f6c5a11b7c4",
    )
}

pub fn worker_direct_host() -> String {
    let value = env_value("WORKER_DIRECT_HOST", "workerdirecthost");
    if value.is_empty() {
        "ppw-3c19aa324d48.edgecache-628bbe41dc.workers.dev".into()
    } else {
        value
    }
}

pub fn worker_direct_path() -> String {
    let value = env_value("WORKER_DIRECT_PATH", "workerdirectpath");
    if value.is_empty() {
        "/w/986b32e37335922c2faab7ce2153a8c9f9c6aff9de334f28".into()
    } else {
        value
    }
}

pub fn worker_fixed_relay_path() -> String {
    normalize_route_path(
        env_value("WORKER_FIXED_RELAY_PATH", "workerfixedrelaypath"),
        "/pf/4e1b9c72a6d0f5e38b4c1a97d2f6e0ab3c8d5f11",
    )
}

pub fn worker_fixed_host() -> String {
    let value = env_value("WORKER_FIXED_HOST", "workerfixedhost");
    if value.is_empty() {
        "ppf-56cf1bc939.edgecache-628bbe41dc.workers.dev".into()
    } else {
        value
    }
}

pub fn worker_fixed_path() -> String {
    let value = env_value("WORKER_FIXED_PATH", "workerfixedpath");
    if value.is_empty() {
        "/ppwf/124b41395c04d8a24b794893309742a2f20b5482116d1e32".into()
    } else {
        value
    }
}

fn normalize_direct_origin(value: String) -> String {
    if value == "cdn.cspf.online" {
        "slipnet.wordpresscsp.ir".into()
    } else {
        value
    }
}

pub fn direct_config() -> DirectConfig {
    DirectConfig {
        host: normalize_direct_origin(env_value("DIRECT_ORIGIN_HOST", "directoriginhost")),
        port: env_int("DIRECT_ORIGIN_PORT", "directoriginport").clamp(0, 65535) as u16,
        servername: normalize_direct_origin(env_value(
            "DIRECT_ORIGIN_SERVERNAME",
            "directoriginservername",
        )),
        path: env_value("DIRECT_ORIGIN_PATH", "directoriginpath"),
    }
}

impl DirectConfig {
    pub fn valid(&self) -> bool {
        !self.host.is_empty()
            && !self.servername.is_empty()
            && !self.path.is_empty()
            && self.port > 0
    }

    pub fn websocket_url(&self) -> String {
        let host = if self.port == 443 {
            self.servername.clone()
        } else {
            format!("{}:{}", self.servername, self.port)
        };
        format!("wss://{}{}", host, self.path)
    }
}

pub fn origin_config() -> Option<(String, u16, String)> {
    let host = env_value("ORIGIN_HOST", "originhost");
    let port = env_int("ORIGIN_PORT", "originport");
    let servername = env_value("ORIGIN_SERVERNAME", "originservername");
    if host.is_empty() || servername.is_empty() || !(1..=65535).contains(&port) {
        return None;
    }
    Some((host, port as u16, servername))
}

pub fn worker_url(host: &str, path: &str) -> String {
    format!("wss://{}{}", host, path)
}

