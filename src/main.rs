use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::{
    collections::HashMap,
    env,
    error::Error,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpListener, TcpStream},
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
};

const BUILD_ID: &str = "frankfurt-standalone-failover-v1";
const MAX_PREFACE: usize = 4096;
const MAX_WS_MESSAGE: usize = 1024 * 1024;
type DynError = Box<dyn Error + Send + Sync>;
type DynResult<T> = Result<T, DynError>;
type UserId = [u8; 16];

#[derive(Clone)]
struct Config {
    port: u16,
    ws_path: String,
    users: HashMap<UserId, String>,
    max_sessions: usize,
    max_ips_per_user: usize,
    connect_timeout: Duration,
    allow_private_targets: bool,
    trust_proxy_headers: bool,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let port = env::var("PORT")
            .unwrap_or_else(|_| "8080".into())
            .parse::<u16>()
            .map_err(|_| "PORT must be a valid TCP port")?;

        let mut ws_path = env::var("WS_PATH").unwrap_or_else(|_| "/failover".into());
        if !ws_path.starts_with('/') {
            ws_path.insert(0, '/');
        }
        if ws_path == "/health"
            || ws_path.contains('{')
            || ws_path.contains('}')
            || ws_path.contains('*')
        {
            return Err("WS_PATH is invalid or reserved".into());
        }

        let users_raw = env::var("VLESS_USERS")
            .map_err(|_| "VLESS_USERS is required, e.g. ME=uuid,ELAHE=uuid")?;
        let users = parse_users(&users_raw)?;
        if users.is_empty() {
            return Err("VLESS_USERS must contain at least one user".into());
        }

        Ok(Self {
            port,
            ws_path,
            users,
            max_sessions: env_usize("MAX_SESSIONS", 128, 1, 4096)?,
            max_ips_per_user: env_usize("MAX_IPS_PER_USER", 3, 1, 32)?,
            connect_timeout: Duration::from_secs(env_u64("CONNECT_TIMEOUT_SECS", 10, 1, 60)?),
            allow_private_targets: env_bool("ALLOW_PRIVATE_TARGETS", false),
            trust_proxy_headers: env_bool("TRUST_PROXY_HEADERS", true),
        })
    }
}

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    slots: Arc<Semaphore>,
    active_sessions: Arc<AtomicUsize>,
    bytes_up: Arc<AtomicU64>,
    bytes_down: Arc<AtomicU64>,
    active_ips: Arc<Mutex<HashMap<UserId, HashMap<IpAddr, usize>>>>,
}

struct SessionCounter(Arc<AtomicUsize>);

impl SessionCounter {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}

impl Drop for SessionCounter {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug)]
struct VlessRequest {
    version: u8,
    user_id: UserId,
    target: Target,
    port: u16,
    payload: Vec<u8>,
}

#[tokio::main]
async fn main() -> DynResult<()> {
    let cfg = Arc::new(
        Config::from_env().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
    );
    let state = AppState {
        slots: Arc::new(Semaphore::new(cfg.max_sessions)),
        cfg: cfg.clone(),
        active_sessions: Arc::new(AtomicUsize::new(0)),
        bytes_up: Arc::new(AtomicU64::new(0)),
        bytes_down: Arc::new(AtomicU64::new(0)),
        active_ips: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route(&cfg.ws_path, get(vless_ws))
        .fallback(not_found)
        .with_state(state);

    let listener = TcpListener::bind(("0.0.0.0", cfg.port)).await?;
    eprintln!(
        "SlipNet Frankfurt failover listening on 0.0.0.0:{} path={} build={}",
        cfg.port, cfg.ws_path, BUILD_ID
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

async fn health(State(state): State<AppState>) -> Response {
    Json(json!({
        "ok": true,
        "service": "slipnet-frankfurt-failover",
        "build": BUILD_ID,
        "standalone": true,
        "mode": "direct-egress",
        "protocol": "vless-ws-tcp",
        "originRequired": false,
        "server95Required": false,
        "server155Required": false,
        "users": state.cfg.users.len(),
        "activeSessions": state.active_sessions.load(Ordering::SeqCst),
        "maxSessions": state.cfg.max_sessions,
        "maxIpsPerUser": state.cfg.max_ips_per_user,
        "bytesUp": state.bytes_up.load(Ordering::Relaxed),
        "bytesDown": state.bytes_down.load(Ordering::Relaxed),
    }))
    .into_response()
}

async fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

async fn vless_ws(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let slot = match state.slots.clone().try_acquire_owned() {
        Ok(slot) => slot,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let source_ip = source_ip(&headers, peer, state.cfg.trust_proxy_headers);

    ws.max_message_size(MAX_WS_MESSAGE)
        .on_upgrade(move |socket| async move {
            let _slot = slot;
            let _count = SessionCounter::new(state.active_sessions.clone());
            if let Err(err) = handle_session(socket, state, source_ip).await {
                eprintln!("session ended: {err}");
            }
        })
}

async fn handle_session(
    mut socket: WebSocket,
    state: AppState,
    source_ip: IpAddr,
) -> DynResult<()> {
    let request = read_request(&mut socket).await?;

    if !state.cfg.users.contains_key(&request.user_id) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "unknown user").into());
    }

    if !register_ip(&state, request.user_id, source_ip).await {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "ip limit reached").into());
    }

    let user_id = request.user_id;
    let result = run_authenticated_session(socket, state.clone(), request).await;
    unregister_ip(&state, user_id, source_ip).await;
    result
}

async fn read_request(socket: &mut WebSocket) -> DynResult<VlessRequest> {
    let mut preface = Vec::new();

    loop {
        let message = socket
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "websocket closed"))??;

        match message {
            Message::Binary(data) => preface.extend_from_slice(&data),
            Message::Text(text) => preface.extend_from_slice(text.as_bytes()),
            Message::Close(_) => {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "websocket closed").into())
            }
            Message::Ping(_) | Message::Pong(_) => continue,
        }

        if preface.len() > MAX_PREFACE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "vless header too large").into());
        }

        match parse_vless_request(&preface) {
            Ok(Some(request)) => return Ok(request),
            Ok(None) => continue,
            Err(err) => return Err(io::Error::new(io::ErrorKind::InvalidData, err).into()),
        }
    }
}

fn parse_vless_request(data: &[u8]) -> Result<Option<VlessRequest>, String> {
    if data.len() < 18 {
        return Ok(None);
    }

    let version = data[0];
    let mut user_id = [0u8; 16];
    user_id.copy_from_slice(&data[1..17]);

    let addon_len = data[17] as usize;
    let mut cursor = 18usize
        .checked_add(addon_len)
        .ok_or_else(|| "invalid addon length".to_string())?;

    if data.len() < cursor + 4 {
        return Ok(None);
    }

    let command = data[cursor];
    cursor += 1;
    if command != 0x01 {
        return Err("only VLESS TCP command is supported".into());
    }

    let port = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
    cursor += 2;
    if port == 0 {
        return Err("destination port 0 is invalid".into());
    }

    let address_type = data[cursor];
    cursor += 1;

    let target = match address_type {
        0x01 => {
            if data.len() < cursor + 4 {
                return Ok(None);
            }
            let ip = Ipv4Addr::new(
                data[cursor],
                data[cursor + 1],
                data[cursor + 2],
                data[cursor + 3],
            );
            cursor += 4;
            Target::Ip(IpAddr::V4(ip))
        }
        0x02 => {
            if data.len() < cursor + 1 {
                return Ok(None);
            }
            let len = data[cursor] as usize;
            cursor += 1;
            if len == 0 {
                return Err("empty domain is invalid".into());
            }
            if data.len() < cursor + len {
                return Ok(None);
            }
            let domain = std::str::from_utf8(&data[cursor..cursor + len])
                .map_err(|_| "domain is not valid UTF-8")?
                .to_owned();
            cursor += len;
            Target::Domain(domain)
        }
        0x03 => {
            if data.len() < cursor + 16 {
                return Ok(None);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[cursor..cursor + 16]);
            cursor += 16;
            Target::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => return Err("unsupported address type".into()),
    };

    Ok(Some(VlessRequest {
        version,
        user_id,
        target,
        port,
        payload: data[cursor..].to_vec(),
    }))
}

async fn run_authenticated_session(
    socket: WebSocket,
    state: AppState,
    request: VlessRequest,
) -> DynResult<()> {
    let mut target =
        connect_target(&request.target, request.port, &state.cfg).await?;
    target.set_nodelay(true)?;

    let (mut client_tx, mut client_rx) = socket.split();

    client_tx
        .send(Message::Binary(vec![request.version, 0x00]))
        .await?;

    if !request.payload.is_empty() {
        target.write_all(&request.payload).await?;
        state
            .bytes_up
            .fetch_add(request.payload.len() as u64, Ordering::Relaxed);
    }

    let (mut target_rx, mut target_tx) = target.into_split();

    let upload_state = state.clone();
    let client_to_target = async move {
        while let Some(message) = client_rx.next().await {
            match message? {
                Message::Binary(data) => {
                    target_tx.write_all(&data).await?;
                    upload_state
                        .bytes_up
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                Message::Text(text) => {
                    let bytes = text.as_bytes();
                    target_tx.write_all(bytes).await?;
                    upload_state
                        .bytes_up
                        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                }
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) => {}
            }
        }
        let _ = target_tx.shutdown().await;
        Ok::<(), DynError>(())
    };

    let download_state = state.clone();
    let target_to_client = async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = target_rx.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            client_tx.send(Message::Binary(buf[..n].to_vec())).await?;
            download_state
                .bytes_down
                .fetch_add(n as u64, Ordering::Relaxed);
        }
        Ok::<(), DynError>(())
    };

    tokio::select! {
        result = client_to_target => result?,
        result = target_to_client => result?,
    }

    Ok(())
}

async fn connect_target(target: &Target, port: u16, cfg: &Config) -> io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = match target {
        Target::Ip(ip) => vec![SocketAddr::new(*ip, port)],
        Target::Domain(domain) => {
            let resolved = tokio::time::timeout(cfg.connect_timeout, lookup_host((domain.as_str(), port)))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns lookup timed out"))??;
            resolved.collect()
        }
    };

    let mut last_error: Option<io::Error> = None;
    let mut allowed_seen = false;

    for addr in addrs {
        if !cfg.allow_private_targets && is_forbidden_ip(addr.ip()) {
            continue;
        }
        allowed_seen = true;

        match tokio::time::timeout(cfg.connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => last_error = Some(err),
            Err(_) => {
                last_error = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "destination connect timed out",
                ))
            }
        }
    }

    if !allowed_seen {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "destination resolves only to blocked private/local addresses",
        ));
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "destination has no usable address")
    }))
}

fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
                || ip.is_multicast()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
        }
    }
}

async fn register_ip(state: &AppState, user_id: UserId, ip: IpAddr) -> bool {
    let mut all = state.active_ips.lock().await;
    let per_user = all.entry(user_id).or_default();

    if !per_user.contains_key(&ip) && per_user.len() >= state.cfg.max_ips_per_user {
        return false;
    }

    *per_user.entry(ip).or_insert(0) += 1;
    true
}

async fn unregister_ip(state: &AppState, user_id: UserId, ip: IpAddr) {
    let mut all = state.active_ips.lock().await;
    let remove_user = if let Some(per_user) = all.get_mut(&user_id) {
        if let Some(count) = per_user.get_mut(&ip) {
            if *count > 1 {
                *count -= 1;
            } else {
                per_user.remove(&ip);
            }
        }
        per_user.is_empty()
    } else {
        false
    };

    if remove_user {
        all.remove(&user_id);
    }
}

fn source_ip(headers: &HeaderMap, peer: SocketAddr, trust_proxy_headers: bool) -> IpAddr {
    if trust_proxy_headers {
        for name in ["cf-connecting-ip", "x-real-ip"] {
            if let Some(ip) = headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<IpAddr>().ok())
            {
                return ip;
            }
        }

        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
        {
            return ip;
        }
    }

    peer.ip()
}

fn parse_users(raw: &str) -> Result<HashMap<UserId, String>, String> {
    let mut users = HashMap::new();

    for (index, item) in raw.split(',').enumerate() {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }

        let (name, uuid_text) = match item.split_once('=') {
            Some((name, uuid)) => (name.trim().to_owned(), uuid.trim()),
            None => (format!("user{}", index + 1), item),
        };

        if name.is_empty() {
            return Err("VLESS_USERS contains an empty user name".into());
        }

        let id = parse_uuid(uuid_text)?;
        if users.insert(id, name).is_some() {
            return Err("VLESS_USERS contains a duplicate UUID".into());
        }
    }

    Ok(users)
}

fn parse_uuid(value: &str) -> Result<UserId, String> {
    let compact: String = value.chars().filter(|c| *c != '-').collect();
    if compact.len() != 32 {
        return Err(format!("invalid UUID: {value}"));
    }

    let mut out = [0u8; 16];
    for (index, slot) in out.iter_mut().enumerate() {
        let pos = index * 2;
        *slot = u8::from_str_radix(&compact[pos..pos + 2], 16)
            .map_err(|_| format!("invalid UUID: {value}"))?;
    }
    Ok(out)
}

fn env_bool(name: &str, default: bool) -> bool {
    match env::var(name) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

fn env_usize(name: &str, default: usize, min: usize, max: usize) -> Result<usize, String> {
    let value = match env::var(name) {
        Ok(value) => value
            .parse::<usize>()
            .map_err(|_| format!("{name} must be an integer"))?,
        Err(_) => default,
    };
    if !(min..=max).contains(&value) {
        return Err(format!("{name} must be between {min} and {max}"));
    }
    Ok(value)
}

fn env_u64(name: &str, default: u64, min: u64, max: u64) -> Result<u64, String> {
    let value = match env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|_| format!("{name} must be an integer"))?,
        Err(_) => default,
    };
    if !(min..=max).contains(&value) {
        return Err(format!("{name} must be between {min} and {max}"));
    }
    Ok(value)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut sigterm) = signal(SignalKind::terminate()) {
            sigterm.recv().await;
        } else {
            futures_util::future::pending::<()>().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = futures_util::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> UserId {
        parse_uuid("00112233-4455-6677-8899-aabbccddeeff").unwrap()
    }

    #[test]
    fn parses_domain_request_and_payload() {
        let mut data = vec![0x00];
        data.extend_from_slice(&user());
        data.push(0x00);
        data.push(0x01);
        data.extend_from_slice(&443u16.to_be_bytes());
        data.push(0x02);
        data.push(11);
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(b"hello");

        let parsed = parse_vless_request(&data).unwrap().unwrap();
        assert_eq!(parsed.user_id, user());
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.target, Target::Domain("example.com".into()));
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn parses_ipv4_request() {
        let mut data = vec![0x00];
        data.extend_from_slice(&user());
        data.push(0x00);
        data.push(0x01);
        data.extend_from_slice(&80u16.to_be_bytes());
        data.push(0x01);
        data.extend_from_slice(&[1, 1, 1, 1]);

        let parsed = parse_vless_request(&data).unwrap().unwrap();
        assert_eq!(parsed.target, Target::Ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn waits_for_partial_header() {
        let data = vec![0u8; 10];
        assert!(parse_vless_request(&data).unwrap().is_none());
    }

    #[test]
    fn rejects_udp_command() {
        let mut data = vec![0x00];
        data.extend_from_slice(&user());
        data.push(0x00);
        data.push(0x02);
        data.extend_from_slice(&53u16.to_be_bytes());
        data.push(0x01);
        data.extend_from_slice(&[1, 1, 1, 1]);

        assert!(parse_vless_request(&data).is_err());
    }

    #[test]
    fn blocks_private_targets_by_default() {
        assert!(is_forbidden_ip("127.0.0.1".parse().unwrap()));
        assert!(is_forbidden_ip("10.0.0.1".parse().unwrap()));
        assert!(is_forbidden_ip("::1".parse().unwrap()));
        assert!(!is_forbidden_ip("1.1.1.1".parse().unwrap()));
    }
}
