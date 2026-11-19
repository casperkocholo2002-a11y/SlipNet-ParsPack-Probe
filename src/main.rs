mod config;
mod guard;
mod tls;

use anyhow::Result;
use async_stream::stream;
use axum::{
    body::Body,
    extract::{
        ws::{Message as AMessage, WebSocket, WebSocketUpgrade},
        ConnectInfo, DefaultBodyLimit, Query, State,
    },
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message as TMessage;

use config::*;
use guard::{SessionGuard, SessionMeta};
use tls::BackendWs;

const MAX_ECHO: usize = 16 * 1024 * 1024;
const MAX_STREAM: usize = 8 * 1024 * 1024;
const MAX_WS: usize = 1024 * 1024;
const BUILD_ID: &str = "rust-native-v6-direct-dns-diagnostic";

#[derive(Clone)]
struct AppState {
    guard: Arc<SessionGuard>,
    sessions: Arc<AtomicUsize>,
}

struct SessionPermit(Arc<AtomicUsize>);

impl SessionPermit {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}

impl Drop for SessionPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn json_response(status: StatusCode, value: Value) -> Response {
    let mut response = (status, Json(value)).into_response();
    let headers = response.headers_mut();
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert("x-slipnet-probe", HeaderValue::from_static("1"));
    response
}

async fn health(State(state): State<AppState>) -> Response {
    let direct = direct_config();
    let relay_configured = origin_config().is_some();
    json_response(
        StatusCode::OK,
        json!({
            "ok": true,
            "service": "slipnet-parspack-ingress-probe",
            "runtime": format!("rust-{}", env!("CARGO_PKG_VERSION")),
            "relayConfigured": relay_configured,
            "directRelayConfigured": direct.valid(),
            "originSniSent": false,
            "directOriginSniSent": true,
            "originTlsMin": "TLSv1.3",
            "directRelayMode": "wss",
            "workerDirectConfigured": !worker_direct_host().is_empty() && !worker_direct_path().is_empty(),
            "workerFixedConfigured": !worker_fixed_host().is_empty() && !worker_fixed_path().is_empty(),
            "workerRelayMode": "wss",
            "concurrencyGuardEnabled": state.guard.enabled,
            "concurrencyGuardRoute": state.guard.route,
            "activeSessions": state.sessions.load(Ordering::SeqCst),
            "build": BUILD_ID,
        }),
    )
}

async fn origin_check() -> Response {
    let Some((host, port, _)) = origin_config() else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "origin_check_not_configured"}),
        );
    };

    let start = std::time::Instant::now();
    let mut tcp = match tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect((&*host, port)),
    )
    .await
    {
        Ok(Ok(tcp)) => tcp,
        _ => {
            return json_response(
                StatusCode::BAD_GATEWAY,
                json!({"ok": false, "connected": false, "error": "connect_error", "ms": start.elapsed().as_millis()}),
            )
        }
    };
    let _ = tcp.set_nodelay(true);
    let mut buf = [0u8; 256];
    let n = match tokio::time::timeout(Duration::from_millis(800), tcp.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };
    let banner: String = buf[..n]
        .iter()
        .filter_map(|b| {
            if *b == b'\r' || *b == b'\n' || (0x20..=0x7e).contains(b) {
                Some(*b as char)
            } else {
                None
            }
        })
        .take(160)
        .collect();

    json_response(
        StatusCode::OK,
        json!({"ok": true, "connected": true, "ms": start.elapsed().as_millis(), "banner": banner}),
    )
}

fn short_fingerprint(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())[..12].to_owned()
}

async fn resolve_summary(host: &str, port: u16) -> serde_json::Value {
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::lookup_host((host, port)),
    )
    .await;

    match result {
        Ok(Ok(addrs)) => {
            let mut count = 0usize;
            let mut v4 = false;
            let mut v6 = false;
            for addr in addrs {
                count += 1;
                if addr.is_ipv4() {
                    v4 = true;
                } else if addr.is_ipv6() {
                    v6 = true;
                }
            }
            json!({"ok": count > 0, "count": count, "v4": v4, "v6": v6})
        }
        Ok(Err(_)) => json!({"ok": false, "error": "resolve_error"}),
        Err(_) => json!({"ok": false, "error": "resolve_timeout"}),
    }
}

async fn direct_dns_check() -> Response {
    let config = direct_config();
    if !config.valid() {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "direct_dns_check_not_configured"}),
        );
    }

    const CANONICAL: &str = "slipnet.wordpresscsp.ir";
    let host = resolve_summary(&config.host, config.port).await;
    let servername = resolve_summary(&config.servername, config.port).await;

    json_response(
        StatusCode::OK,
        json!({
            "ok": true,
            "hostEqualsServername": config.host == config.servername,
            "hostFingerprint": short_fingerprint(&config.host),
            "servernameFingerprint": short_fingerprint(&config.servername),
            "hostCanonical": config.host == CANONICAL,
            "servernameCanonical": config.servername == CANONICAL,
            "hostResolve": host,
            "servernameResolve": servername,
        }),
    )
}

async fn direct_origin_check() -> Response {
    let config = direct_config();
    if !config.valid() {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "direct_origin_check_not_configured"}),
        );
    }
    let start = std::time::Instant::now();
    match tls::dial_direct_ws(&config).await {
        Ok(ws) => {
            tls::close_backend(ws).await;
            json_response(
                StatusCode::OK,
                json!({"ok": true, "connected": true, "mode": "wss", "ms": start.elapsed().as_millis()}),
            )
        }
        Err(err) => {
            let kind = tls::classify_direct_error(&err);
            json_response(
                StatusCode::BAD_GATEWAY,
                json!({"ok": false, "connected": false, "error": "wss_connect_error", "kind": kind, "ms": start.elapsed().as_millis()}),
            )
        }
    }
}

async fn echo(body: Bytes) -> Response {
    if body.len() > MAX_ECHO {
        let mut response = StatusCode::PAYLOAD_TOO_LARGE.into_response();
        response
            .headers_mut()
            .insert("x-slipnet-probe", HeaderValue::from_static("1"));
        return response;
    }
    let mut hasher = Sha256::new();
    hasher.update(&body);
    json_response(
        StatusCode::OK,
        json!({"ok": true, "bytes": body.len(), "sha256": hex::encode(hasher.finalize())}),
    )
}

#[derive(Deserialize)]
struct StreamQuery {
    bytes: Option<usize>,
    chunk: Option<usize>,
    delay_ms: Option<u64>,
}

async fn stream_http(Query(q): Query<StreamQuery>) -> Response {
    let total = q.bytes.unwrap_or(1024 * 1024).clamp(1, MAX_STREAM);
    let chunk_size = q.chunk.unwrap_or(16 * 1024).clamp(1, 64 * 1024);
    let delay_ms = q.delay_ms.unwrap_or(0).min(1000);

    let body_stream = stream! {
        let chunk = Bytes::from(vec![0x53; chunk_size]);
        let mut sent = 0usize;
        while sent < total {
            let n = (total - sent).min(chunk_size);
            yield Ok::<Bytes, Infallible>(chunk.slice(..n));
            sent += n;
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }
    };

    let mut response = Body::from_stream(body_stream).into_response();
    let headers = response.headers_mut();
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert("x-slipnet-probe", HeaderValue::from_static("1"));
    headers.insert(
        HeaderName::from_static("x-probe-total-bytes"),
        HeaderValue::from_str(&total.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    response
}

#[derive(Deserialize)]
struct HoldQuery {
    seconds: Option<u64>,
}

async fn hold_http(Query(q): Query<HoldQuery>) -> Response {
    let seconds = q.seconds.unwrap_or(30).clamp(1, 120);
    let body_stream = stream! {
        for _ in 0..seconds {
            tokio::time::sleep(Duration::from_secs(1)).await;
            yield Ok::<Bytes, Infallible>(Bytes::from_static(b"tick\n"));
        }
        yield Ok::<Bytes, Infallible>(Bytes::from_static(b"done\n"));
    };
    let mut response = Body::from_stream(body_stream).into_response();
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("text/plain"));
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert("x-slipnet-probe", HeaderValue::from_static("1"));
    response
}

async fn echo_ws(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    ws.max_message_size(MAX_WS)
        .on_upgrade(move |mut socket| async move {
            let _permit = SessionPermit::new(state.sessions.clone());
            while let Some(Ok(message)) = socket.recv().await {
                match message {
                    AMessage::Text(_)
                    | AMessage::Binary(_)
                    | AMessage::Ping(_)
                    | AMessage::Pong(_) => {
                        if socket.send(message).await.is_err() {
                            break;
                        }
                    }
                    AMessage::Close(_) => break,
                }
            }
        })
}

async fn read_initial_payload(socket: &mut WebSocket, needed: usize) -> Result<Vec<u8>> {
    Ok(tokio::time::timeout(Duration::from_secs(5), async {
        let mut out = Vec::with_capacity(needed);
        while out.len() < needed {
            let message = socket
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("websocket_closed"))??;
            let bytes: Vec<u8> = match message {
                AMessage::Binary(data) => data.to_vec(),
                AMessage::Text(text) => text.as_str().as_bytes().to_vec(),
                AMessage::Close(_) => anyhow::bail!("websocket_closed"),
                _ => continue,
            };
            if bytes.len() > MAX_WS || out.len() + bytes.len() > MAX_WS {
                anyhow::bail!("initial_payload_too_large");
            }
            out.extend_from_slice(&bytes);
        }
        Ok::<Vec<u8>, anyhow::Error>(out)
    })
    .await??)
}

async fn primary_relay(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let origin = match tls::dial_primary_origin().await {
        Ok(origin) => origin,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };

    ws.max_message_size(MAX_WS)
        .on_upgrade(move |socket| async move {
            if let Err(error) = primary_session(socket, origin, headers, peer, state).await {
                eprintln!("primary session ended: {error:#}");
            }
        })
}

async fn primary_session(
    mut socket: WebSocket,
    mut origin: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    headers: HeaderMap,
    peer: SocketAddr,
    state: AppState,
) -> Result<()> {
    let _permit = SessionPermit::new(state.sessions.clone());
    let mut meta: Option<SessionMeta> = None;

    if state.guard.enabled {
        let source = guard::source_ip(&headers, peer, &state.guard.route);
        if !source.is_empty() {
            let initial = read_initial_payload(&mut socket, 17).await?;
            meta = state.guard.new_meta(&headers, peer, &initial[..17])?;
            if let Some(m) = meta.as_ref() {
                if state.guard.emit(m, "open").await.is_some_and(|s| s.locked) {
                    return Ok(());
                }
            }
            origin.write_all(&initial).await?;
        }
    }

    let close_meta = meta.clone();
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (mut origin_rx, mut origin_tx) = tokio::io::split(origin);

    let client_to_origin = async {
        while let Some(message) = ws_rx.next().await {
            match message? {
                AMessage::Binary(data) => origin_tx.write_all(&data).await?,
                AMessage::Text(text) => origin_tx.write_all(text.as_str().as_bytes()).await?,
                AMessage::Close(_) => break,
                AMessage::Ping(_) | AMessage::Pong(_) => {}
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    let origin_to_client = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = origin_rx.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            ws_tx.send(AMessage::Binary(buf[..n].to_vec())).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    let heartbeat = async {
        let Some(m) = meta.as_ref() else {
            futures_util::future::pending::<()>().await;
            return Ok::<(), anyhow::Error>(());
        };
        let mut ticker = tokio::time::interval(state.guard.heartbeat);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let mut response = state.guard.emit(m, "heartbeat").await;
            if response
                .as_ref()
                .is_some_and(|s| s.known && s.session_known == Some(false))
            {
                response = state.guard.emit(m, "open").await;
            }
            if response.as_ref().is_some_and(|s| s.locked) {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        _ = client_to_origin => {},
        _ = origin_to_client => {},
        _ = heartbeat => {},
    }

    if let Some(m) = close_meta {
        let guard = state.guard.clone();
        tokio::spawn(async move {
            let _ = guard.emit(&m, "close").await;
        });
    }
    Ok(())
}

async fn direct_relay(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    let config = direct_config();
    if !config.valid() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let backend = match tls::dial_direct_ws(&config).await {
        Ok(backend) => backend,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    ws.max_message_size(MAX_WS)
        .on_upgrade(move |socket| async move {
            let _ = proxy_backend_session(socket, backend, state).await;
        })
}

async fn worker_direct_relay(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    let url = worker_url(&worker_direct_host(), &worker_direct_path());
    backend_relay_response(ws, state, &url).await
}

async fn worker_fixed_relay(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    let url = worker_url(&worker_fixed_host(), &worker_fixed_path());
    backend_relay_response(ws, state, &url).await
}

async fn backend_relay_response(ws: WebSocketUpgrade, state: AppState, url: &str) -> Response {
    let backend = match tls::dial_url_ws(url).await {
        Ok(backend) => backend,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    ws.max_message_size(MAX_WS)
        .on_upgrade(move |socket| async move {
            let _ = proxy_backend_session(socket, backend, state).await;
        })
}

async fn proxy_backend_session(
    socket: WebSocket,
    backend: BackendWs,
    state: AppState,
) -> Result<()> {
    let _permit = SessionPermit::new(state.sessions.clone());
    let (mut client_tx, mut client_rx) = socket.split();
    let (mut backend_tx, mut backend_rx) = backend.split();

    let client_to_backend = async {
        while let Some(message) = client_rx.next().await {
            match message? {
                AMessage::Binary(data) => backend_tx.send(TMessage::Binary(data)).await?,
                AMessage::Text(text) => {
                    backend_tx
                        .send(TMessage::Text(text.to_string().into()))
                        .await?
                }
                AMessage::Ping(data) => backend_tx.send(TMessage::Ping(data)).await?,
                AMessage::Pong(data) => backend_tx.send(TMessage::Pong(data)).await?,
                AMessage::Close(_) => {
                    let _ = backend_tx.send(TMessage::Close(None)).await;
                    break;
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    let backend_to_client = async {
        while let Some(message) = backend_rx.next().await {
            match message? {
                TMessage::Binary(data) => client_tx.send(AMessage::Binary(data)).await?,
                TMessage::Text(text) => {
                    client_tx
                        .send(AMessage::Text(text.to_string().into()))
                        .await?
                }
                TMessage::Ping(data) => client_tx.send(AMessage::Ping(data)).await?,
                TMessage::Pong(data) => client_tx.send(AMessage::Pong(data)).await?,
                TMessage::Close(_) => {
                    let _ = client_tx.send(AMessage::Close(None)).await;
                    break;
                }
                TMessage::Frame(_) => {}
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        _ = client_to_backend => {},
        _ = backend_to_client => {},
    }
    Ok(())
}

async fn not_found() -> Response {
    json_response(
        StatusCode::NOT_FOUND,
        json!({"ok": false, "error": "not_found"}),
    )
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

#[tokio::main]
async fn main() -> Result<()> {
    let port = env_int("PORT", "");
    let port = if (1..=65535).contains(&port) {
        port as u16
    } else {
        8080
    };

    let state = AppState {
        guard: Arc::new(SessionGuard::new("parspack")),
        sessions: Arc::new(AtomicUsize::new(0)),
    };

    let relay = relay_path();
    let direct = direct_relay_path();
    let worker_direct = worker_direct_relay_path();
    let worker_fixed = worker_fixed_relay_path();

    let app = Router::new()
        .route("/health", get(health))
        .route("/origin-check", get(origin_check))
        .route("/direct-origin-check", get(direct_origin_check))
        .route("/direct-dns-check", get(direct_dns_check))
        .route("/echo", post(echo))
        .route("/stream", get(stream_http))
        .route("/hold", get(hold_http))
        .route("/ws", get(echo_ws))
        .route(&relay, get(primary_relay))
        .route(&direct, get(direct_relay))
        .route(&worker_direct, get(worker_direct_relay))
        .route(&worker_fixed, get(worker_fixed_relay))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_ECHO + 1))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    eprintln!("slipnet-parspack-rust listening on {port} build={BUILD_ID}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}