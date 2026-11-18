use anyhow::{Context, Result};
use futures_util::SinkExt;
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use std::{sync::Arc, time::Duration};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

use crate::config::{origin_config, DirectConfig};

pub type BackendWs = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

fn tls13_config(send_sni: bool) -> ClientConfig {
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(root_store())
        .with_no_client_auth();
    config.enable_sni = send_sni;
    config
}

async fn tcp_connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let stream = tokio::time::timeout(timeout, TcpStream::connect((host, port)))
        .await
        .context("tcp connect timeout")??;
    stream.set_nodelay(true)?;
    Ok(stream)
}

pub async fn dial_primary_origin() -> Result<TlsStream<TcpStream>> {
    let (host, port, servername) = origin_config().context("origin_not_configured")?;
    let tcp = tcp_connect(&host, port, Duration::from_secs(15)).await?;
    let server_name =
        ServerName::try_from(servername.clone()).context("invalid origin servername")?;
    let connector = TlsConnector::from(Arc::new(tls13_config(false)));
    let tls = tokio::time::timeout(Duration::from_secs(15), connector.connect(server_name, tcp))
        .await
        .context("tls handshake timeout")??;
    Ok(tls)
}

pub async fn dial_direct_ws(config: &DirectConfig) -> Result<BackendWs> {
    if !config.valid() {
        anyhow::bail!("direct_not_configured");
    }

    let target = config.websocket_url();
    let (ws, _) = tokio::time::timeout(Duration::from_secs(5), connect_async(&target))
        .await
        .context("direct websocket timeout")??;
    Ok(ws)
}

pub async fn dial_url_ws(url: &str) -> Result<BackendWs> {
    let (ws, _) = tokio::time::timeout(Duration::from_secs(15), connect_async(url))
        .await
        .context("backend websocket timeout")??;
    Ok(ws)
}

pub fn classify_direct_error(err: &anyhow::Error) -> &'static str {
    for cause in err.chain() {
        if let Some(ws_err) = cause.downcast_ref::<tokio_tungstenite::tungstenite::Error>() {
            use tokio_tungstenite::tungstenite::Error as WsError;
            return match ws_err {
                WsError::Http(response) => match response.status().as_u16() {
                    400 => "http_400",
                    401 => "http_401",
                    403 => "http_403",
                    404 => "http_404",
                    426 => "http_426",
                    429 => "http_429",
                    500 => "http_500",
                    502 => "http_502",
                    503 => "http_503",
                    504 => "http_504",
                    _ => "http_other",
                },
                WsError::Tls(_) => "tls",
                WsError::Io(io) => match io.kind() {
                    std::io::ErrorKind::ConnectionRefused => "connection_refused",
                    std::io::ErrorKind::ConnectionReset => "connection_reset",
                    std::io::ErrorKind::ConnectionAborted => "connection_aborted",
                    std::io::ErrorKind::TimedOut => "io_timeout",
                    std::io::ErrorKind::NotFound => "dns_or_not_found",
                    _ => "io_other",
                },
                WsError::Protocol(_) => "websocket_protocol",
                WsError::Utf8 => "websocket_utf8",
                _ => "websocket_other",
            };
        }
    }
    let msg = format!("{err:#}").to_ascii_lowercase();
    if msg.contains("timeout") {
        "timeout"
    } else if msg.contains("dns") || msg.contains("lookup") || msg.contains("name or service") {
        "dns"
    } else if msg.contains("certificate") || msg.contains("tls") {
        "tls"
    } else {
        "unknown"
    }
}

pub async fn close_backend(mut ws: BackendWs) {
    let _ = ws.send(Message::Close(None)).await;
}