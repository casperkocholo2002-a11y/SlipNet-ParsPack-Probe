use anyhow::{Context, Result};
use futures_util::SinkExt;
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use std::{sync::Arc, time::Duration};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};
use tokio_tungstenite::{
    client_async_tls_with_config,
    connect_async,
    tungstenite::{client::IntoClientRequest, Message},
    Connector, MaybeTlsStream, WebSocketStream,
};

use crate::config::{origin_config, DirectConfig};

pub type BackendWs = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

fn tls_config(send_sni: bool) -> ClientConfig {
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
    let server_name = ServerName::try_from(servername.clone()).context("invalid origin servername")?;
    let connector = TlsConnector::from(Arc::new(tls_config(false)));
    let tls = tokio::time::timeout(
        Duration::from_secs(15),
        connector.connect(server_name, tcp),
    )
    .await
    .context("tls handshake timeout")??;
    Ok(tls)
}

pub async fn dial_direct_ws(config: &DirectConfig) -> Result<BackendWs> {
    if !config.valid() {
        anyhow::bail!("direct_not_configured");
    }

    let tcp = tcp_connect(&config.host, config.port, Duration::from_secs(5)).await?;
    let request = config
        .websocket_url()
        .into_client_request()
        .context("direct websocket request")?;
    let connector = Connector::Rustls(Arc::new(tls_config(true)));
    let (ws, _) = tokio::time::timeout(
        Duration::from_secs(5),
        client_async_tls_with_config(request, tcp, None, Some(connector)),
    )
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

pub async fn close_backend(mut ws: BackendWs) {
    let _ = ws.send(Message::Close(None)).await;
}
