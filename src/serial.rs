//! A VM's serial console, read through PVE's own terminal API - what the PVE web UI's
//! xterm.js console does: `POST termproxy` for a one-time ticket, then the
//! `vncwebsocket` with `user:ticket\n` as the first message, "2" as a keep-alive every
//! 30 seconds, and the console's output as the messages that follow.
//!
//! The Windows bake's WinPE passes write their markers to COM1 - WinPE has no guest agent
//! and the studio cannot read a VM's disk - so this is how the studio hears them.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue, Message};

use crate::{
    form,
    pve::{enc, Pve},
};

#[derive(Deserialize)]
struct TermProxy {
    user: String,
    ticket: String,
    port: serde_json::Value,
}

/// Starts reading serial0; complete lines arrive on the channel until the console closes
/// (the VM stops) or the receiver is dropped.
pub async fn open(pve: &Pve, node: &str, vmid: u32) -> Result<mpsc::UnboundedReceiver<String>> {
    let tp: TermProxy = pve
        .post(&format!("/nodes/{}/qemu/{vmid}/termproxy", enc(node)), form![("serial", "serial0")])
        .await
        .context("opening the serial console")?;
    let port = tp.port.as_u64().or_else(|| tp.port.as_str().and_then(|p| p.parse().ok())).ok_or_else(|| anyhow!("termproxy gave no port"))?;
    let url = format!(
        "{}/api2/json/nodes/{}/qemu/{vmid}/vncwebsocket?port={port}&vncticket={}",
        pve.origin.replacen("https://", "wss://", 1),
        enc(node),
        enc(&tp.ticket)
    );
    let mut req = url.into_client_request()?;
    req.headers_mut().insert("Authorization", HeaderValue::from_str(pve.token_header())?);
    let connector = tokio_tungstenite::Connector::Rustls(pve.ws_tls.clone());
    let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(req, None, false, Some(connector))
        .await
        .context("connecting to the serial console")?;
    let (mut tx, mut rx) = ws.split();
    tx.send(Message::text(format!("{}:{}\n", tp.user, tp.ticket))).await?;
    // termproxy answers the login with "OK" before the console's own output.
    match tokio::time::timeout(Duration::from_secs(10), rx.next()).await {
        Ok(Some(Ok(m))) if m.to_text().map(|t| t.starts_with("OK")).unwrap_or(false) => {}
        Ok(Some(Ok(m))) => bail!("serial console refused the ticket: {m}"),
        _ => bail!("serial console did not answer"),
    }

    let (out, lines) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut ping = tokio::time::interval(Duration::from_secs(30));
        let mut partial = String::new();
        loop {
            tokio::select! {
                _ = ping.tick() => {
                    if tx.send(Message::text("2")).await.is_err() { break; }
                }
                m = rx.next() => {
                    let Some(Ok(m)) = m else { break };
                    let bytes = match m {
                        Message::Binary(b) => b.to_vec(),
                        Message::Text(t) => t.as_bytes().to_vec(),
                        Message::Close(_) => break,
                        _ => continue,
                    };
                    partial.push_str(&String::from_utf8_lossy(&bytes));
                    while let Some(i) = partial.find('\n') {
                        let line: String = partial.drain(..=i).collect();
                        let line = line.trim_end_matches(['\r', '\n']).to_owned();
                        if out.send(line).is_err() { return; }
                    }
                }
            }
        }
        if !partial.trim().is_empty() {
            let _ = out.send(partial.trim_end().to_owned());
        }
    });
    Ok(lines)
}
