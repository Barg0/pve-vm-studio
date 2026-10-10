//! What a PVE node sends and whether the studio would take it: the certificate chain as it
//! comes over the wire (looked at only - the connection is closed before anything is sent),
//! then one API call with the studio's own client and trust - the system's roots, the
//! cluster CA, the added CAs, the pinned certificates, the learned names.

use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use serde::Serialize;

use crate::{cas, config::PveConfig, pve::Pve};

/// One way to the API: the configured one, or a cluster node the studio learned.
#[derive(Debug, Clone)]
pub struct Target {
    pub node: String,
    pub url: String,
    pub tls_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Probe {
    pub node: String,
    pub url: String,
    pub tls_name: Option<String>,
    /// As sent, the node's own certificate first.
    pub chain: Vec<cas::CertSummary>,
    /// The handshake did not happen: no route, refused, timed out.
    pub unreachable: Option<String>,
    pub trusted: bool,
    /// "ca" or "pin" - how it is trusted.
    pub trusted_by: String,
    /// Why not, in the TLS library's words.
    pub trust_error: Option<String>,
    /// The token was accepted (PVE answered /version).
    pub api_ok: bool,
    pub api_error: Option<String>,
    pub pve_version: Option<String>,
}

/// Takes every certificate and lets the handshake finish, so the chain can be shown. Never
/// used for a connection that carries anything.
#[derive(Debug)]
struct Recorder {
    seen: std::sync::Mutex<Vec<Vec<u8>>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end: &rustls::pki_types::CertificateDer<'_>,
        inter: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut s = self.seen.lock().unwrap();
        s.push(end.to_vec());
        s.extend(inter.iter().map(|c| c.to_vec()));
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &rustls::pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &rustls::pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// The chain a node sends, DER, its own certificate first.
pub async fn chain(t: &Target) -> Result<Vec<Vec<u8>>> {
    let url = reqwest::Url::parse(&t.url).with_context(|| format!("'{}' is not a URL", t.url))?;
    let host = url.host_str().context("no host in the URL")?.trim_matches(['[', ']']).to_owned();
    let port = url.port().unwrap_or(8006);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let rec = Arc::new(Recorder { seen: Default::default(), provider: provider.clone() });
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(rec.clone())
        .with_no_client_auth();
    let sni = t.tls_name.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| host.clone());
    let name = rustls::pki_types::ServerName::try_from(sni).map_err(|e| anyhow!("{e}"))?;
    let tcp = tokio::time::timeout(Duration::from_secs(6), tokio::net::TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| anyhow!("{host}:{port} did not answer within 6 s"))?
        .with_context(|| format!("connecting to {host}:{port}"))?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let mut stream = tokio::time::timeout(Duration::from_secs(6), tls.connect(name, tcp))
        .await
        .map_err(|_| anyhow!("{host}:{port}: no TLS handshake within 6 s"))?
        .with_context(|| format!("TLS handshake with {host}:{port}"))?;
    {
        use tokio::io::AsyncWriteExt;
        let _ = stream.shutdown().await;
    }
    let seen = rec.seen.lock().unwrap().clone();
    Ok(seen)
}

/// The chain, and the studio's verdict on it - with `base` (config.toml's [pve]) for the
/// token and the cluster CA.
pub async fn probe(base: &PveConfig, data_dir: &std::path::Path, names: &[String], t: &Target) -> Probe {
    let mut p = Probe {
        node: t.node.clone(),
        url: t.url.clone(),
        tls_name: t.tls_name.clone(),
        chain: vec![],
        unreachable: None,
        trusted: false,
        trusted_by: String::new(),
        trust_error: None,
        api_ok: false,
        api_error: None,
        pve_version: None,
    };
    let ders = match chain(t).await {
        Ok(c) => c,
        Err(e) => {
            p.unreachable = Some(format!("{e:#}"));
            return p;
        }
    };
    p.chain = ders.iter().filter_map(|d| cas::summary(d).ok()).collect();
    let mut cfg = base.clone();
    cfg.url = t.url.clone();
    cfg.tls_name = t.tls_name.clone().filter(|n| !n.is_empty());
    let pve = match Pve::new(&cfg) {
        Ok(p) => p,
        Err(e) => {
            p.trust_error = Some(format!("{e:#}"));
            return p;
        }
    };
    let added: Vec<Vec<u8>> = cas::read_file(&cas::path(data_dir)).into_iter().map(|c| c.der).collect();
    let _ = pve.set_extra_cas(&added);
    let pins = cas::read_pins(data_dir);
    pve.set_pins(cas::pin_digests(&pins));
    pve.learn_names(names.to_vec());
    match tokio::time::timeout(Duration::from_secs(15), pve.version()).await {
        Ok(Ok(v)) => {
            p.trusted = true;
            p.api_ok = true;
            p.pve_version = Some(v.version);
        }
        Ok(Err(e)) => {
            let msg = format!("{e:#}");
            if is_tls_error(&msg) {
                p.trust_error = Some(tls_reason(&msg));
            } else {
                // Past TLS: trusted, but PVE said no (token) or something else failed.
                p.trusted = true;
                p.api_error = Some(msg);
            }
        }
        Err(_) => p.api_error = Some("PVE did not answer within 15 s".into()),
    }
    if p.trusted {
        let leaf = p.chain.first().map(|c| c.fingerprint.clone()).unwrap_or_default();
        p.trusted_by = if pins.iter().any(|x| x.fingerprint == leaf) && !chain_ok_without_pins(base, data_dir, names, t).await { "pin".into() } else { "ca".into() };
    }
    p
}

/// Whether the certificate would also pass without the pins (so "pinned" is only said of
/// the ones the pin carries alone).
async fn chain_ok_without_pins(base: &PveConfig, data_dir: &std::path::Path, names: &[String], t: &Target) -> bool {
    let mut cfg = base.clone();
    cfg.url = t.url.clone();
    cfg.tls_name = t.tls_name.clone().filter(|n| !n.is_empty());
    let Ok(pve) = Pve::new(&cfg) else { return false };
    let added: Vec<Vec<u8>> = cas::read_file(&cas::path(data_dir)).into_iter().map(|c| c.der).collect();
    let _ = pve.set_extra_cas(&added);
    pve.learn_names(names.to_vec());
    match tokio::time::timeout(Duration::from_secs(15), pve.version()).await {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => !is_tls_error(&format!("{e:#}")),
        Err(_) => false,
    }
}

pub fn is_tls_error(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("certificate") || m.contains("unknownissuer") || m.contains("invalid peer") || m.contains("notvalidforname")
}

/// The part of a reqwest error chain that says what was wrong with the certificate.
fn tls_reason(msg: &str) -> String {
    let parts: Vec<&str> = msg.split(": ").collect();
    match parts.iter().position(|p| p.to_ascii_lowercase().contains("certificate")) {
        Some(i) => parts[i..].join(": ").trim().to_owned(),
        None => msg.trim().to_owned(),
    }
}
