//! The studio's own certificate: self-signed out of the box, an imported one, or one from
//! Let's Encrypt that renews itself.
//!
//! The certificate the server presents always lives in <data_dir>/tls/{cert,key}.pem and
//! is swapped in without a restart (RustlsConfig::reload). The ACME client is lego
//! (Debian's `lego` package): one client for HTTP-01 and for DNS-01 through any of its
//! 100+ DNS providers (IONOS, INWX, Cloudflare, RFC 2136...), credentials passed as the
//! environment variables `lego dnshelp -c <provider>` names. It runs as the studio's own
//! user with its data under <data_dir>/lego; HTTP-01 answers from a webroot the port-80
//! listener serves.

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::{
    jobs::{JobLog, Tag},
    settings,
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsSettings {
    /// self-signed | imported | acme
    pub mode: String,
    pub acme: AcmeSettings,
    /// When the renewal last ran and what it said.
    pub last_check: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AcmeSettings {
    pub email: String,
    /// http-01 | dns-01
    pub challenge: String,
    pub dns_provider: String,
    pub staging: bool,
}

/// The name the studio is reached by. Everything else follows it: the certificate, the
/// link in the PVE notes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerSettings {
    pub fqdn: String,
}

pub struct Paths {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub lego: PathBuf,
    pub webroot: PathBuf,
}

impl Paths {
    pub fn new(data: &Path) -> Self {
        Self {
            cert: data.join("tls/cert.pem"),
            key: data.join("tls/key.pem"),
            lego: data.join("lego"),
            webroot: data.join("acme-webroot"),
        }
    }

    fn credentials(&self, provider: &str) -> PathBuf {
        self.lego.join(format!("{provider}.env"))
    }
}

/// What the page shows about the certificate in use.
#[derive(Debug, Clone, Serialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub names: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub days_left: i64,
    pub self_signed: bool,
}

pub fn cert_info(pem: &[u8]) -> Result<CertInfo> {
    let (_, p) = x509_parser::pem::parse_x509_pem(pem).map_err(|e| anyhow!("not a PEM certificate: {e}"))?;
    let cert = p.parse_x509().map_err(|e| anyhow!("unreadable certificate: {e}"))?;
    let mut names = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for n in &san.value.general_names {
            match n {
                x509_parser::extensions::GeneralName::DNSName(d) => names.push(d.to_string()),
                x509_parser::extensions::GeneralName::IPAddress(b) if b.len() == 4 => {
                    names.push(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
                }
                _ => {}
            }
        }
    }
    let not_after = cert.validity().not_after.timestamp();
    let now = chrono::Utc::now().timestamp();
    let ts = |t: i64| chrono::DateTime::from_timestamp(t, 0).map(|d| d.to_rfc3339()).unwrap_or_default();
    Ok(CertInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        names,
        not_before: ts(cert.validity().not_before.timestamp()),
        not_after: ts(not_after),
        days_left: (not_after - now) / 86400,
        self_signed: cert.subject() == cert.issuer(),
    })
}

/// A self-signed certificate for the studio's name and addresses, valid ten years.
pub fn self_signed(names: &[String]) -> Result<(String, String)> {
    let mut params = rcgen::CertificateParams::new(names.to_vec())?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, names.first().cloned().unwrap_or_else(|| "pve-vm-studio".into()));
    dn.push(rcgen::DnType::OrganizationName, "PVE VM Studio (self-signed)");
    params.distinguished_name = dn;
    use chrono::Datelike;
    let today = chrono::Utc::now().date_naive();
    params.not_before = rcgen::date_time_ymd(today.year(), today.month() as u8, today.day() as u8);
    params.not_after = rcgen::date_time_ymd(today.year() + 10, today.month() as u8, today.day().min(28) as u8);
    let key = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// The names a self-signed certificate should carry: the FQDN, the short host name and
/// this machine's addresses.
pub fn local_names(fqdn: &str) -> Vec<String> {
    let mut names = Vec::new();
    if !fqdn.is_empty() {
        names.push(fqdn.to_owned());
    }
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        let h = h.trim().to_owned();
        if !h.is_empty() && !names.contains(&h) {
            names.push(h);
        }
    }
    if let Ok(out) = std::process::Command::new("hostname").arg("-I").output() {
        for ip in String::from_utf8_lossy(&out.stdout).split_whitespace() {
            if ip.parse::<std::net::Ipv4Addr>().is_ok() && !names.iter().any(|n| n == ip) {
                names.push(ip.to_owned());
            }
        }
    }
    if names.is_empty() {
        names.push("pve-vm-studio".into());
    }
    names
}

/// Makes sure a certificate exists - a first start gets a self-signed one.
pub async fn ensure(paths: &Paths, fqdn: &str) -> Result<()> {
    if paths.cert.exists() && paths.key.exists() {
        return Ok(());
    }
    let (cert, key) = self_signed(&local_names(fqdn))?;
    write_pair(paths, cert.as_bytes(), key.as_bytes()).await?;
    tracing::info!("created a self-signed certificate");
    Ok(())
}

async fn write_pair(paths: &Paths, cert: &[u8], key: &[u8]) -> Result<()> {
    if let Some(d) = paths.cert.parent() {
        tokio::fs::create_dir_all(d).await?;
    }
    // Written beside and renamed over, so a reader never sees half a file.
    let (tc, tk) = (paths.cert.with_extension("pem.new"), paths.key.with_extension("pem.new"));
    tokio::fs::write(&tc, cert).await?;
    write_private(&tk, key).await?;
    tokio::fs::rename(&tk, &paths.key).await?;
    tokio::fs::rename(&tc, &paths.cert).await?;
    Ok(())
}

async fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = path.to_owned();
    let data = data.to_owned();
    tokio::task::spawn_blocking(move || -> Result<()> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&path)?;
        f.write_all(&data)?;
        Ok(())
    })
    .await?
}

/// Checks a certificate and key, installs them and swaps them in.
pub async fn install(paths: &Paths, live: Option<&RustlsConfig>, cert: &[u8], key: &[u8]) -> Result<CertInfo> {
    let info = cert_info(cert)?;
    // rustls refuses a key that does not match the certificate, or that it cannot read.
    RustlsConfig::from_pem(cert.to_vec(), key.to_vec())
        .await
        .context("the certificate and key do not form a usable pair")?;
    write_pair(paths, cert, key).await?;
    if let Some(l) = live {
        l.reload_from_pem_file(&paths.cert, &paths.key).await?;
    }
    Ok(info)
}

// ---- Let's Encrypt (lego) ----

const LE_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
const LE_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// lego's DNS provider codes, from `lego dnshelp`.
pub async fn dns_providers() -> Vec<String> {
    let Ok(out) = tokio::process::Command::new("lego").arg("dnshelp").output().await else {
        return vec![];
    };
    let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    let Some(list) = text.split("All DNS codes:").nth(1) else { return vec![] };
    list.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .split(',')
        .map(|c| c.trim().to_owned())
        .filter(|c| !c.is_empty() && c.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-'))
        .collect()
}

/// What a provider needs, as lego explains it (`lego dnshelp -c <code>`).
pub async fn provider_help(code: &str) -> Result<String> {
    if code.is_empty() || !code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        bail!("unknown DNS provider '{code}'");
    }
    let out = tokio::process::Command::new("lego").args(["dnshelp", "-c", code]).output().await.context("running lego - is it installed?")?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if text.is_empty() {
        bail!("lego knows no DNS provider '{code}'");
    }
    Ok(text)
}

/// Saves a DNS provider's credentials: KEY=VALUE lines, as lego reads them from the
/// environment (0600, never shown again).
pub async fn save_credentials(paths: &Paths, provider: &str, text: &str) -> Result<()> {
    provider_help(provider).await?;
    let mut clean = String::new();
    for (i, line) in text.lines().map(str::trim).enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("line {}: expected KEY=value", i + 1))?;
        let k = k.trim();
        if k.is_empty() || !k.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
            bail!("line {}: '{k}' is not an environment variable name", i + 1);
        }
        clean += &format!("{k}={}\n", v.trim().trim_matches('"'));
    }
    if clean.is_empty() {
        bail!("no KEY=value lines");
    }
    tokio::fs::create_dir_all(&paths.lego).await?;
    write_private(&paths.credentials(provider), clean.as_bytes()).await
}

pub fn has_credentials(paths: &Paths, provider: &str) -> bool {
    paths.credentials(provider).exists()
}

async fn credentials_env(paths: &Paths, provider: &str) -> Result<Vec<(String, String)>> {
    let text = tokio::fs::read_to_string(paths.credentials(provider))
        .await
        .with_context(|| format!("no credentials saved for {provider}"))?;
    Ok(text
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect())
}

/// lego's arguments for one certificate, shared by `run` and `renew`.
async fn lego_args(paths: &Paths, fqdn: &str, acme: &AcmeSettings) -> Result<(Vec<String>, Vec<(String, String)>)> {
    let mut args: Vec<String> = vec![
        "--accept-tos".into(),
        "--email".into(),
        acme.email.clone(),
        "--path".into(),
        paths.lego.display().to_string(),
        "--key-type".into(),
        "ec256".into(),
        "--domains".into(),
        fqdn.to_owned(),
        "--server".into(),
        if acme.staging { LE_STAGING } else { LE_PRODUCTION }.into(),
    ];
    let mut env = Vec::new();
    if acme.challenge == "dns-01" {
        env = credentials_env(paths, &acme.dns_provider).await?;
        args.extend(["--dns".into(), acme.dns_provider.clone()]);
        // Public resolvers for the propagation check: a lab's own DNS often answers for
        // the zone itself (split horizon) and would never show the TXT record.
        args.extend(["--dns.resolvers".into(), "1.1.1.1:53".into(), "--dns.resolvers".into(), "9.9.9.9:53".into()]);
    } else {
        tokio::fs::create_dir_all(&paths.webroot).await?;
        args.extend(["--http".into(), "--http.webroot".into(), paths.webroot.display().to_string()]);
    }
    Ok((args, env))
}

async fn run_lego(args: Vec<String>, env: Vec<(String, String)>, log: Option<&JobLog>) -> Result<()> {
    let mut child = tokio::process::Command::new("lego")
        .args(&args)
        .envs(env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running lego - is it installed?")?;
    let (out, err) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let mut lines = tokio_stream::StreamExt::merge(
        tokio_stream::wrappers::LinesStream::new(BufReader::new(out).lines()),
        tokio_stream::wrappers::LinesStream::new(BufReader::new(err).lines()),
    );
    let mut last = String::new();
    while let Some(Ok(l)) = tokio_stream::StreamExt::next(&mut lines).await {
        if l.trim().is_empty() {
            continue;
        }
        last = l.clone();
        if let Some(log) = log {
            log.debug(format!("lego | {l}")).await;
        }
    }
    if !child.wait().await?.success() {
        bail!("lego failed: {last}");
    }
    Ok(())
}

/// Obtains a certificate for `fqdn` and installs it.
pub async fn acme_issue(
    paths: &Paths,
    live: Option<&RustlsConfig>,
    fqdn: &str,
    acme: &AcmeSettings,
    log: &JobLog,
) -> Result<CertInfo> {
    if fqdn.is_empty() || !fqdn.contains('.') {
        bail!("Let's Encrypt needs a fully qualified DNS name for the studio - set it first");
    }
    if !acme.email.contains('@') {
        bail!("Let's Encrypt needs a contact e-mail address");
    }
    let (mut args, env) = lego_args(paths, fqdn, acme).await?;
    if acme.challenge == "dns-01" {
        log.tag(Tag::Run, format!("Let's Encrypt, DNS-01 through {}, for {fqdn}", acme.dns_provider)).await;
    } else {
        log.tag(Tag::Run, format!("Let's Encrypt, HTTP-01 on port 80, for {fqdn}")).await;
    }
    if acme.staging {
        log.warn("Staging: the certificate will not be trusted by browsers - for testing the setup only").await;
    }
    // lego reports no progress of its own; the bar marks the two steps there are.
    log.progress("Let's Encrypt", Some(10.0), "ordering and validating");
    args.push("run".into());
    run_lego(args, env, Some(log)).await?;
    log.progress("Let's Encrypt", Some(90.0), "installing the certificate");
    let info = install_from_lego(paths, live, fqdn).await?;
    log.ok(format!("Certificate for {} from {}, valid until {}", info.names.join(", "), info.issuer, info.not_after)).await;
    Ok(info)
}

async fn install_from_lego(paths: &Paths, live: Option<&RustlsConfig>, fqdn: &str) -> Result<CertInfo> {
    let dir = paths.lego.join("certificates");
    // lego writes the certificate with its chain (a bundle) by default.
    let cert = tokio::fs::read(dir.join(format!("{fqdn}.crt"))).await.context("lego left no certificate")?;
    let key = tokio::fs::read(dir.join(format!("{fqdn}.key"))).await?;
    install(paths, live, &cert, &key).await
}

/// Twice a day: lego renews a certificate within 30 days of expiry, and a renewed one is
/// swapped in. Runs for the life of the process.
pub async fn renew_loop(db: SqlitePool, paths: Paths, live: Option<RustlsConfig>) {
    loop {
        tokio::time::sleep(Duration::from_secs(12 * 3600)).await;
        let mut s: TlsSettings = match settings::load(&db, "tls").await {
            Ok(s) => s,
            Err(_) => continue,
        };
        if s.mode != "acme" {
            continue;
        }
        let server: ServerSettings = settings::load(&db, "server").await.unwrap_or_default();
        let before = tokio::fs::read(&paths.cert).await.unwrap_or_default();
        let result = async {
            let (mut args, env) = lego_args(&paths, &server.fqdn, &s.acme).await?;
            args.extend(["renew".into(), "--days".into(), "30".into()]);
            run_lego(args, env, None).await?;
            let fresh = tokio::fs::read(paths.lego.join(format!("certificates/{}.crt", server.fqdn))).await?;
            if fresh != before {
                let info = install_from_lego(&paths, live.as_ref(), &server.fqdn).await?;
                tracing::info!("renewed certificate installed, valid until {}", info.not_after);
            }
            anyhow::Ok(())
        }
        .await;
        s.last_check = Some(chrono::Utc::now().to_rfc3339());
        s.last_error = result.err().map(|e| format!("{e:#}"));
        if let Some(e) = &s.last_error {
            tracing::error!("certificate renewal: {e}");
        }
        let _ = settings::save(&db, "tls", &s).await;
    }
}
