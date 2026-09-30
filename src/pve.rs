//! A thin client for the Proxmox VE API - typed where the studio uses it, not a full binding.
//!
//! Two ways in: the studio's own API token (background jobs, inventory), and a user's
//! ticket (login, and checking what that user may do). Requests go form-encoded, the one
//! body format every PVE endpoint takes.

use std::{collections::HashMap, path::Path, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use reqwest::{header, Method};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

use crate::config::PveConfig;

#[derive(Clone)]
pub struct Pve {
    http: reqwest::Client,
    /// Uploads take as long as they take; everything else gets the short client.
    upload_http: reqwest::Client,
    base: String,
    /// "https://node:8006", for the websocket the serial console runs over.
    pub origin: String,
    /// TLS for that websocket - the same trust as the API client.
    pub ws_tls: std::sync::Arc<rustls::ClientConfig>,
    token_header: String,
    /// /cluster/nextid only suggests an id; two jobs asking at once get the same one. Held
    /// from asking until the VM exists.
    vmid_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}

/// What POST /access/ticket hands back for a user.
#[derive(Debug, Clone, Deserialize)]
pub struct Ticket {
    pub username: String,
    pub ticket: String,
    #[serde(rename = "CSRFPreventionToken")]
    pub csrf: String,
}

/// PVE wraps every answer in {"data": ...}.
#[derive(Deserialize)]
struct Envelope<T> {
    data: T,
}

/// Form parameters. A key may repeat - that is how PVE takes arrays (agent/exec's command).
pub type Form = Vec<(String, String)>;

/// `form![("name", value), ...]` - values are anything that displays.
#[macro_export]
macro_rules! form {
    ($(($k:expr, $v:expr)),* $(,)?) => {
        vec![$(($k.to_string(), $v.to_string())),*]
    };
}

impl Pve {
    pub fn new(cfg: &PveConfig) -> Result<Self> {
        let builder = |timeout: Option<Duration>| -> Result<reqwest::Client> {
            let mut b = reqwest::Client::builder()
                .user_agent(concat!("pve-vm-studio/", env!("CARGO_PKG_VERSION")))
                .connect_timeout(Duration::from_secs(15));
            if let Some(t) = timeout {
                b = b.timeout(t);
            }
            if let Some(ca) = &cfg.ca_file {
                let pem = std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?;
                b = b.add_root_certificate(reqwest::Certificate::from_pem(&pem)?);
            }
            if cfg.insecure {
                b = b.danger_accept_invalid_certs(true);
            }
            Ok(b.build()?)
        };
        Ok(Self {
            http: builder(Some(Duration::from_secs(120)))?,
            upload_http: builder(None)?,
            base: format!("{}/api2/json", cfg.url.trim_end_matches('/')),
            origin: cfg.url.trim_end_matches('/').to_owned(),
            ws_tls: std::sync::Arc::new(ws_tls_config(cfg)?),
            token_header: format!("PVEAPIToken={}={}", cfg.token_id, cfg.token_secret),
            vmid_lock: Default::default(),
        })
    }

    // ---- as the studio (token) ----

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.call(Method::GET, path, None, Auth::Token).await
    }

    pub async fn get_q<T: DeserializeOwned>(&self, path: &str, query: Form) -> Result<T> {
        let q: Vec<String> = query
            .iter()
            .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
            .collect();
        self.get(&format!("{path}?{}", q.join("&"))).await
    }

    pub async fn post<T: DeserializeOwned>(&self, path: &str, form: Form) -> Result<T> {
        self.call(Method::POST, path, Some(form), Auth::Token).await
    }

    pub async fn put<T: DeserializeOwned>(&self, path: &str, form: Form) -> Result<T> {
        self.call(Method::PUT, path, Some(form), Auth::Token).await
    }

    pub async fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.call(Method::DELETE, path, None, Auth::Token).await
    }

    // ---- as a user ----

    /// Logs a user in with their PVE credentials. `username` carries the realm (root@pam).
    pub async fn login(&self, username: &str, password: &str) -> Result<Ticket> {
        let form = [("username", username), ("password", password)];
        let resp = self
            .http
            .post(format!("{}/access/ticket", self.base))
            .form(&form)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("PVE refused the login ({})", resp.status()));
        }
        Ok(resp.json::<Envelope<Ticket>>().await?.data)
    }

    /// Tickets live two hours; handing one back as the password renews it.
    pub async fn renew(&self, ticket: &Ticket) -> Result<Ticket> {
        self.login(&ticket.username, &ticket.ticket).await
    }

    /// The user's effective privileges: path -> { privilege -> propagate }.
    pub async fn permissions(&self, ticket: &Ticket) -> Result<HashMap<String, HashMap<String, u8>>> {
        self.call(Method::GET, "/access/permissions", None, Auth::User(ticket)).await
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        form: Option<Form>,
        auth: Auth<'_>,
    ) -> Result<T> {
        let url = format!("{}{}", self.base, path);
        // pveproxy drops a kept-alive connection now and then ("connection closed before
        // message completed"). A read is simply asked again; a write is not - it may have
        // happened.
        let attempts = if method == Method::GET { 3 } else { 1 };
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut req = self.http.request(method.clone(), &url);
            req = match auth {
                Auth::Token => req.header(header::AUTHORIZATION, &self.token_header),
                Auth::User(t) => req
                    .header(header::COOKIE, format!("PVEAuthCookie={}", t.ticket))
                    .header("CSRFPreventionToken", &t.csrf),
            };
            if let Some(f) = &form {
                req = req.form(f);
            }
            match req.send().await {
                Ok(resp) => return decode(resp, &method, path).await,
                Err(e) if attempt < attempts && (e.is_connect() || e.is_request() || e.is_timeout()) => {
                    tokio::time::sleep(Duration::from_millis(500 * attempt)).await;
                }
                Err(e) => return Err(anyhow::Error::from(e).context(format!("{method} {path}"))),
            }
        }
    }

    // ---- tasks ----

    /// Waits for a PVE task (an UPID) to end, handing each new log line to `on_line`.
    /// Fails when the task ends in anything but OK.
    pub async fn wait_task<F>(&self, upid: &str, mut on_line: F) -> Result<()>
    where
        F: FnMut(&str),
    {
        let node = upid_node(upid)?;
        let base = format!("/nodes/{}/tasks/{}", enc(node), enc(upid));
        let mut next = 0u64;
        loop {
            let status: TaskStatus = self.get(&format!("{base}/status")).await?;
            let lines: Vec<TaskLine> = self
                .get(&format!("{base}/log?start={next}&limit=500"))
                .await
                .unwrap_or_default();
            for l in lines {
                if l.n > next {
                    next = l.n;
                    // PVE ends the log with its own "TASK OK" line; the status says it.
                    if !l.t.starts_with("TASK ") && !l.t.is_empty() && l.t != "no content" {
                        on_line(&l.t);
                    }
                }
            }
            if status.status == "stopped" {
                return match status.exitstatus.as_deref() {
                    Some("OK") => Ok(()),
                    // "WARNINGS: n" still produced what was asked for.
                    Some(s) if s.starts_with("WARNINGS") => Ok(()),
                    Some(s) => bail!("PVE task failed: {s}"),
                    None => bail!("PVE task ended without a status"),
                };
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// POST that starts a task, then waits for it.
    pub async fn run_task<F: FnMut(&str)>(&self, path: &str, form: Form, on_line: F) -> Result<()> {
        let upid: String = self.post(path, form).await?;
        self.wait_task(&upid, on_line).await
    }

    // ---- storage ----

    pub async fn storage_content(&self, node: &str, storage: &str, content: &str) -> Result<Vec<Volume>> {
        self.get(&format!("/nodes/{}/storage/{}/content?content={}", enc(node), enc(storage), enc(content)))
            .await
    }

    pub async fn delete_volume(&self, node: &str, volid: &str) -> Result<()> {
        let storage = volid.split(':').next().unwrap_or_default();
        let _: Value = self
            .delete(&format!("/nodes/{}/storage/{}/content/{}", enc(node), enc(storage), enc(volid)))
            .await?;
        Ok(())
    }

    /// Uploads a local file (an ISO the studio built) into a storage. Returns the volid.
    pub async fn upload(&self, node: &str, storage: &str, content: &str, file: &Path, name: &str) -> Result<String> {
        let f = tokio::fs::File::open(file).await?;
        let len = f.metadata().await?.len();
        let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(f));
        let part = reqwest::multipart::Part::stream_with_length(body, len)
            .file_name(name.to_owned())
            .mime_str("application/octet-stream")?;
        let multipart = reqwest::multipart::Form::new()
            .text("content", content.to_owned())
            .part("filename", part);
        let path = format!("/nodes/{}/storage/{}/upload", enc(node), enc(storage));
        let resp = self
            .upload_http
            .post(format!("{}{}", self.base, path))
            .header(header::AUTHORIZATION, &self.token_header)
            .multipart(multipart)
            .send()
            .await
            .with_context(|| format!("uploading {name}"))?;
        let upid: String = decode(resp, &Method::POST, &path).await?;
        self.wait_task(&upid, |_| {}).await?;
        Ok(format!("{storage}:{content}/{name}"))
    }

    // ---- VMs ----

    /// Hold this from next_vmid() until the create (or clone) with that id returned.
    pub async fn vmid_guard(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.vmid_lock.lock().await
    }

    pub async fn next_vmid(&self) -> Result<u32> {
        let v: Value = self.get("/cluster/nextid").await?;
        v.as_str()
            .and_then(|s| s.parse().ok())
            .or_else(|| v.as_u64().map(|n| n as u32))
            .ok_or_else(|| anyhow!("unexpected nextid answer {v}"))
    }

    /// The lowest id in `range` no guest uses - golds and bakes live in 9000-9999, so
    /// the tree sorts them below everything else. Hold vmid_guard() around it and the create.
    pub async fn free_vmid_in(&self, range: std::ops::RangeInclusive<u32>) -> Result<u32> {
        let used: std::collections::HashSet<u32> = self
            .resources()
            .await?
            .iter()
            .filter(|r| r.kind == "qemu" || r.kind == "lxc")
            .filter_map(|r| r.vmid)
            .collect();
        range
            .clone()
            .find(|id| !used.contains(id))
            .ok_or_else(|| anyhow!("no free id left in {}-{}", range.start(), range.end()))
    }

    /// Makes sure a resource pool exists.
    pub async fn ensure_pool(&self, pool: &str, comment: &str) -> Result<()> {
        if self.get::<Value>(&format!("/pools/{}", enc(pool))).await.is_ok() {
            return Ok(());
        }
        let _: Value = self.post("/pools", form![("poolid", pool), ("comment", comment)]).await?;
        Ok(())
    }

    pub async fn vm_status(&self, node: &str, vmid: u32) -> Result<VmStatus> {
        self.get(&format!("/nodes/{}/qemu/{vmid}/status/current", enc(node))).await
    }

    pub async fn vm_config(&self, node: &str, vmid: u32) -> Result<HashMap<String, Value>> {
        self.get(&format!("/nodes/{}/qemu/{vmid}/config", enc(node))).await
    }

    /// Changes a VM's config synchronously (PUT), for settings that need no task.
    pub async fn vm_set(&self, node: &str, vmid: u32, form: Form) -> Result<()> {
        let _: Value = self.put(&format!("/nodes/{}/qemu/{vmid}/config", enc(node)), form).await?;
        Ok(())
    }

    /// Changes a VM's config through a task (POST) - what disk allocation and imports need.
    pub async fn vm_set_task<F: FnMut(&str)>(&self, node: &str, vmid: u32, form: Form, on_line: F) -> Result<()> {
        let path = format!("/nodes/{}/qemu/{vmid}/config", enc(node));
        let answer: Value = self.post(&path, form).await?;
        match answer.as_str() {
            Some(upid) if upid.starts_with("UPID:") => self.wait_task(upid, on_line).await,
            _ => Ok(()),
        }
    }

    pub async fn vm_action(&self, node: &str, vmid: u32, action: &str) -> Result<()> {
        self.run_task(&format!("/nodes/{}/qemu/{vmid}/status/{action}", enc(node)), vec![], |_| {})
            .await
    }

    pub async fn vm_resize(&self, node: &str, vmid: u32, disk: &str, size: &str) -> Result<()> {
        let path = format!("/nodes/{}/qemu/{vmid}/resize", enc(node));
        let answer: Value = self.put(&path, form![("disk", disk), ("size", size)]).await?;
        if let Some(upid) = answer.as_str().filter(|s| s.starts_with("UPID:")) {
            self.wait_task(upid, |_| {}).await?;
        }
        Ok(())
    }

    /// Removes a VM and its disks. A running one is stopped first.
    pub async fn vm_destroy(&self, node: &str, vmid: u32) -> Result<()> {
        if let Ok(s) = self.vm_status(node, vmid).await
            && s.status == "running"
        {
            self.vm_action(node, vmid, "stop").await?;
        }
        let upid: String = self
            .delete(&format!("/nodes/{}/qemu/{vmid}?purge=1&destroy-unreferenced-disks=1", enc(node)))
            .await?;
        self.wait_task(&upid, |_| {}).await
    }

    // ---- guest agent ----

    /// True when the guest agent answers.
    pub async fn agent_ping(&self, node: &str, vmid: u32) -> bool {
        self.post::<Value>(&format!("/nodes/{}/qemu/{vmid}/agent/ping", enc(node)), vec![])
            .await
            .is_ok()
    }

    /// Reads up to 1 MiB of a file in the guest from `offset`. Returns the text and how
    /// many bytes it was; None when the file does not exist (or the agent is not up).
    pub async fn agent_read(&self, node: &str, vmid: u32, file: &str, offset: u64) -> Option<(String, u64)> {
        #[derive(Deserialize)]
        struct Read {
            content: String,
        }
        let r: Read = self
            .get_q(
                &format!("/nodes/{}/qemu/{vmid}/agent/file-read", enc(node)),
                form![("file", file), ("offset", offset), ("count", 1u64 << 20)],
            )
            .await
            .ok()?;
        // PVE hands the file's bytes over one character per byte (Latin-1), so UTF-8 text
        // arrives as mojibake until the bytes are put back together.
        let bytes: Vec<u8> = r.content.chars().map(|c| c as u32 as u8).collect();
        let n = bytes.len() as u64;
        Some((String::from_utf8_lossy(&bytes).into_owned(), n))
    }

    /// Runs a command in the guest and waits for it. Returns (exit code, stdout+stderr).
    pub async fn agent_exec(&self, node: &str, vmid: u32, argv: &[&str]) -> Result<(i64, String)> {
        #[derive(Deserialize)]
        struct Started {
            pid: i64,
        }
        #[derive(Deserialize)]
        struct Status {
            exited: Option<u8>,
            exitcode: Option<i64>,
            #[serde(rename = "out-data")]
            out: Option<String>,
            #[serde(rename = "err-data")]
            err: Option<String>,
        }
        let base = format!("/nodes/{}/qemu/{vmid}/agent", enc(node));
        let form: Form = argv.iter().map(|a| ("command".to_owned(), (*a).to_owned())).collect();
        let started: Started = self.post(&format!("{base}/exec"), form).await?;
        for _ in 0..600 {
            let s: Status = self.get(&format!("{base}/exec-status?pid={}", started.pid)).await?;
            if s.exited == Some(1) {
                let out = format!("{}{}", s.out.unwrap_or_default(), s.err.unwrap_or_default());
                return Ok((s.exitcode.unwrap_or(-1), out));
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        bail!("guest command did not finish in 10 minutes: {}", argv.join(" "))
    }

    /// The guest's IPv4 addresses (not loopback), as the agent reports them.
    pub async fn agent_ipv4(&self, node: &str, vmid: u32) -> Vec<String> {
        #[derive(Deserialize)]
        struct Wrap {
            result: Vec<Iface>,
        }
        #[derive(Deserialize)]
        struct Iface {
            name: String,
            #[serde(rename = "ip-addresses", default)]
            ips: Vec<Ip>,
        }
        #[derive(Deserialize)]
        struct Ip {
            #[serde(rename = "ip-address")]
            addr: String,
            #[serde(rename = "ip-address-type")]
            kind: String,
        }
        let Ok(w) = self
            .get::<Wrap>(&format!("/nodes/{}/qemu/{vmid}/agent/network-get-interfaces", enc(node)))
            .await
        else {
            return vec![];
        };
        w.result
            .into_iter()
            .filter(|i| i.name != "lo")
            .flat_map(|i| i.ips)
            .filter(|ip| ip.kind == "ipv4" && !ip.addr.starts_with("127."))
            .map(|ip| ip.addr)
            .collect()
    }
}

/// rustls for the serial console's websocket: the configured CA, or no checks at all when
/// `insecure` is set (as for the API client).
fn ws_tls_config(cfg: &PveConfig) -> Result<rustls::ClientConfig> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions()?;
    if cfg.insecure {
        return Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify(provider)))
            .with_no_client_auth());
    }
    let mut roots = rustls::RootCertStore::empty();
    if let Some(ca) = &cfg.ca_file {
        use rustls::pki_types::{pem::PemObject, CertificateDer};
        for c in CertificateDer::pem_file_iter(ca)? {
            roots.add(c?)?;
        }
    }
    Ok(builder.with_root_certificates(roots).with_no_client_auth())
}

#[derive(Debug)]
struct NoVerify(std::sync::Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

impl Pve {
    pub fn token_header(&self) -> &str {
        &self.token_header
    }
}

async fn decode<T: DeserializeOwned>(resp: reqwest::Response, method: &Method, path: &str) -> Result<T> {
    let status = resp.status();
    if !status.is_success() {
        // PVE puts the reason in the status line and the details in "errors".
        let reason = status.canonical_reason().unwrap_or("");
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("{method} {path}: {} {reason} {text}", status.as_u16()));
    }
    let env: Envelope<T> = resp
        .json()
        .await
        .with_context(|| format!("{method} {path}: unexpected answer"))?;
    Ok(env.data)
}

enum Auth<'a> {
    Token,
    User(&'a Ticket),
}

fn upid_node(upid: &str) -> Result<&str> {
    upid.split(':').nth(1).filter(|n| !n.is_empty()).ok_or_else(|| anyhow!("not a UPID: {upid}"))
}

#[derive(Deserialize)]
struct TaskStatus {
    status: String,
    exitstatus: Option<String>,
}

#[derive(Deserialize)]
struct TaskLine {
    n: u64,
    t: String,
}

// ---- the parts of the API the inventory and jobs read ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub version: String,
    pub release: String,
}

/// One row of GET /cluster/resources. The API mixes nodes, guests, storages and SDN
/// objects in one list; the fields each type does not have stay None.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub node: Option<String>,
    pub status: Option<String>,
    pub name: Option<String>,
    pub vmid: Option<u32>,
    pub template: Option<u8>,
    pub storage: Option<String>,
    pub content: Option<String>,
    pub shared: Option<u8>,
    pub plugintype: Option<String>,
    pub sdn: Option<String>,
    pub tags: Option<String>,
    pub cpu: Option<f64>,
    pub maxcpu: Option<f64>,
    pub mem: Option<u64>,
    pub maxmem: Option<u64>,
    pub disk: Option<u64>,
    pub maxdisk: Option<u64>,
    pub uptime: Option<u64>,
}

impl Resource {
    pub fn has_content(&self, c: &str) -> bool {
        self.content.as_deref().unwrap_or("").split(',').any(|x| x == c)
    }
}

/// One row of GET /cluster/status: the cluster itself, or a node's membership.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStatus {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    pub quorate: Option<u8>,
    pub nodes: Option<u32>,
    pub online: Option<u8>,
    pub ip: Option<String>,
    pub local: Option<u8>,
}

/// A bridge on a node (GET /nodes/{node}/network?type=any_bridge).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bridge {
    pub iface: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub active: Option<u8>,
    pub cidr: Option<String>,
    pub comments: Option<String>,
    pub bridge_vlan_aware: Option<u8>,
}

/// An SDN VNet (GET /cluster/sdn/vnets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vnet {
    pub vnet: String,
    pub zone: Option<String>,
    pub tag: Option<u32>,
    pub alias: Option<String>,
}

/// A file in a storage (GET /nodes/{node}/storage/{storage}/content).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Volume {
    pub volid: String,
    pub size: Option<u64>,
    pub format: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmStatus {
    pub status: String,
    pub name: Option<String>,
    pub template: Option<u8>,
}

impl Pve {
    pub async fn version(&self) -> Result<Version> {
        self.get("/version").await
    }

    pub async fn resources(&self) -> Result<Vec<Resource>> {
        self.get("/cluster/resources").await
    }

    pub async fn cluster_status(&self) -> Result<Vec<ClusterStatus>> {
        self.get("/cluster/status").await
    }

    pub async fn bridges(&self, node: &str) -> Result<Vec<Bridge>> {
        self.get(&format!("/nodes/{}/network?type=any_bridge", enc(node))).await
    }

    /// SDN is optional; a cluster without it answers with an error, which means "none".
    pub async fn vnets(&self) -> Vec<Vnet> {
        self.get::<Vec<Vnet>>("/cluster/sdn/vnets").await.unwrap_or_default()
    }
}

pub fn enc(s: &str) -> String {
    urlencoding::encode(s).into_owned()
}
