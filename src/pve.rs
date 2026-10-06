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
    /// The nodes the API is reached through: the configured one first, then the cluster's
    /// other nodes (learned from PVE, set_nodes). A node that cannot be reached hands the
    /// request to the next one, and the studio stays there.
    endpoints: std::sync::Arc<std::sync::RwLock<Vec<std::sync::Arc<Endpoint>>>>,
    active: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    cfg: std::sync::Arc<PveConfig>,
    /// TLS for that websocket - the same trust as the API client.
    pub ws_tls: std::sync::Arc<rustls::ClientConfig>,
    token_header: String,
    /// /cluster/nextid only suggests an id; two jobs asking at once get the same one. Held
    /// from asking until the VM exists.
    vmid_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}

/// What POST /access/ticket hands back for a user.
#[derive(Debug, Clone, Deserialize, Serialize)]
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

/// One way to the API: a node's address, and the name its certificate is checked for.
pub struct Endpoint {
    /// The node's name, or the configured url for the configured one.
    pub label: String,
    http: reqwest::Client,
    /// Uploads take as long as they take; everything else gets the short client.
    upload_http: reqwest::Client,
    base: String,
    /// "https://node:8006", for the websocket the serial console runs over.
    pub origin: String,
    /// With a tls_name: the address every connection goes to, `origin` naming the
    /// certificate's name instead.
    pub connect_addr: Option<std::net::SocketAddr>,
}

/// A node the API can be reached through (kept in the studio's settings, "pve_nodes").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeEndpoint {
    pub node: String,
    pub ip: String,
    /// The DNS name of its own certificate (ACME or uploaded); "" while it runs on PVE's.
    #[serde(default)]
    pub tls_name: String,
}

impl Endpoint {
    fn new(cfg: &PveConfig, label: &str, url_s: &str, tls_name: Option<&str>) -> Result<Self> {
        // tls_name: requests name the certificate's name, but go to url's address - the
        // certificate is checked for that name, and no DNS lookup is involved.
        let url = reqwest::Url::parse(url_s).with_context(|| format!("[pve] url {url_s}"))?;
        let port = url.port_or_known_default().unwrap_or(8006);
        let tls_name = tls_name.map(str::trim).filter(|n| !n.is_empty());
        let connect_addr = match tls_name {
            Some(_) => {
                use std::net::ToSocketAddrs;
                let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
                Some((host, port).to_socket_addrs().with_context(|| format!("[pve] url {url_s}: no address"))?.next().ok_or_else(|| anyhow!("[pve] url {url_s}: no address"))?)
            }
            None => None,
        };
        let origin = match tls_name {
            Some(name) => format!("https://{name}:{port}"),
            None => url_s.trim_end_matches('/').to_owned(),
        };
        let builder = |timeout: Option<Duration>| -> Result<reqwest::Client> {
            let mut b = reqwest::Client::builder()
                .user_agent(concat!("pve-vm-studio/", env!("CARGO_PKG_VERSION")))
                .connect_timeout(Duration::from_secs(15));
            if let (Some(name), Some(addr)) = (tls_name, connect_addr) {
                b = b.resolve(name, addr);
            }
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
            label: label.to_owned(),
            http: builder(Some(Duration::from_secs(120)))?,
            upload_http: builder(None)?,
            base: format!("{origin}/api2/json"),
            origin,
            connect_addr,
        })
    }
}

impl Pve {
    pub fn new(cfg: &PveConfig) -> Result<Self> {
        let first = Endpoint::new(cfg, &cfg.url, &cfg.url, cfg.tls_name.as_deref())?;
        Ok(Self {
            endpoints: std::sync::Arc::new(std::sync::RwLock::new(vec![std::sync::Arc::new(first)])),
            active: Default::default(),
            cfg: std::sync::Arc::new(cfg.clone()),
            ws_tls: std::sync::Arc::new(ws_tls_config(cfg)?),
            token_header: format!("PVEAPIToken={}={}", cfg.token_id, cfg.token_secret),
            vmid_lock: Default::default(),
        })
    }

    /// The way to the API in use now.
    pub fn endpoint(&self) -> std::sync::Arc<Endpoint> {
        let eps = self.endpoints.read().unwrap();
        eps[self.active.load(std::sync::atomic::Ordering::Relaxed) % eps.len()].clone()
    }

    pub fn endpoint_count(&self) -> usize {
        self.endpoints.read().unwrap().len()
    }

    /// The cluster's other nodes as further ways to the API, behind the configured one.
    /// The configured node itself (by its address) is not added twice.
    pub fn set_nodes(&self, nodes: &[NodeEndpoint]) {
        let configured = reqwest::Url::parse(&self.cfg.url).ok().and_then(|u| u.host_str().map(|h| h.trim_matches(['[', ']']).to_owned())).unwrap_or_default();
        let current = self.endpoint().label.clone();
        let mut eps = vec![self.endpoints.read().unwrap()[0].clone()];
        for n in nodes.iter().filter(|n| !n.ip.is_empty() && n.ip != configured && n.tls_name != configured) {
            let host = if n.ip.contains(':') { format!("[{}]", n.ip) } else { n.ip.clone() };
            match Endpoint::new(&self.cfg, &n.node, &format!("https://{host}:8006"), (!n.tls_name.is_empty()).then_some(n.tls_name.as_str())) {
                Ok(e) => eps.push(std::sync::Arc::new(e)),
                Err(e) => tracing::warn!("PVE node {} as a way to the API: {e:#}", n.node),
            }
        }
        let at = eps.iter().position(|e| e.label == current).unwrap_or(0);
        *self.endpoints.write().unwrap() = eps;
        self.active.store(at, std::sync::atomic::Ordering::Relaxed);
    }

    /// Every node of the cluster with its address and its certificate's name - for
    /// set_nodes, asked of PVE through the way in use.
    pub async fn discover_nodes(&self) -> Result<Vec<NodeEndpoint>> {
        let status = self.cluster_status().await?;
        let mut out = Vec::new();
        for s in status.iter().filter(|s| s.kind == "node") {
            let Some(ip) = s.ip.clone() else { continue };
            let tls_name = if s.online == Some(1) { self.custom_cert_name(&s.name).await.unwrap_or_default() } else { String::new() };
            out.push(NodeEndpoint { node: s.name.clone(), ip, tls_name });
        }
        out.sort_by(|a, b| a.node.cmp(&b.node));
        Ok(out)
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
        let ep = self.endpoint();
        let resp = ep.http.post(format!("{}/access/ticket", ep.base)).form(&form).send().await?;
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
        // pveproxy drops a kept-alive connection now and then ("connection closed before
        // message completed"). A read is simply asked again; a write is not - it may have
        // happened. A node that cannot be connected to at all got nothing: the request goes
        // to the next node (failover), a write too.
        let attempts = if method == Method::GET { 3 } else { 1 };
        let mut attempt = 0;
        let mut tried = 0;
        let mut retried_fork = false;
        let mut ep = self.endpoint();
        loop {
            attempt += 1;
            let url = format!("{}{}", ep.base, path);
            let mut req = ep.http.request(method.clone(), &url);
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
                Ok(resp) => match decode(resp, &method, path).await {
                    // PVE could not fork the task's worker ("got no worker upid - start worker
                    // failed"): nothing ran, so asking once more is safe - a write too. Seen
                    // once in ~90 VM starts, right after another task of the same daemon.
                    Err(e) if !retried_fork && e.to_string().contains("got no worker upid") => {
                        retried_fork = true;
                        tracing::warn!("{method} {path}: PVE could not start its task worker - asking again");
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                    r => return r,
                },
                Err(e) if e.is_connect() && tried + 1 < self.endpoints.read().unwrap().len() => {
                    tried += 1;
                    let next = self.failover(&ep);
                    tracing::warn!("PVE through {} unreachable ({e}) - now through {}", ep.label, next.label);
                    ep = next;
                    attempt = 0;
                }
                Err(e) if attempt < attempts && (e.is_connect() || e.is_request() || e.is_timeout()) => {
                    tokio::time::sleep(Duration::from_millis(500 * attempt)).await;
                }
                Err(e) => return Err(anyhow::Error::from(e).context(format!("{method} {path} (through {})", ep.label))),
            }
        }
    }

    /// The next way to the API after `failed` - made the one in use, unless another
    /// request already moved on.
    fn failover(&self, failed: &Endpoint) -> std::sync::Arc<Endpoint> {
        let eps = self.endpoints.read().unwrap();
        let at = eps.iter().position(|e| e.label == failed.label).unwrap_or(0);
        let next = (at + 1) % eps.len();
        let _ = self.active.compare_exchange(at, next, std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed);
        eps[self.active.load(std::sync::atomic::Ordering::Relaxed) % eps.len()].clone()
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
        let ep = self.endpoint();
        let resp = ep
            .upload_http
            .post(format!("{}{}", ep.base, path))
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

/// rustls for the serial console's websocket: the system's roots plus the configured CA, as
/// for the API client (a PVE with an ACME certificate is signed by a public CA, not by its
/// own), or no checks at all when `insecure` is set.
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
    let (_, unreadable) = roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if unreadable > 0 {
        tracing::debug!("{unreadable} system root certificate(s) could not be read");
    }
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
    /// The resource pool a guest belongs to.
    pub pool: Option<String>,
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

impl Pve {
    /// The DNS name a node's own certificate (pveproxy-ssl.pem: ACME or uploaded) carries -
    /// None while it runs on PVE's self-signed one, which names its address too.
    pub async fn custom_cert_name(&self, node: &str) -> Option<String> {
        let certs: Vec<serde_json::Value> = self.get(&format!("/nodes/{}/certificates/info", enc(node))).await.ok()?;
        let custom = certs.iter().find(|c| c["filename"].as_str() == Some("pveproxy-ssl.pem"))?;
        custom["san"].as_array()?.iter().filter_map(|s| s.as_str()).find(|s| s.parse::<std::net::IpAddr>().is_err() && *s != "localhost" && s.contains('.')).map(str::to_owned)
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

    /// The cluster's storage definitions (type, content, sparse, preallocation...).
    pub async fn storage_configs(&self) -> Result<Vec<Value>> {
        self.get("/storage").await
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

#[cfg(test)]
mod endpoint_tests {
    use super::*;

    fn pve() -> Pve {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Pve::new(&PveConfig {
            url: "https://10.10.0.10:8006".into(),
            token_id: "t@pve!s".into(),
            token_secret: "x".into(),
            ca_file: None,
            tls_name: Some("pve-01.example.com".into()),
            insecure: false,
        })
        .unwrap()
    }

    #[test]
    fn nodes_behind_the_configured_one() {
        let p = pve();
        assert_eq!(p.endpoint().origin, "https://pve-01.example.com:8006");
        let n = |node: &str, ip: &str, name: &str| NodeEndpoint { node: node.into(), ip: ip.into(), tls_name: name.into() };
        // The configured node (by its address) is not added again; the others follow it.
        p.set_nodes(&[n("pve-01", "10.10.0.10", "pve-01.example.com"), n("pve-02", "10.10.0.11", ""), n("pve-03", "10.10.0.12", "pve-03.example.com")]);
        assert_eq!(p.endpoint_count(), 3);
        let eps = p.endpoints.read().unwrap().clone();
        assert_eq!(eps[1].origin, "https://10.10.0.11:8006");
        assert_eq!((eps[2].origin.as_str(), eps[2].connect_addr), ("https://pve-03.example.com:8006", Some("10.10.0.12:8006".parse().unwrap())));
        // Failing over moves on and stays; a refresh keeps the node in use.
        let next = p.failover(&eps[0]);
        assert_eq!(next.label, "pve-02");
        p.set_nodes(&[n("pve-02", "10.10.0.11", ""), n("pve-03", "10.10.0.12", "pve-03.example.com")]);
        assert_eq!(p.endpoint().label, "pve-02");
        // Every way failed: round to the configured one again.
        assert_eq!(p.failover(&p.endpoint()).label, "pve-03");
        assert_eq!(p.failover(&p.endpoint()).label, "https://10.10.0.10:8006");
    }
}
