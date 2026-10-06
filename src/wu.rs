//! Which builds Microsoft released as security updates - from Microsoft Update itself, the
//! way WSUS and Configuration Manager learn it: the server-to-server sync protocol
//! ([MS-WSUSSS], Microsoft's open specification; Microsoft's own client is
//! github.com/microsoft/update-server-server-sync). Anonymous, no WSUS server:
//!
//!   GetAuthConfig -> GetAuthorizationCookie (DssAuthWebService, the all-zero account)
//!   -> GetCookie (an hour) -> GetRevisionIdList (a product, the Security Updates
//!   classification) -> GetUpdateData (100 at a time): each update's metadata, its build as
//!   a field (ReleaseVersion="10.0.26200.9445"), KB, title, publication state, date.
//!
//! The sync list carries what Microsoft ships to companies: the Patch Tuesday (B) and
//! out-of-band security updates. A preview (D) or a Release Preview build is never in it -
//! measured 2026-10-06: 26200.9445 and .9457 listed, .9550 (D) and .9539 (Release Preview) not.
//! The answers stay on disk (wu-security.json); a sync asks only for updates it has not seen.

use std::{collections::HashMap, path::Path};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

const ROOT: &str = "https://sws.update.microsoft.com";
const NS: &str = "http://www.microsoft.com/SoftwareDistribution";
const DSS: &str = "http://www.microsoft.com/SoftwareDistribution/Server/DssAuthWebService";
/// sws.update.microsoft.com chains to Microsoft's own root, which the usual trust stores do
/// not carry (sha256 84:7D:F6:A7:...:07:ED:7C:61, valid to 2036): pinned, nothing else trusted.
const MS_ROOT_2011: &[u8] = include_bytes!("ms-root-2011.pem");
/// Microsoft Update's "Security Updates" classification.
const SECURITY: &str = "0fa1201d-4330-4fa8-8ae9-b877473b6441";

/// The Microsoft Update product a studio product's builds are listed under.
pub fn category(product_id: &str) -> Option<&'static str> {
    match product_id {
        p if p.starts_with("w11-") && !p.contains("canary") && !p.contains("dev") => Some("72e7624a-5b00-45d2-b92f-e561c0a6a160"), // Windows 11
        "ws2025" => Some("b256987d-4693-4c87-955d-dbb9341205eb"), // Microsoft Server Operating System-24H2
        "ws2022" => Some("71718f13-7324-4b0f-8f9e-2ca9dc978e53"), // Microsoft Server operating system-21H2
        _ => None,
    }
}
const CATEGORIES: [&str; 3] = ["72e7624a-5b00-45d2-b92f-e561c0a6a160", "b256987d-4693-4c87-955d-dbb9341205eb", "71718f13-7324-4b0f-8f9e-2ca9dc978e53"];

/// One security update as Microsoft Update lists it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Update {
    pub id: String,
    pub rev: u32,
    pub kb: String,
    pub title: String,
    /// 26200.9445 (ReleaseVersion without its 10.0.), empty when the update names none.
    pub build: String,
    /// When Microsoft published it (CreationDate).
    pub created: String,
    /// "Published", "Expired".
    pub state: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Index {
    /// Per category: when it was synced last (RFC 3339).
    pub synced: HashMap<String, String>,
    pub updates: Vec<Update>,
}

impl Index {
    /// The published security update for a build, if Microsoft released one.
    pub fn security(&self, build: &str) -> Option<&Update> {
        // The update itself ("2026-09 Cumulative Update ... (KB5124008)") before its child
        // revisions ("all Child Revision for ...", "Windows10.0-KB5122882-x64"), which carry the
        // same build; the first published among them.
        let titled = |u: &Update| u.title.get(..5).is_some_and(|t| t.ends_with('-') && t[..4].chars().all(|c| c.is_ascii_digit()));
        self.updates.iter().filter(|u| u.build == build && u.state != "Expired").min_by(|a, b| titled(b).cmp(&titled(a)).then(a.created.cmp(&b.created)))
    }
}

static INDEX: std::sync::RwLock<Option<Index>> = std::sync::RwLock::new(None);
static SYNCING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether Microsoft Update has answered for this category yet (its labels are facts, not
/// estimates), and whether a sync runs right now.
pub fn checked(category: &str) -> bool {
    INDEX.read().ok().and_then(|g| g.as_ref().map(|i| i.synced.contains_key(category))).unwrap_or(false)
}
pub fn syncing() -> bool {
    SYNCING.load(std::sync::atomic::Ordering::Relaxed)
}

/// Clears the syncing flag however the sync ends.
struct Syncing;
impl Drop for Syncing {
    fn drop(&mut self) {
        SYNCING.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}
static SYNC: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// What Microsoft Update said about a build: None while this category was never synced,
/// Some(None) when it lists no security update for the build, Some(Some(update)) when it does.
pub fn lookup(category: &str, build: &str) -> Option<Option<Update>> {
    let g = INDEX.read().ok()?;
    let idx = g.as_ref()?;
    idx.synced.contains_key(category).then(|| idx.security(build).cloned())
}

fn path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("wu-security.json")
}

/// Loads what an earlier sync left on disk.
pub async fn load(data_dir: &Path) {
    if let Ok(raw) = tokio::fs::read(path(data_dir)).await
        && let Ok(idx) = serde_json::from_slice::<Index>(&raw)
        && let Ok(mut g) = INDEX.write()
    {
        *g = Some(idx);
    }
}

/// Syncs when the last sync is older than `max_age` (or never ran). A failure keeps what
/// there is and says so in the service log.
pub async fn refresh(data_dir: &Path, max_age: std::time::Duration) -> Result<()> {
    let _one = SYNC.lock().await;
    let mut idx = INDEX.read().ok().and_then(|g| g.clone()).unwrap_or_default();
    let stale = CATEGORIES.iter().any(|c| {
        idx.synced
            .get(*c)
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .is_none_or(|t| chrono::Utc::now().signed_duration_since(t).to_std().unwrap_or_default() > max_age)
    });
    if !stale {
        return Ok(());
    }
    SYNCING.store(true, std::sync::atomic::Ordering::Relaxed);
    let _flag = Syncing;
    let client = Client::new()?;
    let cookie = client.auth().await?;
    for cat in CATEGORIES {
        let ids = client.revision_ids(&cookie, cat).await.with_context(|| format!("listing the security updates of {cat}"))?;
        let new: Vec<(String, u32)> = ids.into_iter().filter(|(id, rev)| !idx.updates.iter().any(|u| u.id == *id && u.rev == *rev)).collect();
        for chunk in new.chunks(100) {
            for blob in client.update_data(&cookie, chunk).await? {
                if let Some(u) = parse(&blob.0, blob.1, &blob.2) {
                    idx.updates.push(u);
                }
            }
        }
        idx.synced.insert(cat.to_owned(), chrono::Utc::now().to_rfc3339());
    }
    tokio::fs::write(path(data_dir), serde_json::to_vec(&idx)?).await?;
    tracing::info!("Microsoft Update: {} security update(s) known", idx.updates.len());
    if let Ok(mut g) = INDEX.write() {
        *g = Some(idx);
    }
    Ok(())
}

struct Client {
    web: reqwest::Client,
}

impl Client {
    fn new() -> Result<Self> {
        let root = reqwest::Certificate::from_pem(MS_ROOT_2011)?;
        let web = reqwest::Client::builder().tls_certs_only([root]).timeout(std::time::Duration::from_secs(300)).user_agent("PVE VM Studio").build()?;
        Ok(Self { web })
    }

    async fn soap(&self, url: &str, ns: &str, action: &str, body: &str) -> Result<String> {
        let env = format!(r#"<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>{body}</s:Body></s:Envelope>"#);
        let resp = self
            .web
            .post(url)
            .header("Content-Type", "text/xml; charset=utf-8")
            .header("SOAPAction", format!("\"{ns}/{action}\""))
            .body(env)
            .send()
            .await
            .with_context(|| format!("asking Microsoft Update ({action})"))?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            bail!("Microsoft Update answered {action} with HTTP {status}: {}", tag(&text, "faultstring").unwrap_or_default());
        }
        Ok(text)
    }

    async fn auth(&self) -> Result<String> {
        let sync = format!("{ROOT}/ServerSyncWebService/ServerSyncWebService.asmx");
        let r = self.soap(&sync, NS, "GetAuthConfig", &format!(r#"<GetAuthConfig xmlns="{NS}"><protocolVersion>1.7</protocolVersion></GetAuthConfig>"#)).await?;
        let svc = tag(&r, "ServiceUrl").ok_or_else(|| anyhow!("Microsoft Update named no authorization service"))?;
        let zero = "00000000-0000-0000-0000-000000000000";
        let r = self
            .soap(&format!("{ROOT}/{svc}"), DSS, "GetAuthorizationCookie", &format!(r#"<GetAuthorizationCookie xmlns="{DSS}"><accountName>{zero}</accountName><accountGuid>{zero}</accountGuid></GetAuthorizationCookie>"#))
            .await?;
        let (pid, data) = (tag(&r, "PlugInId").unwrap_or_default(), tag(&r, "CookieData").ok_or_else(|| anyhow!("no authorization cookie"))?);
        let r = self
            .soap(&sync, NS, "GetCookie", &format!(r#"<GetCookie xmlns="{NS}"><authCookies><AuthorizationCookie><PlugInId>{pid}</PlugInId><CookieData>{data}</CookieData></AuthorizationCookie></authCookies><protocolVersion>1.7</protocolVersion></GetCookie>"#))
            .await?;
        let (exp, enc) = (tag(&r, "Expiration").unwrap_or_default(), tag(&r, "EncryptedData").ok_or_else(|| anyhow!("no access cookie"))?);
        Ok(format!("<cookie><Expiration>{exp}</Expiration><EncryptedData>{enc}</EncryptedData></cookie>"))
    }

    /// Every revision of a product's security updates. Child order matters to the service;
    /// without a classification it lists nothing.
    async fn revision_ids(&self, cookie: &str, category: &str) -> Result<Vec<(String, u32)>> {
        let filter = format!(
            "<GetConfig>false</GetConfig><Get63LanguageOnly>false</Get63LanguageOnly><Categories><IdAndDelta><Id>{category}</Id><Delta>false</Delta></IdAndDelta></Categories><Classifications><IdAndDelta><Id>{SECURITY}</Id><Delta>false</Delta></IdAndDelta></Classifications>"
        );
        let r = self.soap(&format!("{ROOT}/ServerSyncWebService/ServerSyncWebService.asmx"), NS, "GetRevisionIdList", &format!(r#"<GetRevisionIdList xmlns="{NS}">{cookie}<filter>{filter}</filter></GetRevisionIdList>"#)).await?;
        Ok(r.split("<UpdateIdentity>")
            .skip(1)
            .filter_map(|s| Some((tag(s, "UpdateID")?.to_lowercase(), tag(s, "RevisionNumber")?.parse().ok()?)))
            .collect())
    }

    /// (id, rev, metadata XML) for each update; a compressed blob (a CAB of UTF-16 XML,
    /// rare) is opened with cabextract.
    async fn update_data(&self, cookie: &str, ids: &[(String, u32)]) -> Result<Vec<(String, u32, String)>> {
        let body: String = ids.iter().map(|(u, r)| format!("<UpdateIdentity><UpdateID>{u}</UpdateID><RevisionNumber>{r}</RevisionNumber></UpdateIdentity>")).collect();
        let r = self.soap(&format!("{ROOT}/ServerSyncWebService/ServerSyncWebService.asmx"), NS, "GetUpdateData", &format!(r#"<GetUpdateData xmlns="{NS}">{cookie}<updateIds>{body}</updateIds></GetUpdateData>"#)).await?;
        let mut out = Vec::new();
        for item in r.split("<ServerSyncUpdateData>").skip(1) {
            let (Some(id), Some(rev)) = (tag(item, "UpdateID"), tag(item, "RevisionNumber").and_then(|r| r.parse().ok())) else { continue };
            let xml = if let Some(x) = tag(item, "XmlUpdateBlob") {
                unescape(&x)
            } else if let Some(c) = tag(item, "XmlUpdateBlobCompressed") {
                match uncab(&c).await {
                    Ok(x) => x,
                    Err(_) => continue,
                }
            } else {
                continue;
            };
            out.push((id.to_lowercase(), rev, xml));
        }
        Ok(out)
    }
}

async fn uncab(b64: &str) -> Result<String> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD.decode(b64.trim())?;
    let tmp = std::env::temp_dir().join(format!("wu-{}.cab", uuid::Uuid::new_v4().simple()));
    tokio::fs::write(&tmp, &raw).await?;
    let out = tokio::process::Command::new("cabextract").arg("--pipe").arg(&tmp).output().await;
    let _ = tokio::fs::remove_file(&tmp).await;
    let out = out?.stdout;
    let utf16: Vec<u16> = out.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    Ok(String::from_utf16_lossy(&utf16).trim_start_matches('\u{feff}').to_owned())
}

/// The text of the first <tag>...</tag> (any namespace prefix), entities left as they are.
fn tag(xml: &str, name: &str) -> Option<String> {
    let mut rest = xml;
    loop {
        let at = rest.find('<')?;
        rest = &rest[at + 1..];
        let head_end = rest.find('>')?;
        let head = &rest[..head_end];
        let local = head.split_whitespace().next().unwrap_or("").rsplit(':').next().unwrap_or("");
        if local == name && !head.starts_with('/') && !head.ends_with('/') {
            let body = &rest[head_end + 1..];
            let close = body.find("</")?;
            return Some(body[..close].to_owned());
        }
        rest = &rest[head_end..];
    }
}

fn attr(xml: &str, element: &str, name: &str) -> Option<String> {
    let start = xml.find(&format!(":{element} ")).or_else(|| xml.find(&format!("<{element} ")))?;
    let head = &xml[start..xml[start..].find('>')? + start];
    let key = format!(" {name}=\"");
    let at = head.find(&key)? + key.len();
    Some(head[at..].split('"').next()?.to_owned())
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

/// An update's metadata: its English title, KB, build, date, state.
fn parse(id: &str, rev: u32, xml: &str) -> Option<Update> {
    let title = xml
        .split("LocalizedProperties>")
        .find(|s| tag(s, "Language").as_deref() == Some("en"))
        .and_then(|s| tag(s, "Title"))
        .map(|t| unescape(&t))?;
    // The build: ReleaseVersion on the newer updates; a classic one (Server 2022) names it only
    // in its child package's identity, Package_for_RollupFix version="20348.5622.1.23".
    let build = attr(xml, "Properties", "ReleaseVersion").map(|v| v.trim_start_matches("10.0.").to_owned()).or_else(|| {
        let at = xml.find("\"Package_for_RollupFix\" version=\"")? + "\"Package_for_RollupFix\" version=\"".len();
        let v: Vec<&str> = xml[at..].split('"').next()?.split('.').collect();
        (v.len() >= 2).then(|| format!("{}.{}", v[0], v[1]))
    });
    let kb = tag(xml, "KBArticleID").or_else(|| title.split("KB").nth(1).map(|r| r.chars().take_while(char::is_ascii_digit).collect::<String>()).filter(|k| !k.is_empty()));
    Some(Update {
        id: id.to_owned(),
        rev,
        kb: kb.unwrap_or_default(),
        title,
        build: build.unwrap_or_default(),
        created: attr(xml, "Properties", "CreationDate").unwrap_or_default(),
        state: attr(xml, "Properties", "PublicationState").unwrap_or_else(|| "Published".into()),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_an_update_blob() {
        let xml = r#"<upd:Update xmlns:upd="x"><upd:UpdateIdentity UpdateID="e421" RevisionNumber="101" /><upd:Properties UpdateType="Software" ProductName="Client.OS.RS2.AMD64" ReleaseVersion="10.0.26200.9445" PublicationState="Expired" CreationDate="2026-09-08T04:04:09.254Z"><upd:KBArticleID>5124008</upd:KBArticleID></upd:Properties><upd:LocalizedPropertiesCollection><upd:LocalizedProperties><upd:Language>de</upd:Language><upd:Title>Kumulatives Update</upd:Title></upd:LocalizedProperties><upd:LocalizedProperties><upd:Language>en</upd:Language><upd:Title>2026-09 Cumulative Update for Windows 11, version 25H2 for x64-based Systems (KB5124008) (26200.9445)</upd:Title></upd:LocalizedProperties></upd:LocalizedPropertiesCollection></upd:Update>"#;
        let u = super::parse("e421", 101, xml).unwrap();
        assert_eq!(u.build, "26200.9445");
        assert_eq!(u.kb, "5124008");
        assert_eq!(u.state, "Expired");
        assert!(u.title.starts_with("2026-09 Cumulative Update for Windows 11"));
        assert_eq!(u.created, "2026-09-08T04:04:09.254Z");
    }

    #[test]
    fn finds_tags_with_and_without_prefix() {
        assert_eq!(super::tag("<a><b:PlugInId>x</b:PlugInId></a>", "PlugInId").as_deref(), Some("x"));
        assert_eq!(super::tag("<CookieData>abc</CookieData>", "CookieData").as_deref(), Some("abc"));
        assert_eq!(super::tag("<UpdateIDs/><UpdateID>u1</UpdateID>", "UpdateID").as_deref(), Some("u1"));
    }
}

#[cfg(test)]
mod live {
    /// Against Microsoft Update itself (about 70 MB the first time): cargo test wu_live -- --ignored
    #[tokio::test]
    #[ignore]
    async fn wu_live() {
        let dir = std::env::temp_dir().join("wu-live");
        std::fs::create_dir_all(&dir).unwrap();
        super::load(&dir).await;
        let t = std::time::Instant::now();
        super::refresh(&dir, std::time::Duration::from_secs(0)).await.unwrap();
        println!("synced in {:?}", t.elapsed());
        let w11 = super::category("w11-25h2").unwrap();
        for b in ["26200.9445", "26200.9457", "26200.9550", "26200.9539", "26200.9168", "26200.8894", "26200.9106"] {
            println!("{b}: {:?}", super::lookup(w11, b).unwrap().map(|u| (u.kb, u.created, u.title)));
        }
        let s25 = super::category("ws2025").unwrap();
        println!("26100.33438: {:?}", super::lookup(s25, "26100.33438").unwrap().map(|u| u.title));
        let s22 = super::category("ws2022").unwrap();
        println!("20348.5622: {:?}", super::lookup(s22, "20348.5622").unwrap().map(|u| u.title));
    }
}
