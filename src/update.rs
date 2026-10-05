//! The studio's own updates, from its GitHub releases.
//!
//! The service runs unprivileged and cannot replace its own binary, so an update is split:
//! the studio's job waits for every other job, downloads the release's binary into
//! `<data>/update/`, checks it against the release's SHA256SUMS and leaves a request file.
//! A root helper in the container (pve-vm-studio-update.path -> pvs-update.sh) sees the
//! request, fetches SHA256SUMS from GitHub ITSELF, checks the staged binary again, swaps it
//! in and restarts the service; it leaves a status file that the next start reads to close
//! the job (`finish_pending`) instead of marking it interrupted.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::jobs::JobLog;

pub const REPO: &str = "Barg0/pve-vm-studio";
/// The release asset that is the studio itself.
pub const ASSET: &str = "pve-vm-studio-x86_64";
const SUMS: &str = "SHA256SUMS";

/// The rolling pre-release CI publishes for every push to main (the development channel).
pub const DEVELOPMENT: &str = "development";

/// Updates settings. Automatic installation is opt-in: off until an admin switches it on.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateSettings {
    pub auto: bool,
    /// "stable" (releases, the default) or "development" (every commit on main - untested).
    pub channel: String,
}

impl UpdateSettings {
    pub fn development(&self) -> bool {
        self.channel == "development"
    }
}

/// One release, as the version card shows it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Release {
    pub tag: String,
    pub version: String,
    pub name: String,
    pub published: String,
    pub url: String,
    /// The notes, one line each: (kind, text) - kind new | fix | chg | "" from a "New: ..." prefix.
    pub notes: Vec<(String, String)>,
    pub asset_url: String,
    pub asset_size: u64,
    pub sums_url: String,
}

pub fn dir(data: &Path) -> PathBuf {
    data.join("update")
}

/// "1.2.3" > "1.2.0"; "v" and pre-release tails ignored for the order.
pub fn newer(a: &str, b: &str) -> bool {
    let p = |v: &str| v.trim_start_matches('v').split(['.', '-']).map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    p(a) > p(b)
}

/// Release notes markdown -> (kind, text) per bullet; "New:", "Added:", "Fixed:", "Changed:"
/// prefixes give the kind.
pub fn parse_notes(body: &str) -> Vec<(String, String)> {
    body.lines()
        .filter_map(|l| {
            let t = l.trim().strip_prefix("- ").or_else(|| l.trim().strip_prefix("* "))?.trim();
            let (kind, rest) = match t.split_once(':') {
                Some((k, r)) if matches!(k.trim().to_lowercase().as_str(), "new" | "added" | "add") => ("new", r),
                Some((k, r)) if matches!(k.trim().to_lowercase().as_str(), "fixed" | "fix") => ("fix", r),
                Some((k, r)) if matches!(k.trim().to_lowercase().as_str(), "changed" | "change") => ("chg", r),
                _ => ("", t),
            };
            Some((kind.to_owned(), rest.trim().to_owned()))
        })
        .collect()
}

async fn gh(web: &reqwest::Client, path: &str) -> Option<Value> {
    let r = web.get(format!("https://api.github.com/repos/{REPO}{path}")).header("Accept", "application/vnd.github+json").send().await.ok()?;
    if !r.status().is_success() {
        return None;
    }
    r.json::<Value>().await.ok()
}

/// This build and GitHub's releases (published, not drafts or pre-releases), newest first,
/// and how far main is ahead of this build's commit. Cached 6 hours unless `fresh`.
pub async fn status(web: &reqwest::Client, fresh: bool, development: bool) -> Value {
    static CACHE: std::sync::Mutex<Option<(Instant, bool, Value)>> = std::sync::Mutex::new(None);
    if !fresh
        && let Some((at, dev, v)) = CACHE.lock().unwrap().as_ref()
        && *dev == development
        && at.elapsed() < Duration::from_secs(6 * 3600)
    {
        return v.clone();
    }
    let version = env!("CARGO_PKG_VERSION");
    let commit = env!("STUDIO_COMMIT");
    let list = gh(web, "/releases?per_page=10").await;
    let releases: Vec<Release> = list
        .as_ref()
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter(|r| !r["draft"].as_bool().unwrap_or(false) && !r["prerelease"].as_bool().unwrap_or(false))
                .map(release_of)
                .collect()
        })
        .unwrap_or_default();
    let mut state = match releases.first() {
        Some(l) if newer(&l.version, version) => "update",
        Some(_) => "current",
        None if list.is_some() => "none",
        None => "unreachable",
    };
    let own = commit.trim_end_matches("-dirty");
    let main_ahead = match own {
        "" => None,
        c => gh(web, &format!("/compare/{c}...main")).await.and_then(|v| v["ahead_by"].as_u64()),
    };
    // The development channel: CI's rolling pre-release of main's newest commit.
    let mut development_build = Value::Null;
    if development {
        let dev = gh(web, &format!("/releases/tags/{DEVELOPMENT}")).await;
        if let Some(e) = &dev {
            let rel = release_of(e);
            let text = format!("{} {}", e["name"].as_str().unwrap_or(""), e["body"].as_str().unwrap_or(""));
            let built = dev_commit(&text).unwrap_or_default();
            // What changed between this build and the development build: its commits.
            let mut commits = Vec::new();
            let mut ahead = 0;
            if !own.is_empty() && !built.is_empty() {
                if let Some(c) = gh(web, &format!("/compare/{own}...{built}")).await {
                    ahead = c["ahead_by"].as_u64().unwrap_or(0);
                    commits = c["commits"].as_array().map(|a| {
                        a.iter().rev().take(15).map(|x| json!({
                            "sha": x["sha"].as_str().unwrap_or("").chars().take(7).collect::<String>(),
                            "message": x["commit"]["message"].as_str().unwrap_or("").lines().next().unwrap_or(""),
                            "date": x["commit"]["committer"]["date"].as_str().unwrap_or(""),
                        })).collect::<Vec<_>>()
                    }).unwrap_or_default();
                }
            }
            state = if built.is_empty() { "none" } else if !own.is_empty() && built.starts_with(own) { "current" } else if ahead > 0 || own.is_empty() { "update" } else { "current" };
            development_build = json!({ "release": rel, "commit": built.chars().take(7).collect::<String>(), "ahead": ahead, "commits": commits });
        } else {
            state = "none";
        }
    }
    let v = json!({
        "version": version, "commit": commit, "state": state, "channel": if development { "development" } else { "stable" },
        "latest": releases.first().map(|l| l.version.clone()), "releases": releases, "main_ahead": main_ahead,
        "development": development_build,
        "checked": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    });
    *CACHE.lock().unwrap() = Some((Instant::now(), development, v.clone()));
    v
}

/// The commit a development build was made from: the first 40-hex word in its name or notes
/// (CI writes "Development build <sha>").
fn dev_commit(text: &str) -> Option<String> {
    text.split(|c: char| !c.is_ascii_hexdigit()).find(|w| w.len() == 40).map(str::to_lowercase)
}

fn release_of(r: &Value) -> Release {
    let asset = |name: &str| r["assets"].as_array().and_then(|a| a.iter().find(|x| x["name"].as_str() == Some(name))).cloned().unwrap_or_default();
    let bin = asset(ASSET);
    let tag = r["tag_name"].as_str().unwrap_or("").to_owned();
    Release {
        version: tag.trim_start_matches('v').to_owned(),
        name: r["name"].as_str().unwrap_or(&tag).to_owned(),
        published: r["published_at"].as_str().unwrap_or("").to_owned(),
        url: r["html_url"].as_str().unwrap_or("").to_owned(),
        notes: parse_notes(r["body"].as_str().unwrap_or("")),
        asset_url: bin["browser_download_url"].as_str().unwrap_or("").to_owned(),
        asset_size: bin["size"].as_u64().unwrap_or(0),
        sums_url: asset(SUMS)["browser_download_url"].as_str().unwrap_or("").to_owned(),
        tag,
    }
}

async fn sha256_hex(path: &Path) -> Result<String> {
    let out = tokio::process::Command::new("sha256sum").arg(path).output().await?;
    if !out.status.success() {
        bail!("sha256sum {}", path.display());
    }
    Ok(String::from_utf8_lossy(&out.stdout).split_whitespace().next().unwrap_or("").to_lowercase())
}

/// The update job: waits for the other jobs, stages and checks the binary, hands over to the
/// root helper - which restarts the studio, so a successful job ends in the next process.
pub async fn run(web: reqwest::Client, data: PathBuf, log: JobLog, jobs: crate::jobs::Jobs, job_id: String, tag: String) -> Result<()> {
    let st = status(&web, true, tag == DEVELOPMENT).await;
    let found = if tag == DEVELOPMENT {
        Some(st["development"]["release"].clone()).filter(|r| !r.is_null())
    } else {
        st["releases"].as_array().and_then(|a| a.iter().find(|r| r["tag"].as_str() == Some(&tag))).cloned()
    };
    let rel: Release = serde_json::from_value(found.context("GitHub does not list that release")?)?;
    if rel.asset_url.is_empty() || rel.sums_url.is_empty() {
        bail!("release {tag} has no {ASSET} or no {SUMS} asset");
    }
    let target = if tag == DEVELOPMENT { format!("development build {}", st["development"]["commit"].as_str().unwrap_or("")) } else { rel.version.clone() };
    log.run(format!("Update to {target} - from {} ({})", env!("CARGO_PKG_VERSION"), env!("STUDIO_COMMIT"))).await;
    // Every other job first: the restart would cut them off.
    let mut said = false;
    loop {
        log.check_abort()?;
        let others = jobs.running_ids().await.into_iter().filter(|i| *i != job_id).count();
        if others == 0 {
            break;
        }
        if !said {
            log.line(format!("Waiting for {others} running job(s) to finish - the restart would cut them off")).await;
            said = true;
        }
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
    let d = dir(&data);
    tokio::fs::create_dir_all(&d).await?;
    let staged = d.join("pve-vm-studio.new");
    log.get(format!("Downloading {ASSET} ({:.1} MB)", rel.asset_size as f64 / 1e6)).await;
    let bytes = web.get(&rel.asset_url).send().await?.error_for_status()?.bytes().await?;
    tokio::fs::write(&staged, &bytes).await?;
    let sums = web.get(&rel.sums_url).send().await?.error_for_status()?.text().await?;
    let want = sums
        .lines()
        .find_map(|l| {
            let mut p = l.split_whitespace();
            let (h, f) = (p.next()?, p.next()?);
            (f.trim_start_matches('*') == ASSET).then(|| h.to_lowercase())
        })
        .context("SHA256SUMS does not list the binary")?;
    let have = sha256_hex(&staged).await?;
    if have != want {
        let _ = tokio::fs::remove_file(&staged).await;
        bail!("the download does not match the release's SHA-256 ({have} vs {want}) - nothing installed");
    }
    log.ok(format!("SHA-256 matches the release ({}…)", &want[..12])).await;
    // The request the root helper acts on. Key=value, read by a shell script.
    let req = format!("TAG={tag}\nVERSION={target}\nJOB={job_id}\nSHA256={want}\n");
    tokio::fs::write(d.join("request.tmp"), req).await?;
    tokio::fs::rename(d.join("request.tmp"), d.join("request")).await?;
    log.run("Handing over to the updater - the studio restarts into the new version").await;
    // The helper restarts the service; this job ends in the next process (finish_pending).
    for _ in 0..24 {
        log.check_abort()?;
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    let _ = tokio::fs::remove_file(d.join("request")).await;
    bail!("the updater did not take over within 2 minutes - is pve-vm-studio-update.path installed in the container? (deploy/update-lxc.sh installs it)")
}

/// At start, before the jobs table marks running jobs interrupted: the helper's result for
/// an update job closes it as succeeded or failed, with the helper's message in its log.
/// This build as people read it: 0.1.0 (abc1234).
pub fn current_label() -> String {
    let commit = env!("STUDIO_COMMIT");
    if commit.is_empty() { env!("CARGO_PKG_VERSION").to_owned() } else { format!("{} ({commit})", env!("CARGO_PKG_VERSION")) }
}

/// Closes the update job the restart ended. Returns (job, ok, message) for the mail.
pub async fn finish_pending(db: &sqlx::SqlitePool, data: &Path, jobs_dir: &Path) -> Option<(String, bool, String)> {
    let f = dir(data).join("status");
    let Ok(text) = tokio::fs::read_to_string(&f).await else { return None };
    let get = |k: &str| text.lines().find_map(|l| l.strip_prefix(&format!("{k}="))).unwrap_or("").to_owned();
    let (job, result, msg) = (get("JOB"), get("RESULT"), get("MESSAGE"));
    if !job.is_empty() {
        let ok = result == "ok";
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let line = if ok {
            format!("{now} [ o.k.  ] {msg}\n{now} [ end   ] Update: done\n")
        } else {
            format!("{now} [ error ] {msg}\n")
        };
        use tokio::io::AsyncWriteExt;
        if let Ok(mut l) = tokio::fs::OpenOptions::new().append(true).open(jobs_dir.join(format!("{job}.log"))).await {
            let _ = l.write_all(line.as_bytes()).await;
        }
        let ended = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let _ = sqlx::query("UPDATE jobs SET status = ?, ended_at = ?, error = ? WHERE id = ?")
            .bind(if ok { "succeeded" } else { "failed" })
            .bind(ended)
            .bind(if ok { None } else { Some(msg.clone()) })
            .bind(&job)
            .execute(db)
            .await;
    }
    let _ = tokio::fs::remove_file(&f).await;
    (!job.is_empty()).then(|| (job, result == "ok", msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_and_notes() {
        assert!(newer("1.10.0", "1.9.3") && newer("v2.0.0", "1.9.9") && !newer("1.0.0", "1.0.0"));
        let n = parse_notes("## 1.1\n- New: CIS for Leap\n* Fixed: gold remove\n- plain line\ntext");
        assert_eq!(n, vec![("new".into(), "CIS for Leap".into()), ("fix".into(), "gold remove".into()), ("".into(), "plain line".into())]);
    }
}
