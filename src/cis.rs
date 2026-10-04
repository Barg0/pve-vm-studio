//! CIS Benchmark hardening for Linux golds (docs/cis-benchmark.md). The rules run inside the
//! guest (guest-files/cis: pvs-cis fix, a reboot, pvs-cis check); the studio carries the
//! bundle on the bake's seed disk, reads the report back and keeps it with the gold.
//!
//! Wording: "configured per the CIS ... Benchmark, self-assessed" - never "CIS certified",
//! "hardened" or "compliant" (the benchmarks' licence; CIS membership needed for that).

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// The CIS options of a bake: the Server level (1 or 2) and any exceptions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CisOptions {
    pub level: u8,
    #[serde(default)]
    pub exceptions: Vec<Exception>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exception {
    pub id: String,
    pub reason: String,
}

/// A benchmark the studio implements, for the images it covers: its map (guest-files/cis/
/// <dir>/map.tsv, or <map>/map.tsv when shared) over a family's rules (guest-files/cis/<family>/;
/// several families in order, the later ones redefining: "deb el").
pub struct Benchmark {
    pub dir: &'static str,
    pub family: &'static str,
    /// The folder of a shared map (Alma, Oracle and Rocky Linux 9 are one text).
    pub map: Option<&'static str>,
    pub name: &'static str,
    pub version: &'static str,
    pub images: &'static [&'static str],
}

pub static BENCHMARKS: &[Benchmark] = &[
    Benchmark { dir: "ubuntu2604", family: "deb", map: None, name: "CIS Ubuntu Linux 26.04 LTS Benchmark", version: "1.0.0", images: &["ubuntu2604"] },
    Benchmark { dir: "debian13", family: "deb", map: None, name: "CIS Debian Linux 13 Benchmark", version: "1.1.0", images: &["debian13"] },
    Benchmark { dir: "ubuntu2404", family: "deb", map: None, name: "CIS Ubuntu Linux 24.04 LTS Benchmark", version: "2.0.0", images: &["ubuntu2404"] },
    Benchmark { dir: "debian12", family: "deb", map: None, name: "CIS Debian Linux 12 Benchmark", version: "2.0.0", images: &["debian12"] },
    Benchmark { dir: "rocky9", family: "deb el", map: Some("el9"), name: "CIS Rocky Linux 9 Benchmark", version: "3.0.0", images: &["rocky9"] },
    Benchmark { dir: "alma9", family: "deb el", map: Some("el9"), name: "CIS AlmaLinux OS 9 Benchmark", version: "3.0.0", images: &["alma9"] },
    Benchmark { dir: "oracle9", family: "deb el", map: Some("el9"), name: "CIS Oracle Linux 9 Benchmark", version: "3.0.0", images: &["oracle9"] },
    Benchmark { dir: "rocky10", family: "deb el", map: Some("el10"), name: "CIS Rocky Linux 10 Benchmark", version: "1.0.0", images: &["rocky10"] },
    Benchmark { dir: "alma10", family: "deb el", map: Some("el10"), name: "CIS AlmaLinux OS 10 Benchmark", version: "1.0.0", images: &["alma10"] },
    Benchmark { dir: "oracle10", family: "deb el", map: Some("el10"), name: "CIS Oracle Linux 10 Benchmark", version: "1.0.0", images: &["oracle10"] },
    // CIS publishes none for openSUSE; Leap 16.0 is built from SLE 16's sources.
    Benchmark { dir: "leap16", family: "deb el suse", map: Some("sle16"), name: "CIS SUSE Linux Enterprise 16 Benchmark (applied to openSUSE Leap 16.0)", version: "1.0.0", images: &["leap16"] },
];

pub fn benchmark_for(image: &str) -> Option<&'static Benchmark> {
    BENCHMARKS.iter().find(|b| b.images.contains(&image))
}

macro_rules! guest_file {
    ($p:literal) => {
        ($p, include_bytes!(concat!("../guest-files/cis/", $p)) as &[u8])
    };
}

/// The bundle as it lands in /usr/local/lib/pvs-cis (relative paths).
static COMMON: &[(&str, &[u8])] = &[
    guest_file!("pvs-cis"),
    guest_file!("lib.sh"),
    guest_file!("layout.sh"),
    guest_file!("bake/finish.sh"),
    guest_file!("bake/pvs-cis-finish.service"),
    guest_file!("bake/pvs-cis-layout.service"),
    guest_file!("units/pvs-cis-aide-init.service"),
    guest_file!("units/pvs-cis-grow.service"),
];

/// The Debian family's rules (Ubuntu and Debian).
static DEB: &[(&str, &[u8])] = &[
    guest_file!("deb/1a-filesystem-packages.sh"),
    guest_file!("deb/1b-boot-process-banners.sh"),
    guest_file!("deb/2-services.sh"),
    guest_file!("deb/3-network.sh"),
    guest_file!("deb/4-firewall.sh"),
    guest_file!("deb/5-access.sh"),
    guest_file!("deb/6-logging-audit.sh"),
    guest_file!("deb/7-maintenance.sh"),
];

/// Enterprise Linux (Alma, Oracle, Rocky 9 and 10): on top of DEB - what differs, and what
/// only Enterprise Linux has (SELinux, crypto policies, firewalld, authselect, dnf).
static EL: &[(&str, &[u8])] = &[
    guest_file!("el/1a-filesystem-packages.sh"),
    guest_file!("el/1b-boot-process-banners.sh"),
    guest_file!("el/2-services.sh"),
    guest_file!("el/3-network.sh"),
    guest_file!("el/4-firewall.sh"),
    guest_file!("el/5-access.sh"),
    guest_file!("el/6-logging-audit.sh"),
    guest_file!("el/7-maintenance.sh"),
];

/// openSUSE Leap (the SLE 16 benchmark): on top of DEB and EL - zypper, pam-config, the
/// vendor files in /usr/etc, GRUB without grubby.
static SUSE: &[(&str, &[u8])] = &[
    guest_file!("suse/1a-filesystem-packages.sh"),
    guest_file!("suse/1b-boot-process-banners.sh"),
    guest_file!("suse/2-services.sh"),
    guest_file!("suse/3-network.sh"),
    guest_file!("suse/4-firewall.sh"),
    guest_file!("suse/5-access.sh"),
    guest_file!("suse/6-logging-audit.sh"),
    guest_file!("suse/7-maintenance.sh"),
];

static MAPS: &[(&str, &[u8])] = &[
    guest_file!("ubuntu2604/bench.conf"),
    guest_file!("ubuntu2604/map.tsv"),
    guest_file!("debian13/bench.conf"),
    guest_file!("debian13/map.tsv"),
    guest_file!("ubuntu2404/bench.conf"),
    guest_file!("ubuntu2404/map.tsv"),
    guest_file!("debian12/bench.conf"),
    guest_file!("debian12/map.tsv"),
    guest_file!("el9/map.tsv"),
    guest_file!("el10/map.tsv"),
    guest_file!("rocky9/bench.conf"),
    guest_file!("alma9/bench.conf"),
    guest_file!("oracle9/bench.conf"),
    guest_file!("rocky10/bench.conf"),
    guest_file!("alma10/bench.conf"),
    guest_file!("oracle10/bench.conf"),
    guest_file!("sle16/map.tsv"),
    guest_file!("leap16/bench.conf"),
    guest_file!("leap16/exceptions.default"),
];

/// The seed disk's pvs-cis/ folder: the engine, the family's rules, this benchmark's map, this
/// bake's profile and exceptions.
pub fn seed_files(b: &Benchmark, opt: &CisOptions) -> Vec<(String, Vec<u8>)> {
    let rules = b.family.split(' ').flat_map(|f| match f {
        "deb" => DEB,
        "el" => EL,
        "suse" => SUSE,
        _ => &[],
    });
    let mine = |p: &str| p.starts_with(&format!("{}/", b.dir)) || b.map.is_some_and(|m| p.starts_with(&format!("{m}/")));
    let bench = MAPS.iter().filter(|(p, _)| mine(p));
    let mut out: Vec<(String, Vec<u8>)> = COMMON.iter().chain(rules).chain(bench).map(|(p, c)| (format!("pvs-cis/{p}"), c.to_vec())).collect();
    out.push(("pvs-cis/level".into(), format!("{}\n", opt.level).into_bytes()));
    let exc: String = opt.exceptions.iter().map(|e| format!("{}\t{}\n", e.id, e.reason.replace(['\t', '\n'], " "))).collect();
    out.push(("pvs-cis/exceptions".into(), exc.into_bytes()));
    out
}

// ---- the rules, before a bake ----

/// One recommendation as the studio runs it - for the rules overlay of the bake form.
#[derive(Debug, Clone, Serialize)]
pub struct RuleInfo {
    pub id: String,
    pub level: u8,
    pub manual: bool,
    /// Our own short title (never CIS text).
    pub title: String,
    /// The family has a fix for it: the bake applies it.
    pub fix: bool,
    /// The studio's decision for a rule a person reviews ("ev \"decision: ...\"").
    pub decision: String,
}

/// The benchmark's map over its families' rules, read from the bundle as the guest's engine
/// reads it: families in order, a later one redefining titles and functions.
pub fn rules(b: &Benchmark) -> Vec<RuleInfo> {
    let mut title: std::collections::HashMap<String, String> = Default::default();
    let mut decision: std::collections::HashMap<String, String> = Default::default();
    let mut fixes: std::collections::HashSet<String> = Default::default();
    for fam in b.family.split(' ') {
        let files: &[(&str, &[u8])] = match fam {
            "deb" => DEB,
            "el" => EL,
            "suse" => SUSE,
            _ => &[],
        };
        for (_, c) in files {
            let text = String::from_utf8_lossy(c);
            let mut key: Option<String> = None;
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix("rule ")
                    && let Some((k, t)) = rest.split_once(' ')
                {
                    let k = k.to_owned();
                    title.insert(k.clone(), t.trim().trim_matches('"').to_owned());
                    key = Some(k);
                    continue;
                }
                if let Some(f) = line.strip_prefix("fix_")
                    && let Some((name, _)) = f.split_once("()")
                {
                    fixes.insert(name.to_owned());
                }
                const DECISION: &str = "ev \"decision: ";
                if let (Some(k), Some(i)) = (&key, line.find(DECISION)) {
                    let d = &line[i + DECISION.len()..];
                    decision.insert(k.clone(), d.split('"').next().unwrap_or("").to_owned());
                }
            }
        }
    }
    let dir = b.map.unwrap_or(b.dir);
    let Some((_, map)) = MAPS.iter().find(|(p, _)| *p == format!("{dir}/map.tsv")) else { return vec![] };
    String::from_utf8_lossy(map)
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .filter_map(|l| {
            let mut f = l.split('\t');
            let (id, level, kind, key) = (f.next()?, f.next()?, f.next()?, f.next()?);
            Some(RuleInfo {
                id: id.to_owned(),
                level: level.parse().ok()?,
                manual: kind == "manual",
                title: title.get(key).cloned().unwrap_or_else(|| key.to_owned()),
                fix: fixes.contains(&key.replace('-', "_")),
                decision: decision.get(key).cloned().unwrap_or_default(),
            })
        })
        .collect()
}

// ---- the report ----

/// The counts and score of a report - what the gold's manifest and card carry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Summary {
    pub benchmark: String,
    pub version: String,
    pub level: u8,
    pub profile: String,
    pub checked: String,
    pub pass: u32,
    pub fail: u32,
    pub na: u32,
    pub review: u32,
    pub exception: u32,
    pub error: u32,
    /// Passed of the automated rules that apply: pass / (pass + fail + error), in percent.
    pub score: f64,
}

pub fn summarize(report: &serde_json::Value) -> Result<Summary> {
    let c = &report["counts"];
    let n = |k: &str| c[k].as_u64().unwrap_or(0) as u32;
    if report["results"].as_array().is_none_or(|r| r.is_empty()) {
        bail!("the CIS report has no results");
    }
    let (pass, fail, error) = (n("pass"), n("fail"), n("error"));
    let judged = pass + fail + error;
    Ok(Summary {
        benchmark: report["benchmark"].as_str().unwrap_or("").into(),
        version: report["version"].as_str().unwrap_or("").into(),
        level: report["level"].as_u64().unwrap_or(0) as u8,
        profile: report["profile"].as_str().unwrap_or("").into(),
        checked: report["checked"].as_str().unwrap_or("").into(),
        pass,
        fail,
        na: n("na"),
        review: n("review"),
        exception: n("exception"),
        error,
        score: if judged == 0 { 0.0 } else { (f64::from(pass) * 1000.0 / f64::from(judged)).round() / 10.0 },
    })
}

impl Summary {
    /// "Level 2 Server · 97.1% · 3 exceptions" - the one line the gold card and notes show.
    pub fn line(&self) -> String {
        let mut s = format!("Level {} Server · {}%", self.level, self.score);
        if self.fail > 0 {
            s += &format!(" · {} failed", self.fail);
        }
        if self.exception > 0 {
            s += &format!(" · {} exception{}", self.exception, if self.exception == 1 { "" } else { "s" });
        }
        s
    }
}

pub fn reports_dir(data: &Path) -> PathBuf {
    data.join("cis-reports")
}

pub fn report_path(data: &Path, gold: &str) -> PathBuf {
    reports_dir(data).join(format!("{gold}.json"))
}

pub fn grub_path(data: &Path, gold: &str) -> PathBuf {
    reports_dir(data).join(format!("{gold}.grub"))
}

/// Keeps a gold's report, and its GRUB password readable by the studio's user only.
pub async fn store(data: &Path, gold: &str, report: &[u8], grub: Option<&str>) -> Result<()> {
    let dir = reports_dir(data);
    tokio::fs::create_dir_all(&dir).await?;
    tokio::fs::write(report_path(data, gold), report).await.context("writing the CIS report")?;
    if let Some(pw) = grub.map(str::trim).filter(|p| !p.is_empty()) {
        use std::os::unix::fs::OpenOptionsExt;
        let path = grub_path(data, gold);
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&path)?;
        std::io::Write::write_all(&mut f, pw.as_bytes())?;
    }
    Ok(())
}

pub async fn remove(data: &Path, gold: &str) {
    let _ = tokio::fs::remove_file(report_path(data, gold)).await;
    let _ = tokio::fs::remove_file(grub_path(data, gold)).await;
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The report as one self-contained HTML page - for an auditor, without the studio.
pub fn html(report: &serde_json::Value, gold: &str) -> String {
    let s = summarize(report).unwrap_or_default();
    let rows: String = report["results"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| {
            let st = r["status"].as_str().unwrap_or("");
            let reason = r["reason"].as_str().map(|x| format!("<div class=\"why\">Exception: {}</div>", esc(x))).unwrap_or_default();
            format!(
                "<tr class=\"{st}\"><td class=\"id\">{}</td><td>L{}</td><td>{}{reason}</td><td><span class=\"st\">{st}</span></td><td><pre>{}</pre></td></tr>",
                esc(r["id"].as_str().unwrap_or("")),
                r["level"].as_u64().unwrap_or(0),
                esc(r["title"].as_str().unwrap_or("")),
                esc(r["evidence"].as_str().unwrap_or(""))
            )
        })
        .collect();
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>CIS report - gold {gold}</title>
<style>
body{{font:13px/1.45 system-ui,sans-serif;margin:24px;color:#1d2433;background:#fff}}
h1{{font-size:18px;margin:0 0 4px}}.sub{{color:#5b6475;margin-bottom:16px}}
.counts span{{display:inline-block;margin-right:14px}}
table{{border-collapse:collapse;width:100%;margin-top:16px}}td,th{{border-bottom:1px solid #e3e6ec;padding:6px 8px;text-align:left;vertical-align:top}}
th{{font-size:11px;text-transform:uppercase;color:#5b6475}}.id{{font-family:ui-monospace,monospace;white-space:nowrap}}
pre{{margin:0;font:11px/1.4 ui-monospace,monospace;white-space:pre-wrap;color:#3b4353}}
.st{{font-weight:600;text-transform:uppercase;font-size:11px}}.pass .st{{color:#1a7f37}}.fail .st,.error .st{{color:#cf222e}}
.exception .st,.review .st{{color:#9a6700}}.na .st{{color:#6e7781}}.why{{color:#9a6700;font-size:12px}}
.note{{color:#5b6475;font-size:12px;margin-top:16px}}
</style></head><body>
<h1>{} v{} - Level {} Server</h1>
<div class="sub">Gold {gold} · checked {} · self-assessed by PVE VM Studio</div>
<div class="counts"><span><b>{}%</b> of the applicable automated rules pass</span><span>{} pass</span><span>{} fail</span><span>{} exception</span><span>{} review</span><span>{} n/a</span><span>{} error</span></div>
<table><thead><tr><th>CIS</th><th>Level</th><th>Rule</th><th>Status</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table>
<p class="note">Configured per the {} v{}. Self-assessed with the studio's own checks; not a CIS certification.</p>
</body></html>"#,
        esc(&s.benchmark),
        esc(&s.version),
        s.level,
        esc(&s.checked),
        s.score,
        s.pass,
        s.fail,
        s.exception,
        s.review,
        s.na,
        s.error,
        esc(&s.benchmark),
        esc(&s.version),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_name_existing_rules() {
        // Every key a map names has a check in its family's rules.
        let rules: String = DEB.iter().chain(EL).chain(SUSE).map(|(_, c)| String::from_utf8_lossy(c).into_owned()).collect();
        for (path, c) in MAPS.iter().filter(|(p, _)| p.ends_with("map.tsv")) {
            let text = String::from_utf8_lossy(c);
            let mut ids = std::collections::HashSet::new();
            for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
                let key = line.split('\t').nth(3).unwrap();
                assert!(rules.contains(&format!("\ncheck_{}()", key.replace('-', "_"))), "{path}: no check for {key}");
                assert!(ids.insert(line.split('\t').next().unwrap()), "{path}: {line} twice");
            }
            // The benchmarks' recommendation counts (Server profiles).
            let want = match path.split('/').next().unwrap() {
                "ubuntu2404" => 332,
                "debian12" => 333,
                "el9" => 352,
                "el10" => 328,
                "sle16" => 336,
                _ => 350,
            };
            assert_eq!(ids.len(), want, "{path}");
        }
        let b = benchmark_for("debian13").unwrap();
        assert!(seed_files(b, &CisOptions { level: 1, exceptions: vec![] }).iter().any(|(p, _)| p == "pvs-cis/debian13/map.tsv"));
        // Enterprise Linux: both families and the shared map.
        let el = seed_files(benchmark_for("alma9").unwrap(), &CisOptions { level: 2, exceptions: vec![] });
        for want in ["pvs-cis/alma9/bench.conf", "pvs-cis/el9/map.tsv", "pvs-cis/deb/5-access.sh", "pvs-cis/el/5-access.sh"] {
            assert!(el.iter().any(|(p, _)| p == want), "{want}");
        }
        assert!(!el.iter().any(|(p, _)| p.starts_with("pvs-cis/el10/")));
    }

    #[test]
    fn rules_for_the_overlay() {
        let r = rules(benchmark_for("debian13").unwrap());
        assert_eq!(r.len(), 350);
        assert!(r.iter().all(|x| !x.title.contains('"') && !x.title.is_empty()));
        let l = r.iter().find(|x| x.id == "2.1.23").unwrap();
        assert!(l.decision.starts_with("only sshd"), "{l:?}");
        // Enterprise Linux: el redefines - the MAC audit rule is SELinux there.
        let e = rules(benchmark_for("rocky9").unwrap());
        assert_eq!(e.len(), 352);
        assert!(e.iter().filter(|x| x.fix).count() > 250);
    }

    #[test]
    fn score() {
        let r = serde_json::json!({ "benchmark": "B", "version": "1", "level": 2, "profile": "level2_server", "checked": "t",
            "counts": { "pass": 97, "fail": 2, "na": 10, "review": 5, "exception": 1, "error": 1 }, "results": [{ "id": "1.1" }] });
        let s = summarize(&r).unwrap();
        assert_eq!(s.score, 97.0);
        assert_eq!(s.line(), "Level 2 Server · 97% · 2 failed · 1 exception");
        assert!(html(&r, "abc").contains("Level 2 Server"));
    }
}
