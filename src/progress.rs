//! Progress that means something. A job is a row of weighted stages; inside a stage the
//! percentage comes from what can actually be measured - wget's own percentages, the
//! package manager's counters, cloud-init's stage markers. Nothing is interpolated or
//! animated: when nothing can be measured, the bar stands still at the stage's start.
//! It never goes backwards.

use crate::jobs::JobLog;

pub struct Progress {
    log: JobLog,
    label: String,
    pct: f64,
    /// The current stage's span of the whole bar.
    from: f64,
    to: f64,
    /// The part of the stage a sub-step covers (0.0-1.0): `within` fills it.
    part: (f64, f64),
    /// Each stage's span from earlier runs (`calibrate`), in place of the code's own.
    plan: Vec<(String, f64, f64)>,
}

impl Progress {
    pub fn new(log: &JobLog, label: impl Into<String>) -> Self {
        Self { log: log.clone(), label: label.into(), pct: 0.0, from: 0.0, to: 0.0, part: (0.0, 1.0), plan: vec![] }
    }

    /// Enters a stage covering `from..to` of the bar; the bar moves to its start.
    pub fn stage(&mut self, from: f64, to: f64, detail: impl Into<String>) {
        let detail = detail.into();
        let (from, to) = self.plan.iter().find(|(n, _, _)| *n == detail).map_or((from, to), |(_, f, t)| (*f, *t));
        self.from = from;
        self.to = to;
        self.part = (0.0, 1.0);
        self.log.mark_step(&detail);
        self.set(from, detail);
    }

    /// The stages' spans from what they took before: the median of the last five finished
    /// runs that went through `anchor` (a stage only that kind of job has - "WinPE pass 1"
    /// is a Windows bake). Without such a run, the code's own spans stay.
    pub async fn calibrate(&mut self, anchor: &str) {
        let (Some(dir), anchor) = (self.log.steps_dir(), anchor.to_owned()) else { return };
        if let Ok(plan) = tokio::task::spawn_blocking(move || history(&dir, &anchor, 5)).await {
            self.plan = plan;
        }
    }

    /// How far into the current stage (0.0-1.0) - or into its current part (`part`).
    pub fn within(&mut self, fraction: f64, detail: impl Into<String>) {
        let f = self.part.0 + (self.part.1 - self.part.0) * fraction.clamp(0.0, 1.0);
        self.set(self.from + (self.to - self.from) * f, detail);
    }

    /// A stage made of weighted sub-steps: the next `within` calls fill sub-step `i` of
    /// `weights` (measured durations), and the bar moves to its start now.
    pub fn part(&mut self, weights: &[f64], i: usize, detail: impl Into<String>) {
        let total: f64 = weights.iter().sum::<f64>().max(f64::EPSILON);
        let start: f64 = weights.iter().take(i).sum::<f64>() / total;
        let end = start + weights.get(i).copied().unwrap_or(0.0) / total;
        self.part = (0.0, 1.0);
        self.within(start, detail);
        self.part = (start, end.min(1.0));
    }

    /// A new detail line, the bar where it is (a sub-step's own percentage, say).
    pub fn note(&mut self, detail: impl Into<String>) {
        self.set(self.pct, detail);
    }

    fn set(&mut self, pct: f64, detail: impl Into<String>) {
        if pct > self.pct {
            self.pct = pct;
        }
        // The stage's own share, for the running step's row.
        let step = if self.to > self.from { Some(((self.pct - self.from) / (self.to - self.from) * 100.0).clamp(0.0, 100.0)) } else { None };
        self.log.progress_step(&self.label, Some(self.pct.min(100.0)), step, detail);
    }
}

/// Each stage's span (percent of the job) from the newest `runs` finished jobs whose steps
/// include `anchor`: their stage times (the .steps file; the last stage ends with the log),
/// the median per stage, in the newest run's order.
fn history(dir: &std::path::Path, anchor: &str, runs: usize) -> Vec<(String, f64, f64)> {
    use chrono::{DateTime, Utc};
    let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
    let mut files: Vec<(std::time::SystemTime, std::path::PathBuf)> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "steps"))
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .collect();
    files.sort_by(|a, b| b.0.cmp(&a.0));
    let mut seen: Vec<Vec<(String, f64)>> = Vec::new();
    for (_, p) in files {
        if seen.len() >= runs {
            break;
        }
        let log = p.with_extension("log");
        let Ok(text) = std::fs::read_to_string(&log) else { continue };
        if !text.lines().last().is_some_and(|l| l.contains("[ end")) {
            continue;
        }
        let Ok(steps) = std::fs::read_to_string(&p) else { continue };
        let marks: Vec<(DateTime<Utc>, String)> = steps
            .lines()
            .filter_map(|l| {
                let (t, n) = l.split_once('\t')?;
                Some((DateTime::parse_from_rfc3339(t).ok()?.with_timezone(&Utc), n.to_owned()))
            })
            .collect();
        if !marks.iter().any(|(_, n)| n == anchor) {
            continue;
        }
        let Some(end) = std::fs::metadata(&log).ok().and_then(|m| m.modified().ok()).map(DateTime::<Utc>::from) else { continue };
        let run: Vec<(String, f64)> = marks
            .iter()
            .enumerate()
            .map(|(i, (t, n))| {
                let next = marks.get(i + 1).map_or(end, |(t, _)| *t);
                (n.clone(), (next - *t).num_milliseconds().max(0) as f64 / 1000.0)
            })
            .collect();
        seen.push(run);
    }
    let Some(newest) = seen.first() else { return vec![] };
    let median = |name: &str| {
        let mut v: Vec<f64> = seen.iter().filter_map(|r| r.iter().find(|(n, _)| n == name).map(|(_, s)| *s)).collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        v.get(v.len() / 2).copied().unwrap_or(0.0)
    };
    let times: Vec<(String, f64)> = newest.iter().map(|(n, _)| (n.clone(), median(n))).collect();
    let total: f64 = times.iter().map(|(_, s)| s).sum();
    if total <= 0.0 {
        return vec![];
    }
    let mut at = 0.0;
    times
        .into_iter()
        .map(|(n, s)| {
            let from = at;
            at += s / total * 100.0;
            (n, from, at.min(100.0))
        })
        .collect()
}

/// Reads the package manager's own counters out of cloud-init's output, across however
/// many runs there are (update, upgrade, install).
#[derive(Default)]
pub struct PackageCounter {
    /// apt: announced by its summary line, counted by "Setting up".
    apt_total: u64,
    apt_done: u64,
    /// dnf, pacman, zypper: "x/y" on every line of a transaction - the batch's own ratio.
    batches_done: u64,
    batch_x: u64,
    batch_y: u64,
    seen_any: bool,
}

impl PackageCounter {
    /// Feeds one line; true when it moved the count.
    pub fn line(&mut self, l: &str) -> bool {
        let t = l.trim();
        // apt: "12 upgraded, 3 newly installed, 0 to remove and 0 not upgraded."
        if t.contains(" upgraded, ") && t.contains(" newly installed") {
            let n: Vec<u64> = t.split(|c: char| !c.is_ascii_digit()).filter_map(|p| p.parse().ok()).collect();
            if n.len() >= 2 {
                self.apt_total += n[0] + n[1];
                self.seen_any = true;
                return true;
            }
        }
        if t.starts_with("Setting up ") && self.apt_done < self.apt_total {
            self.apt_done += 1;
            return true;
        }
        // dnf "  Upgrading        : bash-5.2-1.x86_64       12/345"
        // pacman "(12/345) upgrading bash"   zypper "(12/345) Installing: bash ..."
        let ratio = if let Some(rest) = t.strip_prefix('(') {
            rest.split(')').next()
        } else if t.contains(" : ") && (t.starts_with("Upgrading") || t.starts_with("Installing") || t.starts_with("Cleanup") || t.starts_with("Erasing") || t.starts_with("Running scriptlet") || t.starts_with("Verifying")) {
            t.split_whitespace().last()
        } else {
            None
        };
        if let Some((x, y)) = ratio.and_then(|r| r.split_once('/')).and_then(|(x, y)| Some((x.trim().parse::<u64>().ok()?, y.trim().parse::<u64>().ok()?))) {
            if y == 0 || x > y {
                return false;
            }
            // dnf's "Verifying" pass counts 1..y again; it belongs to the same batch's end.
            if t.starts_with("Verifying") {
                return false;
            }
            if y != self.batch_y || x < self.batch_x {
                // A new transaction: the last one counts as done.
                self.batches_done += self.batch_y;
                self.batch_y = y;
            }
            self.batch_x = x;
            self.seen_any = true;
            return true;
        }
        false
    }

    /// Done so far over all known work, 0.0-1.0; None before any count was seen.
    pub fn fraction(&self) -> Option<f64> {
        if !self.seen_any {
            return None;
        }
        let total = self.apt_total + self.batches_done + self.batch_y;
        let done = self.apt_done + self.batches_done + self.batch_x;
        if total == 0 {
            return Some(1.0);
        }
        Some(done as f64 / total as f64)
    }

    pub fn summary(&self) -> String {
        let total = self.apt_total + self.batches_done + self.batch_y;
        let done = self.apt_done + self.batches_done + self.batch_x;
        format!("packages {done}/{total}")
    }
}

/// cloud-init's four stages, in order, from its own "running '...'" lines: 0-4.
pub fn cloud_init_stage(line: &str) -> Option<u8> {
    if !line.contains("Cloud-init v.") {
        return None;
    }
    if line.contains("running 'init-local'") {
        Some(1)
    } else if line.contains("running 'init'") {
        Some(2)
    } else if line.contains("running 'modules:config'") {
        Some(3)
    } else if line.contains("running 'modules:final'") {
        Some(4)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apt_counts() {
        let mut p = PackageCounter::default();
        p.line("3 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.");
        for _ in 0..2 {
            p.line("Setting up libfoo (1.0) ...");
        }
        assert_eq!(p.fraction(), Some(0.5));
    }

    #[test]
    fn dnf_and_pacman_batches() {
        let mut p = PackageCounter::default();
        p.line("  Upgrading        : bash-5.2-1.x86_64                     5/10");
        assert_eq!(p.fraction(), Some(0.5));
        p.line("  Verifying        : bash-5.2-1.x86_64                     1/10");
        assert_eq!(p.fraction(), Some(0.5));
        p.line("(1/4) upgrading linux");
        // first batch done (10), second 1 of 4 -> 11/14
        assert!((p.fraction().unwrap() - 11.0 / 14.0).abs() < 1e-9);
    }

    #[test]
    fn stages() {
        assert_eq!(cloud_init_stage("Cloud-init v. 25.1.4 running 'modules:final' at Wed"), Some(4));
        assert_eq!(cloud_init_stage("random"), None);
    }

    #[test]
    fn spans_from_history() {
        let dir = std::env::temp_dir().join(format!("pvs-hist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.steps"), "2026-10-06T17:36:00+00:00\tcreating the bake VM\n2026-10-06T17:36:10+00:00\tWinPE pass 1\n2026-10-06T17:38:40+00:00\taudit mode and sysprep\n").unwrap();
        std::fs::write(dir.join("a.log"), "x\n2026-10-06 19:42:54 [ end   ] Bake: done\n").unwrap();
        std::fs::write(dir.join("b.steps"), "2026-10-06T17:36:00+00:00\tcloud image\n").unwrap();
        std::fs::write(dir.join("b.log"), "2026-10-06 19:42:54 [ end   ] Bake: done\n").unwrap();
        let plan = history(&dir, "WinPE pass 1", 5);
        assert_eq!(plan.iter().map(|(n, _, _)| n.as_str()).collect::<Vec<_>>(), vec!["creating the bake VM", "WinPE pass 1", "audit mode and sysprep"]);
        assert!(plan[0].1 == 0.0 && plan[2].2 <= 100.0 && plan[1].2 > plan[1].1);
        assert!(history(&dir, "no such stage", 5).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

