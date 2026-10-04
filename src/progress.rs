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
}

impl Progress {
    pub fn new(log: &JobLog, label: impl Into<String>) -> Self {
        Self { log: log.clone(), label: label.into(), pct: 0.0, from: 0.0, to: 0.0 }
    }

    /// Enters a stage covering `from..to` of the bar; the bar moves to its start.
    pub fn stage(&mut self, from: f64, to: f64, detail: impl Into<String>) {
        self.from = from;
        self.to = to;
        self.set(from, detail);
    }

    /// How far into the current stage (0.0-1.0).
    pub fn within(&mut self, fraction: f64, detail: impl Into<String>) {
        let f = fraction.clamp(0.0, 1.0);
        self.set(self.from + (self.to - self.from) * f, detail);
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
}
