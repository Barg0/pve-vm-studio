//! Maintenance windows: when the studio may do work nobody asked for right now - its own
//! update and the Windows auto-update. A window is days, a start and an end in the studio's
//! local time; the start lets work begin, the end stops new steps (a running one finishes).

use chrono::{Datelike, Duration, Local, NaiveDate, NaiveDateTime, NaiveTime, Weekday};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Window {
    /// mon tue wed thu fri sat sun - the day the window opens on.
    pub days: Vec<String>,
    /// HH:MM. An end at or before the start runs past midnight into the next day.
    pub start: String,
    pub end: String,
    /// Only from Patch Tuesday to the Monday after it.
    pub patch_week_only: bool,
}

impl Default for Window {
    fn default() -> Self {
        Self { days: DAYS.iter().map(|d| d.to_string()).collect(), start: "01:00".into(), end: "06:00".into(), patch_week_only: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MaintenanceSettings {
    pub windows: Vec<Window>,
}

/// Every night 01:00-06:00 until someone sets it: the self-update ran at 03:00 before
/// windows existed, and this keeps it nightly.
impl Default for MaintenanceSettings {
    fn default() -> Self {
        Self { windows: vec![Window::default()] }
    }
}

pub const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

fn day_key(d: Weekday) -> &'static str {
    DAYS[d.num_days_from_monday() as usize]
}

fn hm(s: &str) -> Option<NaiveTime> {
    NaiveTime::parse_from_str(s.trim(), "%H:%M").ok()
}

/// The second Tuesday of the month - Microsoft's release day.
pub fn patch_tuesday(year: i32, month: u32) -> NaiveDate {
    let first = NaiveDate::from_ymd_opt(year, month, 1).unwrap();
    let to_tue = (7 + Weekday::Tue.num_days_from_monday() as i64 - first.weekday().num_days_from_monday() as i64) % 7;
    first + Duration::days(to_tue + 7)
}

/// Patch Tuesday up to and including the Monday after it.
pub fn in_patch_week(d: NaiveDate) -> bool {
    let pt = patch_tuesday(d.year(), d.month());
    d >= pt && d < pt + Duration::days(7)
}

impl MaintenanceSettings {
    /// Each window's problem, for the settings page; empty when all are fine.
    pub fn check(&self) -> Result<(), String> {
        for (i, w) in self.windows.iter().enumerate() {
            let n = i + 1;
            if w.days.is_empty() {
                return Err(format!("window {n} has no day"));
            }
            if let Some(d) = w.days.iter().find(|d| !DAYS.contains(&d.as_str())) {
                return Err(format!("window {n}: '{d}' is not a day"));
            }
            let (Some(s), Some(e)) = (hm(&w.start), hm(&w.end)) else {
                return Err(format!("window {n}: start and end are HH:MM"));
            };
            if s == e {
                return Err(format!("window {n} starts and ends at the same time"));
            }
        }
        Ok(())
    }

    /// Whether `at` is inside a window, and when that window closes.
    pub fn open_at(&self, at: NaiveDateTime) -> Option<NaiveDateTime> {
        self.windows.iter().find_map(|w| {
            let (s, e) = (hm(&w.start)?, hm(&w.end)?);
            // The window that opened today, and the one from yesterday that runs past midnight.
            [at.date(), at.date() - Duration::days(1)].into_iter().find_map(|day| {
                if !w.days.iter().any(|d| d == day_key(day.weekday())) || (w.patch_week_only && !in_patch_week(day)) {
                    return None;
                }
                let open = day.and_time(s);
                let close = if e > s { day.and_time(e) } else { (day + Duration::days(1)).and_time(e) };
                (at >= open && at < close).then_some(close)
            })
        })
    }

    pub fn open_now(&self) -> bool {
        self.open_at(Local::now().naive_local()).is_some()
    }

    /// When the next window opens (now, when one is open) - for "builds in the next window".
    pub fn next_open(&self, from: NaiveDateTime) -> Option<NaiveDateTime> {
        if self.open_at(from).is_some() {
            return Some(from);
        }
        let mut best: Option<NaiveDateTime> = None;
        for w in &self.windows {
            let Some(s) = hm(&w.start) else { continue };
            for i in 0..62 {
                let day = from.date() + Duration::days(i);
                if !w.days.iter().any(|d| d == day_key(day.weekday())) || (w.patch_week_only && !in_patch_week(day)) {
                    continue;
                }
                let open = day.and_time(s);
                if open > from {
                    if best.is_none_or(|b| open < b) {
                        best = Some(open);
                    }
                    break;
                }
            }
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M").unwrap()
    }

    #[test]
    fn patch_tuesday_is_the_second_tuesday() {
        assert_eq!(patch_tuesday(2026, 10), NaiveDate::from_ymd_opt(2026, 10, 13).unwrap());
        assert_eq!(patch_tuesday(2026, 9), NaiveDate::from_ymd_opt(2026, 9, 8).unwrap());
    }

    #[test]
    fn windows_open_and_close() {
        let m = MaintenanceSettings {
            windows: vec![Window { days: vec!["mon".into()], start: "22:00".into(), end: "02:00".into(), patch_week_only: false }],
        };
        // 2026-10-05 is a Monday.
        assert!(m.open_at(at("2026-10-05 23:00")).is_some());
        assert!(m.open_at(at("2026-10-06 01:59")).is_some());
        assert!(m.open_at(at("2026-10-06 02:00")).is_none());
        assert!(m.open_at(at("2026-10-05 21:59")).is_none());
        assert_eq!(m.next_open(at("2026-10-06 03:00")), Some(at("2026-10-12 22:00")));
    }

    #[test]
    fn patch_week_only() {
        let m = MaintenanceSettings {
            windows: vec![Window { days: DAYS.iter().map(|d| d.to_string()).collect(), start: "01:00".into(), end: "05:00".into(), patch_week_only: true }],
        };
        assert!(m.open_at(at("2026-10-05 02:00")).is_none());
        assert!(m.open_at(at("2026-10-13 02:00")).is_some());
        assert!(m.open_at(at("2026-10-19 02:00")).is_some());
        assert!(m.open_at(at("2026-10-20 02:00")).is_none());
    }
}
