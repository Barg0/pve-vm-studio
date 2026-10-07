//! Mail: reports to a smart host (Proxmox Mail Gateway, an Exchange relay), anonymously.
//!
//! The template is windows-feature-toolbox's (pwsh/Mail.ps1) carried over: the studio's
//! design language in what mail clients accept. Outlook draws HTML with the Word engine -
//! no flexbox, no <style> block, no SVG, no data: URIs - so it is tables and inline styles,
//! and the icons travel as PNG parts referenced by cid:, the one image path Outlook, OWA and
//! Gmail all render. The palette is one of the studio's themes (Mail card), token for token.

use anyhow::{Context, Result, bail};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Attachment, Mailbox, MultiPart, SinglePart, header::ContentType},
    transport::smtp::client::{Tls, TlsParameters},
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

include!(concat!(env!("OUT_DIR"), "/mail_icons.rs"));

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MailSettings {
    /// Off: nothing is sent, whatever else is filled in.
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    /// none | starttls | tls
    pub security: String,
    /// Off for a smart host with a certificate of its own making.
    pub verify_cert: bool,
    pub from: String,
    /// The sender's display name ("PVE VM Studio" <from>); empty sends the address alone.
    pub from_name: String,
    pub to: Vec<String>,
    pub timeout_sec: u64,
    /// One of the studio's themes (proxmox_dark, kaido_light ...) - the mail's colours.
    pub theme: String,
}

impl Default for MailSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            host: String::new(),
            port: 25,
            security: "none".into(),
            verify_cert: true,
            from: String::new(),
            from_name: "PVE VM Studio".into(),
            to: vec![],
            timeout_sec: 30,
            theme: DEFAULT_THEME.into(),
        }
    }
}

impl MailSettings {
    pub fn ready(&self) -> bool {
        self.enabled && !self.host.trim().is_empty() && !self.from.trim().is_empty() && !self.to.is_empty()
    }

    /// Off saves as it is; on, every field is required and has to be right.
    pub fn check(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.host.trim().is_empty() {
            bail!("the smart host is required");
        }
        if self.port == 0 {
            bail!("the port is required");
        }
        if self.from.trim().is_empty() {
            bail!("the sender address is required");
        }
        if !["none", "starttls", "tls"].contains(&self.security.as_str()) {
            bail!("security is none, starttls or tls");
        }
        self.from.trim().parse::<Mailbox>().with_context(|| format!("'{}' is not a mail address", self.from))?;
        if self.to.is_empty() {
            bail!("add at least one recipient");
        }
        for t in &self.to {
            t.trim().parse::<Mailbox>().with_context(|| format!("'{t}' is not a mail address"))?;
        }
        if !self.theme.is_empty() && !THEMES.iter().any(|t| t.0 == self.theme) {
            bail!("'{}' is not one of the studio's themes", self.theme);
        }
        Ok(())
    }
}

// ---- the template ----

/// The studio's default theme - and the mail's.
pub const DEFAULT_THEME: &str = "proxmox_dark";

/// The template's colours, from one of the studio's themes (build.rs reads them from
/// web/studio.js). The *_soft tones are the hue over the card at 16 %, flattened: a table
/// cell in a mail client has no rgba.
struct Palette {
    theme: &'static str,
    /// Every colour of the theme by key - the bands for a glyph's tile.
    colours: &'static [(&'static str, &'static str)],
    dark: bool,
    background: String,
    card: String,
    subtle: String,
    border: String,
    border_strong: String,
    divider: String,
    text: String,
    muted: String,
    accent: String,
    accent_soft: String,
    accent_text: String,
    danger: String,
    danger_soft: String,
    success: String,
    success_soft: String,
    warn: String,
    warn_soft: String,
    topbar: String,
    topbar_text: String,
}

/// a towards b by t (0 = a, 1 = b), as hex.
fn mix(a: &str, b: &str, t: f64) -> String {
    let p = |s: &str| u32::from_str_radix(s.trim_start_matches('#'), 16).unwrap_or(0);
    let (pa, pb) = (p(a), p(b));
    let ch = |v: u32, sh: u32| f64::from((v >> sh) & 255);
    let m = |sh| (ch(pa, sh) + (ch(pb, sh) - ch(pa, sh)) * t).round() as u32;
    format!("#{:02x}{:02x}{:02x}", m(16), m(8), m(0))
}

impl Palette {
    fn of(theme: &str) -> Self {
        let t = THEMES.iter().find(|t| t.0 == theme).or_else(|| THEMES.iter().find(|t| t.0 == DEFAULT_THEME)).expect("the default theme");
        let c = |k: &str| t.3.iter().find(|(n, _)| *n == k).map_or("#888888", |(_, v)| *v).to_owned();
        let card = c("elevated");
        let soft = |hue: &str| mix(&card, hue, 0.16);
        Self {
            theme: t.0,
            colours: t.3,
            dark: t.2,
            background: c("bg"),
            subtle: c("subtle"),
            border: c("border"),
            border_strong: c("borderStrong"),
            divider: c("divider"),
            text: c("fg"),
            muted: c("muted"),
            accent: c("accent"),
            accent_soft: c("accentSoft"),
            accent_text: if t.2 { c("accentHover") } else { c("accent") },
            danger_soft: soft(&c("danger")),
            danger: c("danger"),
            success_soft: soft(&c("success")),
            success: c("success"),
            warn_soft: soft(&c("warn")),
            warn: c("warn"),
            topbar: c("accent"),
            topbar_text: c("accentFg"),
            card,
        }
    }
}

impl Palette {
    /// A glyph's band colour (its template's band), the accent when it has none.
    fn hue_of(&self, icon: &str) -> String {
        let band = ICON_BANDS.iter().find(|(k, _)| *k == icon).map_or("accent", |(_, b)| *b);
        self.colours.iter().find(|(k, _)| *k == band).map_or_else(|| self.accent.clone(), |(_, v)| (*v).to_owned())
    }
    /// The step bar's hues, in order: the bands, then success.
    fn step_hue(&self, i: usize) -> String {
        let k = ["host", "ident", "deploy", "work", "linux"][i % 5];
        self.colours.iter().find(|(n, _)| *n == k).map_or_else(|| self.accent.clone(), |(_, v)| (*v).to_owned())
    }
}

/// The themes a mail can take: (id, name).
pub fn themes() -> Vec<(&'static str, &'static str)> {
    THEMES.iter().map(|t| (t.0, t.1)).collect()
}

const FONT: &str = "font-family:'Segoe UI','Segoe UI Web (West European)',-apple-system,BlinkMacSystemFont,Roboto,'Helvetica Neue',Arial,sans-serif";
const MONO: &str = "font-family:Consolas,'Cascadia Mono','Courier New','Liberation Mono',monospace";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Neutral,
    Accent,
    Success,
    Warn,
    Danger,
}

impl Tone {
    pub fn key(self) -> &'static str {
        match self {
            Tone::Neutral => "neutral",
            Tone::Accent => "accent",
            Tone::Success => "success",
            Tone::Warn => "warn",
            Tone::Danger => "danger",
        }
    }

    fn colours(self, p: &Palette) -> (String, String, String) {
        let (a, b, c) = match self {
            Tone::Neutral => (&p.muted, &p.subtle, &p.border),
            Tone::Accent => (&p.accent_text, &p.accent_soft, &p.accent),
            Tone::Success => (&p.success, &p.success_soft, &p.success),
            Tone::Warn => (&p.warn, &p.warn_soft, &p.warn),
            Tone::Danger => (&p.danger, &p.danger_soft, &p.danger),
        };
        (a.clone(), b.clone(), c.clone())
    }
}

/// A name, a value, and the line under it saying why it matters - factRow() on the page.
#[derive(Debug, Clone, Default)]
pub struct Fact {
    pub label: String,
    pub value: String,
    pub why: String,
    pub mono: bool,
    /// A glyph before the name (an ICONS key), or none.
    pub icon: &'static str,
}

impl Fact {
    pub fn icon(mut self, icon: &'static str) -> Self {
        self.icon = icon;
        self
    }
    pub fn why(mut self, why: impl Into<String>) -> Self {
        self.why = why.into();
        self
    }
}

/// One of the facts you act on, as a tile in a row of them: Address, Node, Gold, Time.
#[derive(Debug, Clone, Default)]
pub struct Tile {
    pub icon: &'static str,
    pub label: String,
    pub value: String,
    pub sub: String,
    pub mono: bool,
}

pub fn tile(icon: &'static str, label: &str, value: impl Into<String>, sub: impl Into<String>, mono: bool) -> Tile {
    Tile { icon, label: label.into(), value: value.into(), sub: sub.into(), mono }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepState {
    Done,
    Failed,
    Skipped,
}

/// A stage of a job and how long it took (the job's <id>.steps).
#[derive(Debug, Clone)]
pub struct Step {
    pub name: String,
    pub secs: i64,
    pub state: StepState,
}

/// One line of a list: a glyph, a name, a detail, a value at the right, a state.
#[derive(Debug, Clone, Default)]
pub struct Row {
    pub icon: &'static str,
    pub name: String,
    pub detail: String,
    pub right: String,
    pub state: Option<(Tone, String)>,
}

#[derive(Debug, Clone)]
pub struct Button {
    pub label: String,
    /// "#/golds" - made absolute with the studio's address when the mail goes out.
    pub link: String,
    pub icon: &'static str,
    pub primary: bool,
}

pub fn button(label: &str, link: &str, icon: &'static str, primary: bool) -> Button {
    Button { label: label.into(), link: link.into(), icon, primary }
}

/// Old and new, side by side (an update from one build to the next).
#[derive(Debug, Clone, Default)]
pub struct Compare {
    pub was: String,
    pub was_sub: String,
    pub now: String,
    pub now_sub: String,
}

/// How full something is, with the line where it alerts.
#[derive(Debug, Clone, Default)]
pub struct Meter {
    pub pct: u32,
    pub threshold: u32,
    pub left: String,
    pub right: String,
}

pub fn fact(label: &str, value: impl Into<String>) -> Fact {
    Fact { label: label.into(), value: value.into(), ..Default::default() }
}

pub fn mono(label: &str, value: impl Into<String>) -> Fact {
    Fact { label: label.into(), value: value.into(), mono: true, ..Default::default() }
}

#[derive(Debug, Clone, Default)]
pub struct Section {
    pub title: String,
    pub icon: &'static str,
    pub facts: Vec<Fact>,
    pub rows: Vec<Row>,
    /// Settings as chips: green when on, grey when off.
    pub chips: Vec<(String, bool)>,
    pub steps: Vec<Step>,
    pub note: String,
}

/// One mail. Every event fills the same layout: a title, the outcome as a pill, facts,
/// and the error when there is one.
#[derive(Debug, Clone)]
pub struct Report {
    pub subject: String,
    /// One of the ICONS keys.
    pub icon: &'static str,
    pub title: String,
    pub subtitle: String,
    pub status: String,
    pub tone: Tone,
    pub pills: Vec<(String, String)>,
    pub facts: Vec<Fact>,
    pub sections: Vec<Section>,
    pub notice: Option<(Tone, String)>,
    pub error: Option<String>,
    /// The log's last lines before the error.
    pub log_tail: Vec<String>,
    /// The job it came from - the bell opens that job's log.
    pub job: Option<String>,
    /// Where it can be looked at in the studio.
    pub link: Option<String>,
    pub tiles: Vec<Tile>,
    pub compare: Option<Compare>,
    pub meter: Option<Meter>,
    /// The mail's buttons; without any, `link` becomes "Open in the studio".
    pub buttons: Vec<Button>,
}

impl Report {
    pub fn new(subject: impl Into<String>, icon: &'static str, title: impl Into<String>, status: &str, tone: Tone) -> Self {
        Self {
            subject: subject.into(),
            icon,
            title: title.into(),
            subtitle: String::new(),
            status: status.to_owned(),
            tone,
            pills: vec![],
            facts: vec![],
            sections: vec![],
            notice: None,
            error: None,
            log_tail: vec![],
            job: None,
            link: None,
            tiles: vec![],
            compare: None,
            meter: None,
            buttons: vec![],
        }
    }
}

/// Everything put into the template goes through this: a DNS name or an error message is
/// not markup, and an unescaped '<' silently eats the rest of a row.
pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\n', "<br>")
}

fn icon(name: &str, size: u32, alt: &str) -> String {
    if !ICONS.iter().any(|(_, k, _)| *k == name) {
        return String::new();
    }
    format!(
        r#"<img src="cid:icon-{name}" width="{size}" height="{size}" alt="{}" style="display:block;border:0;outline:none;text-decoration:none;">"#,
        esc(alt)
    )
}

/// "OVER 85 %" -> "Over 85 %": the studio's state badges are in sentence case.
fn sentence(s: &str) -> String {
    let shouting = s.chars().any(char::is_alphabetic) && !s.chars().any(char::is_lowercase);
    let l = if shouting { s.to_lowercase() } else { s.to_owned() };
    let mut c = l.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
}

/// The studio's state badge: a dot and the word, tinted in the tone.
fn state_pill(p: &Palette, text: &str, tone: Tone) -> String {
    let (fg, bg, _) = tone.colours(p);
    format!(
        r#"<td style="padding:0 8px 8px 0;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td style="{FONT};font-size:12px;font-weight:600;padding:4px 9px;color:{fg};background:{bg};border-radius:4px;white-space:nowrap;"><span style="color:{fg};">&#9679;</span>&nbsp;{}</td></tr></table></td>"#,
        esc(&sentence(text))
    )
}

/// A plain fact as a badge: the label muted, the value in the text colour.
fn pill(p: &Palette, label: &str, value: &str) -> String {
    let label = if label.is_empty() { String::new() } else { format!(r#"<span style="color:{};">{}</span>&nbsp;&nbsp;"#, p.muted, esc(label)) };
    format!(
        r#"<td style="padding:0 8px 8px 0;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td style="{FONT};font-size:12px;padding:4px 9px;color:{};background:{};border-radius:4px;white-space:nowrap;">{label}<b>{}</b></td></tr></table></td>"#,
        p.text,
        p.subtle,
        esc(value)
    )
}

/// A glyph on a tile tinted in its band - the mail's title mark, and the size it is drawn at.
fn glyph_tile(p: &Palette, name: &str, box_px: u32, glyph_px: u32) -> String {
    let soft = mix(&p.card, &p.hue_of(name), 0.16);
    format!(
        r#"<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td width="{box_px}" height="{box_px}" align="center" valign="middle" bgcolor="{soft}" style="width:{box_px}px;height:{box_px}px;background:{soft};border-radius:4px;">{}</td></tr></table>"#,
        icon(name, glyph_px, "")
    )
}

fn tiles(p: &Palette, t: &[Tile]) -> String {
    if t.is_empty() {
        return String::new();
    }
    let w = 100 / t.len();
    let cells: String = t
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let (face, size) = if t.mono { (MONO, "14px") } else { (FONT, "15px") };
            let edge = if i == 0 { String::new() } else { format!("border-left:1px solid {};", p.border) };
            format!(
                r#"<td width="{w}%" valign="top" style="width:{w}%;padding:12px 14px;{edge}"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td width="13" style="width:13px;padding-right:6px;">{}</td><td style="{FONT};font-size:10.5px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;color:{};">{}</td></tr></table><div style="{face};font-size:{size};font-weight:600;color:{};padding-top:6px;word-break:break-word;">{}</div><div style="{FONT};font-size:11.5px;color:{};padding-top:2px;">{}</div></td>"#,
                icon(t.icon, 13, ""),
                p.muted,
                esc(&t.label),
                p.text,
                esc(&t.value),
                p.muted,
                esc(&t.sub)
            )
        })
        .collect();
    format!(r#"<tr><td style="padding:18px 26px 0;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border:1px solid {};"><tr>{cells}</tr></table></td></tr>"#, p.border)
}

fn duration_text(s: i64) -> String {
    if s >= 3600 { format!("{}h {:02}m", s / 3600, s % 3600 / 60) } else if s >= 60 { format!("{}m {:02}s", s / 60, s % 60) } else { format!("{s}s") }
}

/// A job's stages: one bar split by their share of the time, then one line each.
fn steps(p: &Palette, st: &[Step]) -> String {
    let total: i64 = st.iter().filter(|s| s.state != StepState::Skipped).map(|s| s.secs.max(1)).sum::<i64>().max(1);
    let hue = |i: usize, s: &Step| match s.state {
        StepState::Failed => p.danger.clone(),
        StepState::Skipped => p.border_strong.clone(),
        StepState::Done => p.step_hue(i),
    };
    let bar: String = st
        .iter()
        .enumerate()
        .filter(|(_, s)| s.state != StepState::Skipped)
        .map(|(i, s)| {
            let w = ((s.secs.max(1) * 1000 / total) as f64 / 10.0).max(1.0);
            format!(r#"<td width="{w:.1}%" style="width:{w:.1}%;height:8px;line-height:8px;font-size:0;background:{};">&nbsp;</td>"#, hue(i, s))
        })
        .collect();
    let rows: String = st
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let (colour, time) = match s.state {
                StepState::Failed => (p.danger.clone(), duration_text(s.secs)),
                StepState::Skipped => (p.muted.clone(), "&mdash;".to_owned()),
                StepState::Done => (p.text.clone(), duration_text(s.secs)),
            };
            let weight = if s.state == StepState::Failed { "600" } else { "400" };
            format!(
                r#"<tr><td width="20" style="width:20px;padding:6px 0;border-bottom:1px solid {div};{FONT};font-size:12px;color:{dot};">&#9679;</td><td style="padding:6px 0;border-bottom:1px solid {div};{FONT};font-size:13px;font-weight:{weight};color:{colour};">{}</td><td align="right" style="padding:6px 0;border-bottom:1px solid {div};{MONO};font-size:12px;color:{muted};">{time}</td></tr>"#,
                esc(&sentence(&s.name)),
                div = p.divider,
                dot = hue(i, s),
                muted = p.muted
            )
        })
        .collect();
    format!(
        r#"<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:10px;"><tr>{bar}</tr></table><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:8px;">{rows}</table>"#
    )
}

/// A list: glyph, name and detail, a value at the right, a state - in fixed columns, so
/// the values line up from row to row.
fn rows(p: &Palette, r: &[Row]) -> String {
    let lines: String = r
        .iter()
        .map(|r| {
            let state = r.state.as_ref().map(|(tone, text)| {
                let (fg, bg, _) = tone.colours(p);
                format!(r#"<span style="{FONT};font-size:11.5px;font-weight:600;padding:3px 8px;color:{fg};background:{bg};border-radius:4px;white-space:nowrap;"><span style="color:{fg};">&#9679;</span>&nbsp;{}</span>"#, esc(&sentence(text)))
            });
            let detail = if r.detail.is_empty() { String::new() } else { format!(r#"&nbsp;&nbsp;<span style="{MONO};font-size:11.5px;color:{};">{}</span>"#, p.muted, esc(&r.detail)) };
            format!(
                r#"<tr><td width="24" style="width:24px;padding:8px 0;border-bottom:1px solid {div};">{}</td><td style="padding:8px 0;border-bottom:1px solid {div};{FONT};font-size:13px;color:{};">{}{detail}</td><td width="120" align="right" style="width:120px;padding:8px 12px 8px 0;border-bottom:1px solid {div};{MONO};font-size:12px;color:{};">{}</td><td width="100" style="width:100px;padding:8px 0;border-bottom:1px solid {div};">{}</td></tr>"#,
                icon(r.icon, 16, ""),
                p.text,
                esc(&r.name),
                p.muted,
                esc(&r.right),
                state.unwrap_or_default(),
                div = p.divider
            )
        })
        .collect();
    format!(r#"<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:4px;">{lines}</table>"#)
}

/// Settings as chips: a green border when on, grey when off - no tick, the colour says it.
fn chips(p: &Palette, c: &[(String, bool)]) -> String {
    let all: String = c
        .iter()
        .map(|(label, on)| {
            let (fg, edge) = if *on { (p.success.clone(), mix(&p.border, &p.success, 0.6)) } else { (p.muted.clone(), p.border_strong.clone()) };
            format!(r#"<span style="display:inline-block;{FONT};font-size:12px;padding:3px 8px;margin:0 6px 6px 0;color:{fg};border:1px solid {edge};border-radius:4px;white-space:nowrap;">{}</span>"#, esc(label))
        })
        .collect();
    format!(r#"<div style="padding-top:10px;">{all}</div>"#)
}

fn compare(p: &Palette, c: &Compare) -> String {
    let cell = |k: &str, v: &str, sub: &str, colour: &str| {
        format!(
            r#"<td width="45%" valign="middle" style="width:45%;padding:14px 16px;"><div style="{FONT};font-size:10.5px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;color:{};">{k}</div><div style="{MONO};font-size:20px;font-weight:600;color:{colour};padding-top:4px;">{}</div><div style="{FONT};font-size:11.5px;color:{};padding-top:2px;">{}</div></td>"#,
            p.muted,
            esc(v),
            p.muted,
            esc(sub)
        )
    };
    format!(
        r#"<tr><td style="padding:18px 26px 0;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border:1px solid {};"><tr>{}<td width="10%" align="center" valign="middle" style="width:10%;{FONT};font-size:20px;color:{};">&rarr;</td>{}</tr></table></td></tr>"#,
        p.border,
        cell("Old", &c.was, &c.was_sub, &p.text),
        p.muted,
        cell("New", &c.now, &c.now_sub, &p.success)
    )
}

fn meter(p: &Palette, m: &Meter) -> String {
    let pct = m.pct.min(100);
    let fill = if pct >= m.threshold { &p.warn } else { &p.accent };
    let rest = if pct < 100 { format!(r#"<td style="height:12px;line-height:12px;font-size:0;background:{};">&nbsp;</td>"#, p.subtle) } else { String::new() };
    let th = m.threshold.min(99);
    format!(
        r#"<tr><td style="padding:18px 26px 0;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td width="{pct}%" style="width:{pct}%;height:12px;line-height:12px;font-size:0;background:{fill};">&nbsp;</td>{rest}</tr></table>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td width="{th}%" style="width:{th}%;height:5px;line-height:5px;font-size:0;">&nbsp;</td><td width="2" style="width:2px;height:5px;line-height:5px;font-size:0;background:{};">&nbsp;</td><td style="font-size:0;">&nbsp;</td></tr></table>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="{MONO};font-size:11.5px;color:{};padding-top:4px;">{}</td><td align="right" style="{MONO};font-size:11.5px;color:{};padding-top:4px;">{}</td></tr></table></td></tr>"#,
        p.text,
        p.muted,
        esc(&m.left),
        p.muted,
        esc(&m.right)
    )
}

/// The error: its first line as the headline, the log's last lines under it.
fn error_box(p: &Palette, e: &str, tail: &[String]) -> String {
    let e = if e.trim().is_empty() { "The step failed without a message. The job's log has the detail." } else { e.trim() };
    let (head, rest) = e.split_once('\n').unwrap_or((e, ""));
    let mut lines: Vec<String> = tail.to_vec();
    if !rest.trim().is_empty() {
        lines.extend(rest.lines().map(str::to_owned));
    }
    let log = if lines.is_empty() {
        String::new()
    } else {
        let body: String = lines
            .iter()
            .map(|l| {
                let c = if l.contains("[ error") || l.contains("[ fail") { &p.danger } else { &p.text };
                format!(r#"<div style="color:{c};">{}</div>"#, esc(l))
            })
            .collect();
        format!(r#"<tr><td style="padding:10px 14px;background:{};border-top:1px solid {};{MONO};font-size:11.5px;line-height:1.6;word-break:break-word;">{body}</td></tr>"#, p.subtle, mix(&p.border, &p.danger, 0.3))
    };
    format!(
        r#"<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border:1px solid {};background:{};"><tr><td style="padding:10px 14px;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td width="16" style="width:16px;padding-right:10px;">{}</td><td style="{FONT};font-size:13px;font-weight:600;color:{};">{}</td></tr></table></td></tr>{log}</table>"#,
        mix(&p.border, &p.danger, 0.45),
        p.danger_soft,
        icon("security", 16, ""),
        p.danger,
        esc(head)
    )
}

fn buttons(p: &Palette, b: &[Button]) -> String {
    let cells: String = b
        .iter()
        .filter(|b| !b.link.is_empty())
        .map(|b| {
            let (bg, fg, edge) = if b.primary { (p.accent.clone(), p.topbar_text.clone(), p.accent.clone()) } else { (p.card.clone(), p.text.clone(), p.border_strong.clone()) };
            let glyph = if b.icon.is_empty() || b.primary { String::new() } else { format!(r#"<td width="14" valign="middle" style="width:14px;padding:0 7px 0 0;">{}</td>"#, icon(b.icon, 14, "")) };
            format!(
                r#"<td style="padding:0 8px 8px 0;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td style="background:{bg};border:1px solid {edge};border-radius:2px;"><a href="{}" style="{FONT};display:block;padding:8px 14px;font-size:12.5px;font-weight:600;color:{fg};text-decoration:none;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>{glyph}<td style="{FONT};font-size:12.5px;font-weight:600;color:{fg};">{}</td></tr></table></a></td></tr></table></td>"#,
                esc(&b.link),
                esc(&b.label)
            )
        })
        .collect();
    if cells.is_empty() {
        return String::new();
    }
    format!(r#"<tr><td style="padding:22px 26px 18px;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>{cells}</tr></table></td></tr>"#)
}

fn fact_row(p: &Palette, f: &Fact) -> String {
    let (face, size) = if f.mono { (MONO, "12px") } else { (FONT, "13px") };
    let (value, colour) = if f.value.trim().is_empty() { ("&mdash;".to_owned(), &p.muted) } else { (esc(&f.value), &p.text) };
    // break-all belongs to a hash or a URL, never to a sentence.
    let wrap = if f.mono { "word-break:break-all;" } else { "word-break:break-word;" };
    let why = if f.why.is_empty() {
        String::new()
    } else {
        format!(r#"<div style="{FONT};font-size:11.5px;color:{};padding-top:3px;line-height:1.5;">{}</div>"#, p.muted, esc(&f.why))
    };
    let glyph = if f.icon.is_empty() { String::new() } else { format!(r#"<td width="22" valign="top" style="width:22px;padding:9px 0 0;">{}</td>"#, icon(f.icon, 14, "")) };
    format!(
        r#"<tr><td width="160" valign="top" style="width:160px;padding:0;border-bottom:1px solid {div};"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>{glyph}<td valign="top" style="{FONT};font-size:13px;color:{};padding:8px 16px 8px 0;white-space:nowrap;">{}</td></tr></table></td><td valign="top" style="{face};font-size:{size};color:{colour};padding:8px 0;line-height:1.5;border-bottom:1px solid {div};{wrap}">{value}{why}</td></tr>"#,
        p.muted,
        esc(&f.label),
        div = p.divider
    )
}

fn section_head(p: &Palette, title: &str, glyph: &str) -> String {
    let mut mark = icon(glyph, 16, title);
    if mark.is_empty() {
        mark = format!(r#"<div style="width:10px;height:10px;line-height:10px;font-size:0;background:{};">&nbsp;</div>"#, p.accent);
    }
    format!(
        r#"<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td width="16" valign="middle" style="width:16px;padding-right:10px;">{mark}</td><td valign="middle" style="{FONT};font-size:11px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:{};">{}</td></tr></table>"#,
        p.muted,
        esc(title)
    )
}

fn notice(p: &Palette, tone: Tone, title: &str, text: &str) -> String {
    let (edge, back, head) = match tone {
        Tone::Warn => (&p.warn, &p.warn_soft, &p.warn),
        Tone::Danger => (&p.danger, &p.danger_soft, &p.danger),
        Tone::Success => (&p.success, &p.success_soft, &p.success),
        _ => (&p.accent, &p.accent_soft, &p.accent_text),
    };
    let title = if title.is_empty() {
        String::new()
    } else {
        format!(r#"<div style="{FONT};font-size:11px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:{head};padding-bottom:6px;">{}</div>"#, esc(title))
    };
    format!(
        r#"<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:{back};border-left:3px solid {edge};"><tr><td style="padding:14px 18px;">{title}<div style="{FONT};font-size:12.5px;line-height:1.6;color:{};">{}</div></td></tr></table>"#,
        p.text,
        esc(text)
    )
}

/// The mark drawn in table cells, for the client that blocked images: three stepped bars,
/// the studio's own shape, in the topbar's ink.
fn logo(p: &Palette) -> String {
    let ink = &p.topbar_text;
    let bar = |w: u32| format!(r#"<tr><td style="height:4px;line-height:4px;font-size:0;mso-line-height-rule:exactly;background:{ink};width:{w}px;">&nbsp;</td></tr>"#);
    let gap = r#"<tr><td style="height:2px;line-height:2px;font-size:0;mso-line-height-rule:exactly;">&nbsp;</td></tr>"#;
    let img = icon("mark", 20, "PVE VM Studio");
    if !img.is_empty() {
        return img;
    }
    format!(r#"<table role="presentation" cellpadding="0" cellspacing="0" border="0">{}{gap}{}{gap}{}</table>"#, bar(12), bar(12), bar(12))
}

/// The HTML of a report in one of the studio's themes, and the icons it uses (their PNGs:
/// icon_png with the same theme).
pub fn render(r: &Report, studio: &str, node: &str, theme: &str) -> (String, Vec<&'static str>) {
    let p = &Palette::of(theme);
    let mut pills = state_pill(p, &r.status, r.tone);
    for (l, v) in &r.pills {
        pills += &pill(p, l, v);
    }
    let mut blocks = String::new();
    blocks += &tiles(p, &r.tiles);
    if let Some(c) = &r.compare {
        blocks += &compare(p, c);
    }
    if let Some(m) = &r.meter {
        blocks += &meter(p, m);
    }
    if !r.facts.is_empty() {
        blocks += &format!(
            r#"<tr><td style="padding:14px 26px 0;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">{}</table></td></tr>"#,
            r.facts.iter().map(|f| fact_row(p, f)).collect::<String>()
        );
    }
    if let Some(e) = &r.error {
        blocks += &format!(
            r#"<tr><td style="padding:22px 26px 8px;">{}</td></tr><tr><td style="padding:0 26px;">{}</td></tr>"#,
            section_head(p, "Error", "security"),
            error_box(p, e, &r.log_tail)
        );
    }
    for s in &r.sections {
        let mut body = String::new();
        if !s.steps.is_empty() {
            body += &steps(p, &s.steps);
        }
        if !s.facts.is_empty() {
            body += &format!(r#"<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">{}</table>"#, s.facts.iter().map(|f| fact_row(p, f)).collect::<String>());
        }
        if !s.chips.is_empty() {
            body += &chips(p, &s.chips);
        }
        if !s.rows.is_empty() {
            body += &rows(p, &s.rows);
        }
        if !s.note.is_empty() {
            body += &format!(r#"<div style="{FONT};font-size:12px;color:{};line-height:1.6;padding-top:10px;">{}</div>"#, p.muted, esc(&s.note));
        }
        blocks += &format!(
            r#"<tr><td style="padding:22px 26px 0;"><div style="padding-bottom:8px;border-bottom:1px solid {};">{}</div>{body}</td></tr>"#,
            p.divider,
            section_head(p, &s.title, s.icon)
        );
    }
    if let Some((tone, text)) = &r.notice {
        blocks += &format!(r#"<tr><td style="padding:18px 26px 0;">{}</td></tr>"#, notice(p, *tone, "", text));
    }
    let mut bs = r.buttons.clone();
    if bs.is_empty()
        && let Some(l) = &r.link
    {
        bs.push(button("Open in the studio", l, "", true));
    }
    let link = Some(buttons(p, &bs)).filter(|b| !b.is_empty()).unwrap_or_else(|| r#"<tr><td style="padding:12px 0 0;"></td></tr>"#.to_owned());
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let html = format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="color-scheme" content="{scheme}"><meta name="supported-color-schemes" content="{scheme}"><meta name="darkreader-lock"><title>{subject}</title></head><body style="margin:0;padding:0;background:{bg};">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{bg}" style="background:{bg};margin:0;padding:0;">
<tr><td align="center" style="padding:32px 16px;">
<table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" bgcolor="{card}" style="width:640px;max-width:640px;background:{card};border:1px solid {border};">
  <tr><td style="background:{topbar};padding:14px 26px;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      <td width="24" style="width:24px;padding-right:12px;">{logo}</td>
      <td style="{FONT};font-size:13px;font-weight:600;color:{topbar_text};">PVE VM Studio</td>
      <td align="right" style="{FONT};font-size:13px;font-weight:600;color:{topbar_text};text-decoration:none;">{node}</td>
    </tr></table>
  </td></tr>
  <tr><td style="padding:26px 26px 0;">
    <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
      <td width="48" valign="middle" style="width:48px;padding:0 16px 0 0;">{glyph}</td>
      <td valign="middle">
        <div style="{FONT};font-size:20px;font-weight:600;color:{text};line-height:1.3;">{title}</div>
        <div style="{FONT};font-size:12.5px;color:{muted};padding-top:4px;">{subtitle}</div>
      </td>
    </tr></table>
  </td></tr>
  <tr><td style="padding:18px 26px 0;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>{pills}</tr></table></td></tr>
  {blocks}
  {link}
  <tr><td style="padding:20px 26px 24px;background:{subtle};border-top:1px solid {divider};">
    <div style="{FONT};font-size:11.5px;color:{muted};line-height:1.7;">
      {studio_line}Sent {now}<br>
      <span style="color:{border_strong};">Automated notification &mdash; nobody reads replies to it.</span>
    </div>
  </td></tr>
</table>
</td></tr>
</table></body></html>"#,
        subject = esc(&r.subject),
        scheme = if p.dark { "dark" } else { "light" },
        bg = p.background,
        card = p.card,
        border = p.border,
        border_strong = p.border_strong,
        topbar = p.topbar,
        topbar_text = p.topbar_text,
        text = p.text,
        muted = p.muted,
        divider = p.divider,
        subtle = p.subtle,
        logo = logo(p),
        // A zero-width space after each dot: mail clients find no address to turn into a link.
        node = esc(node).replace('.', ".&#8203;"),
        glyph = glyph_tile(p, r.icon, 48, 26),
        title = esc(&r.title),
        subtitle = esc(&r.subtitle),
        link = link,
        studio_line = if studio.is_empty() { String::new() } else { format!(r#"<span style="{MONO};color:{};">{}</span><br>"#, p.text, esc(studio)) },
    );
    let used = ICONS.iter().filter(|(t, _, _)| *t == p.theme).map(|(_, k, _)| *k).filter(|k| html.contains(&format!("cid:icon-{k}\""))).collect();
    (html, used)
}

/// An icon's PNG in a theme (the default theme's when the theme has none).
pub fn icon_png(theme: &str, key: &str) -> &'static [u8] {
    let find = |th: &str| ICONS.iter().find(|(t, k, _)| *t == th && *k == key).map(|(_, _, b)| *b);
    find(theme).or_else(|| find(DEFAULT_THEME)).unwrap_or_default()
}

/// A sample report in a theme, its icons inlined - the Mail card's preview.
pub fn preview(theme: &str, studio: &str, node: &str) -> String {
    let mut r = Report::new("VM provisioned: vm-ws2025-01", "vm-work", "vm-ws2025-01 is ready", "PROVISIONED", Tone::Success);
    r.subtitle = "Windows Server 2025 Datacenter Desktop · from gold 9ce03b74".into();
    r.pills = vec![("Started by".into(), "root@pam".into())];
    r.tiles = vec![
        tile("static-ip", "Address", "10.10.0.50", "/24 · net0 · vmbr0", true),
        tile("servers", "Node", "pve-01", "VMID 101", true),
        tile("gold-image-work", "Gold", "9ce03b74", "26100.33438", true),
        tile("clock", "Time", "2m 43s", "09:54 - 09:56", false),
    ];
    let step = |n: &str, s| Step { name: n.into(), secs: s, state: StepState::Done };
    r.sections.push(Section {
        title: "Steps".into(),
        icon: "clock",
        steps: vec![step("cloning the gold", 42), step("building the seed", 4), step("WinPE deploy pass", 40), step("first boot", 48), step("waiting for an address", 26)],
        ..Default::default()
    });
    r.sections.push(Section {
        title: "Configuration".into(),
        icon: "cpu",
        facts: vec![
            fact("Domain", "Workgroup").icon("users"),
            fact("Network", "net0 · vmbr0 · untagged").icon("vnet").why("gateway 10.10.0.1 · DNS 10.10.0.1"),
            fact("Compute", "4 vCPU · 4 GB").icon("cpu"),
            fact("Disks", "scsi0 · 64 GB on local-lvm · full copy").icon("disk"),
        ],
        ..Default::default()
    });
    let base = if studio.is_empty() { "#".to_owned() } else { format!("{studio}/#") };
    r.buttons = vec![button("Open the VM", &format!("{base}/access"), "vm-work", true), button("Log", &format!("{base}/jobs"), "log", false)];
    let (mut html, used) = render(&r, studio, node, theme);
    use base64::Engine;
    for k in used {
        html = html.replace(&format!("cid:icon-{k}\""), &format!("data:image/png;base64,{}\"", base64::engine::general_purpose::STANDARD.encode(icon_png(theme, k))));
    }
    html
}


/// The same report as plain text, for the client that shows no HTML.
pub fn plain(r: &Report) -> String {
    let mut s = format!("{}\n{}\n\nStatus: {}\n", r.title, r.subtitle, r.status);
    for (l, v) in &r.pills {
        s += &format!("{l}: {v}\n");
    }
    for t in &r.tiles {
        s += &format!("{}: {}{}\n", t.label, t.value, if t.sub.is_empty() { String::new() } else { format!(" ({})", t.sub) });
    }
    if let Some(c) = &r.compare {
        s += &format!("Old: {} ({})\nNew: {} ({})\n", c.was, c.was_sub, c.now, c.now_sub);
    }
    if let Some(m) = &r.meter {
        s += &format!("{} % full - {} - {}\n", m.pct, m.left, m.right);
    }
    for f in &r.facts {
        s += &format!("{}: {}\n", f.label, f.value);
    }
    if let Some(e) = &r.error {
        s += &format!("\nError:\n{e}\n");
        for l in &r.log_tail {
            s += &format!("  {l}\n");
        }
    }
    for sec in &r.sections {
        s += &format!("\n{}\n", sec.title);
        for st in &sec.steps {
            let t = match st.state {
                StepState::Skipped => "not reached".to_owned(),
                StepState::Failed => format!("{} - failed", duration_text(st.secs)),
                StepState::Done => duration_text(st.secs),
            };
            s += &format!("  {}: {t}\n", sentence(&st.name));
        }
        for f in &sec.facts {
            s += &format!("  {}: {}\n", f.label, f.value);
        }
        if !sec.chips.is_empty() {
            s += &format!("  {}\n", sec.chips.iter().map(|(c, on)| format!("{c}: {}", if *on { "on" } else { "off" })).collect::<Vec<_>>().join(", "));
        }
        for r in &sec.rows {
            s += &format!("  {} {} {} {}\n", r.name, r.detail, r.right, r.state.as_ref().map(|(_, t)| sentence(t)).unwrap_or_default());
        }
        if !sec.note.is_empty() {
            s += &format!("  {}\n", sec.note);
        }
    }
    if let Some((_, n)) = &r.notice {
        s += &format!("\n{n}\n");
    }
    for b in r.buttons.iter().filter(|b| !b.link.is_empty()) {
        s += &format!("\n{}: {}", b.label, b.link);
    }
    if r.buttons.is_empty()
        && let Some(l) = &r.link
    {
        s += &format!("\n{l}\n");
    }
    s
}

// ---- sending ----

/// Sends a report. `studio` is the studio's own address for the footer and links; `event`
/// names it in the mail log (a notification's key, or "test"). Every mail that gets as far
/// as the smart host goes into the log with the answer - or the reason there was none.
pub async fn send(db: &SqlitePool, event: &str, m: &MailSettings, r: &Report, studio: &str, node: &str) -> Result<String> {
    if !m.enabled {
        bail!("mail is switched off - Studio settings → Mail");
    }
    if !m.ready() {
        bail!("mail is not set up - Studio settings → Mail");
    }
    m.check()?;
    let (html, used) = render(r, studio, node, &m.theme);
    let mut related = MultiPart::related().singlepart(SinglePart::html(html));
    for k in used {
        let png = icon_png(&m.theme, k).to_vec();
        related = related.singlepart(Attachment::new_inline(format!("icon-{k}")).body(png, ContentType::parse("image/png").unwrap()));
    }
    let body = MultiPart::alternative().singlepart(SinglePart::plain(plain(r))).multipart(related);
    let name = m.from_name.trim();
    let from = Mailbox::new((!name.is_empty()).then(|| name.to_owned()), m.from.trim().parse()?);
    let mut msg = Message::builder().from(from).subject(&r.subject);
    for t in &m.to {
        msg = msg.to(t.trim().parse()?);
    }
    let msg = msg.multipart(body)?;

    let host = m.host.trim();
    let tls = || TlsParameters::builder(host.to_owned()).dangerous_accept_invalid_certs(!m.verify_cert).build_rustls();
    let mut b = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host).port(m.port);
    b = match m.security.as_str() {
        "starttls" => b.tls(Tls::Required(tls()?)),
        "tls" => b.tls(Tls::Wrapper(tls()?)),
        _ => b.tls(Tls::None),
    };
    let transport = b.timeout(Some(std::time::Duration::from_secs(m.timeout_sec.clamp(5, 300)))).build();
    let started = std::time::Instant::now();
    let sent = transport.send(msg).await;
    let mut row = LogRow {
        at: chrono::Utc::now().to_rfc3339(),
        event: event.to_owned(),
        subject: r.subject.clone(),
        sender: m.from.trim().to_owned(),
        recipients: m.to.iter().map(|t| t.trim().to_owned()).collect(),
        host: format!("{host}:{}", m.port),
        security: m.security.clone(),
        took_ms: started.elapsed().as_millis() as i64,
        ..LogRow::default()
    };
    match &sent {
        Ok(reply) => {
            row.ok = true;
            row.code = Some(i64::from(u16::from(reply.code())));
            row.reply = reply.message().collect::<Vec<_>>().join("\n");
        }
        Err(e) => {
            row.code = e.status().map(|c| i64::from(u16::from(c)));
            (row.error, row.reply) = smtp_error(e);
        }
    }
    if let Err(e) = log_row(db, &row).await {
        tracing::warn!("mail log: {e:#}");
    }
    match sent {
        Ok(reply) => Ok(reply.message().collect::<Vec<_>>().join(" ")),
        Err(_) if !row.reply.is_empty() => bail!("{} {}: {}", row.host, row.error, row.reply),
        Err(_) => bail!("{}: {}", row.host, row.error),
    }
}

/// Why a send failed: (what happened, the smart host's answer if it gave one). Without an
/// answer the first part carries what went wrong on the way - connection, TLS, timeout -
/// with its causes, each once.
fn smtp_error(e: &lettre::transport::smtp::Error) -> (String, String) {
    let what = if e.is_timeout() {
        "timed out"
    } else if e.is_tls() {
        "TLS failed"
    } else if e.is_permanent() {
        "refused (permanent)"
    } else if e.is_transient() {
        "refused for now (transient)"
    } else {
        "could not talk to the smart host"
    };
    let text = e.to_string();
    // "permanent error (550): 5.1.1 <x>: Recipient address rejected ..." - the answer is
    // what follows the code.
    if e.status().is_some() {
        let answer = text.split_once("): ").map_or(text.as_str(), |(_, a)| a);
        return (what.to_owned(), answer.lines().map(str::trim).collect::<Vec<_>>().join("\n"));
    }
    let mut why = text;
    let mut src = std::error::Error::source(e);
    while let Some(s) = src {
        let part = s.to_string();
        if !why.contains(&part) {
            why.push_str(": ");
            why.push_str(&part);
        }
        src = s.source();
    }
    (format!("{what} - {why}"), String::new())
}

// ---- the mail log ----

/// One mail the studio handed to the smart host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogRow {
    pub at: String,
    pub event: String,
    pub subject: String,
    pub sender: String,
    pub recipients: Vec<String>,
    pub host: String,
    pub security: String,
    pub ok: bool,
    pub code: Option<i64>,
    pub reply: String,
    pub error: String,
    pub took_ms: i64,
}

/// The rows kept: enough for a month of nightly runs and every failure around them.
const LOG_KEEP: i64 = 200;

async fn log_row(db: &SqlitePool, r: &LogRow) -> Result<()> {
    sqlx::query(
        "INSERT INTO mail_log (at, event, subject, sender, recipients, host, security, ok, code, reply, error, took_ms) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&r.at)
    .bind(&r.event)
    .bind(&r.subject)
    .bind(&r.sender)
    .bind(serde_json::to_string(&r.recipients)?)
    .bind(&r.host)
    .bind(&r.security)
    .bind(r.ok)
    .bind(r.code)
    .bind(&r.reply)
    .bind(&r.error)
    .bind(r.took_ms)
    .execute(db)
    .await?;
    sqlx::query("DELETE FROM mail_log WHERE id NOT IN (SELECT id FROM mail_log ORDER BY id DESC LIMIT ?)").bind(LOG_KEEP).execute(db).await?;
    Ok(())
}

/// The newest rows first.
pub async fn log(db: &SqlitePool, limit: i64) -> Result<Vec<LogRow>> {
    type Raw = (String, String, String, String, String, String, String, bool, Option<i64>, String, String, i64);
    let rows: Vec<Raw> = sqlx::query_as(
        "SELECT at, event, subject, sender, recipients, host, security, ok, code, reply, error, took_ms FROM mail_log ORDER BY id DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(at, event, subject, sender, to, host, security, ok, code, reply, error, took_ms)| LogRow {
            at,
            event,
            subject,
            sender,
            recipients: serde_json::from_str(&to).unwrap_or_default(),
            host,
            security,
            ok,
            code,
            reply,
            error,
            took_ms,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Report {
        let mut r = Report::new("Windows Server 2025 golds updated to 26100.4202", "update", "Updated to 26100.4202", "DONE", Tone::Success);
        r.subtitle = "Windows Server 2025 · 2026-10 B".into();
        r.pills = vec![("From".into(), "26100.4061".into()), ("To".into(), "26100.4202".into())];
        r.facts = vec![mono("New ISO", "local:iso/enus-ws2025-dc-26100.4202.iso"), mono("Old ISO", "local:iso/enus-ws2025-dc-26100.4061.iso")];
        r.sections.push(Section { title: "Golds".into(), icon: "gold-image", facts: vec![Fact { label: "7c41e09a".into(), value: "→ 1f0b33aa · ws2025-datacenter-core".into(), mono: true, ..Default::default() }], ..Default::default() });
        r.error = Some("cleanup: <b>not</b> escaped would break".into());
        r.link = Some("https://studio.example.com/#/golds".into());
        r
    }

    #[test]
    fn renders_escaped_with_its_icons() {
        let (html, used) = render(&sample(), "https://studio.example.com", "pve-vm-studio", DEFAULT_THEME);
        assert!(html.contains("&lt;b&gt;not&lt;/b&gt;"));
        assert!(used.contains(&"update") && used.contains(&"mark") && used.contains(&"gold-image") && used.contains(&"security"));
        assert!(!html.contains("@H"));
        // MAIL_PREVIEW=/path.html cargo test writes the sample out for a look in a browser.
        if let Ok(p) = std::env::var("MAIL_PREVIEW") {
            let mut h = html.clone();
            for k in &used {
                let png = icon_png(DEFAULT_THEME, k);
                use base64::Engine;
                h = h.replace(&format!("cid:icon-{k}\""), &format!("data:image/png;base64,{}\"", base64::engine::general_purpose::STANDARD.encode(png)));
            }
            std::fs::write(&p, h).unwrap();
            // The Mail card's preview (a VM provisioned) beside it, in the default theme.
            std::fs::write(format!("{p}.preview.html"), preview(DEFAULT_THEME, "https://studio.example.com", "pve-01")).unwrap();
        }
    }
}
