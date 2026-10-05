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
    topbar_muted: String,
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
            topbar_muted: mix(&c("accentFg"), &c("accent"), 0.45),
            card,
        }
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
}

pub fn fact(label: &str, value: impl Into<String>) -> Fact {
    Fact { label: label.into(), value: value.into(), ..Default::default() }
}

pub fn mono(label: &str, value: impl Into<String>) -> Fact {
    Fact { label: label.into(), value: value.into(), mono: true, ..Default::default() }
}

#[derive(Debug, Clone)]
pub struct Section {
    pub title: String,
    pub icon: &'static str,
    pub facts: Vec<Fact>,
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
    /// Where it can be looked at in the studio.
    pub link: Option<String>,
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
            link: None,
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

fn pill(p: &Palette, label: &str, value: &str, tone: Tone) -> String {
    let (fg, bg, border) = tone.colours(p);
    let label = if label.is_empty() { String::new() } else { format!(r#"<span style="color:{};">{}</span>&nbsp;&nbsp;"#, p.muted, esc(label)) };
    // 4px, the studio's radius - a pill there is a rounded rectangle, never a lozenge.
    format!(
        r#"<td style="padding:0 8px 8px 0;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td style="{FONT};font-size:10px;letter-spacing:1px;text-transform:uppercase;padding:5px 10px;color:{fg};background:{bg};border:1px solid {border};border-radius:4px;white-space:nowrap;">{label}<b>{}</b></td></tr></table></td>"#,
        esc(value)
    )
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
    format!(
        r#"<tr><td width="150" valign="top" style="width:150px;{FONT};font-size:11px;letter-spacing:.6px;text-transform:uppercase;color:{};padding:9px 20px 3px 0;white-space:nowrap;">{}</td><td valign="top" style="{face};font-size:{size};color:{colour};padding:8px 0 3px 0;line-height:1.5;{wrap}">{value}{why}</td></tr>"#,
        p.muted,
        esc(&f.label)
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
    let mut pills = pill(p, "Status", &r.status, r.tone);
    for (l, v) in &r.pills {
        pills += &pill(p, l, v, Tone::Neutral);
    }
    let facts: String = r.facts.iter().map(|f| fact_row(p, f)).collect();
    let mut blocks = String::new();
    if let Some(e) = &r.error {
        blocks += &format!(
            r#"<tr><td style="padding:18px 26px 6px;">{}</td></tr><tr><td style="padding:2px 26px 14px;">{}</td></tr>"#,
            section_head(p, "What went wrong", "security"),
            notice(p, Tone::Danger, "Error", if e.trim().is_empty() { "The step failed without a message. The job's log has the detail." } else { e })
        );
    }
    for s in &r.sections {
        blocks += &format!(
            r#"<tr><td style="padding:18px 26px 6px;">{}</td></tr><tr><td style="padding:2px 26px 20px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">{}</table></td></tr>"#,
            section_head(p, &s.title, s.icon),
            s.facts.iter().map(|f| fact_row(p, f)).collect::<String>()
        );
    }
    if let Some((tone, text)) = &r.notice {
        blocks += &format!(r#"<tr><td style="padding:6px 26px 22px;">{}</td></tr>"#, notice(p, *tone, "", text));
    }
    let link = r.link.as_deref().map(|l| {
        format!(
            r#"<tr><td style="padding:4px 26px 24px;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td style="background:{};border-radius:2px;"><a href="{}" style="{FONT};display:inline-block;padding:8px 16px;font-size:12.5px;font-weight:600;color:{};text-decoration:none;">Open in the studio</a></td></tr></table></td></tr>"#,
            p.accent,
            esc(l),
            p.topbar_text
        )
    });
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
      <td align="right" style="{FONT};font-size:11.5px;color:{topbar_muted};">{node}</td>
    </tr></table>
  </td></tr>
  <tr><td style="padding:26px 26px 0;">
    <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
      <td width="28" valign="top" style="width:28px;padding:2px 14px 0 0;">{glyph}</td>
      <td valign="top">
        <div style="{FONT};font-size:20px;font-weight:600;color:{text};line-height:1.3;">{title}</div>
        <div style="{FONT};font-size:12.5px;color:{muted};padding-top:6px;">{subtitle}</div>
      </td>
    </tr></table>
  </td></tr>
  <tr><td style="padding:20px 26px 0;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>{pills}</tr></table></td></tr>
  <tr><td style="padding:10px 26px 22px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">{facts}</table></td></tr>
  <tr><td style="padding:0 26px;"><div style="height:1px;line-height:1px;font-size:0;background:{divider};">&nbsp;</div></td></tr>
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
        topbar_muted = p.topbar_muted,
        text = p.text,
        muted = p.muted,
        divider = p.divider,
        subtle = p.subtle,
        logo = logo(p),
        node = esc(node),
        glyph = icon(r.icon, 28, &r.title),
        title = esc(&r.title),
        subtitle = esc(&r.subtitle),
        link = link.unwrap_or_default(),
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
    let mut r = Report::new("Windows Server 2025 golds updated to 26100.33438", "update", "Updated to 26100.33438", "DONE", Tone::Success);
    r.subtitle = "Windows Server 2025 · 2026-09 B".into();
    r.pills = vec![("From".into(), "26100.32995".into()), ("To".into(), "26100.33438".into())];
    r.facts = vec![
        mono("New ISO", "local:iso/enus-ws2025-dc-26100.33438.iso"),
        mono("Old ISO", "local:iso/enus-ws2025-dc-26100.32995.iso"),
        fact("Took", "1 h 12 min"),
    ];
    r.sections.push(Section {
        title: "Golds".into(),
        icon: "os-window",
        facts: vec![
            Fact { label: "7d2c4b19".into(), value: "→ 1f0b33aa · ws2025-datacenter-core".into(), why: String::new(), mono: true },
            Fact { label: "9f4e6a03".into(), value: "→ 5c2e81d0 · ws2025-datacenter-desktop".into(), why: String::new(), mono: true },
        ],
    });
    r.error = Some("A sample of the error block: a failed step's own message goes here.".into());
    r.notice = Some((Tone::Accent, "A sample notice: what to do next, when there is something to do.".into()));
    r.link = Some(if studio.is_empty() { "#".into() } else { format!("{studio}/#/golds") });
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
    for f in &r.facts {
        s += &format!("{}: {}\n", f.label, f.value);
    }
    if let Some(e) = &r.error {
        s += &format!("\nWhat went wrong:\n{e}\n");
    }
    for sec in &r.sections {
        s += &format!("\n{}\n", sec.title);
        for f in &sec.facts {
            s += &format!("  {}: {}\n", f.label, f.value);
        }
    }
    if let Some((_, n)) = &r.notice {
        s += &format!("\n{n}\n");
    }
    if let Some(l) = &r.link {
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
    let mut msg = Message::builder().from(m.from.trim().parse()?).subject(&r.subject);
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
        r.sections.push(Section { title: "Golds".into(), icon: "os-window", facts: vec![Fact { label: "7c41e09a".into(), value: "→ 1f0b33aa · ws2025-datacenter-core".into(), why: String::new(), mono: true }] });
        r.error = Some("cleanup: <b>not</b> escaped would break".into());
        r.link = Some("https://studio.example.com/#/golds".into());
        r
    }

    #[test]
    fn renders_escaped_with_its_icons() {
        let (html, used) = render(&sample(), "https://studio.example.com", "pve-vm-studio", DEFAULT_THEME);
        assert!(html.contains("&lt;b&gt;not&lt;/b&gt;"));
        assert!(used.contains(&"update") && used.contains(&"mark") && used.contains(&"os-window") && used.contains(&"security"));
        assert!(!html.contains("@H"));
        // MAIL_PREVIEW=/path.html cargo test writes the sample out for a look in a browser.
        if let Ok(p) = std::env::var("MAIL_PREVIEW") {
            let mut h = html.clone();
            for k in &used {
                let png = icon_png(DEFAULT_THEME, k);
                use base64::Engine;
                h = h.replace(&format!("cid:icon-{k}\""), &format!("data:image/png;base64,{}\"", base64::engine::general_purpose::STANDARD.encode(png)));
            }
            std::fs::write(p, h).unwrap();
        }
    }
}
