//! The git commit the studio is built from, for the update check and the dashboard
//! (STUDIO_COMMIT: short hash, "-dirty" with uncommitted changes, "" outside a checkout).
//!
//! And the mail's themes and icons: the studio's own themes (FAMILIES) and glyphs from
//! web/studio.js, each glyph tinted in every theme and rasterised to 64px PNG. A mail client
//! renders no SVG (Outlook draws with Word), so the drawings travel as PNG - made from the
//! same source, so mail and page never drift apart.
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// The glyphs the mail uses: (file name in studio.js, colour override). None takes the
/// icon's own band.
const MAIL_ICONS: &[(&str, Option<&str>)] = &[
    // On the accent topbar the mark takes the accent's ink, or it vanishes into it.
    ("mark.svg", Some("accentFg")),
    // In the body, beside a title, the mark takes the accent itself.
    ("mark-accent.svg", None),
    ("os-window.svg", None),
    ("gold-image.svg", None),
    ("static-ip.svg", None),
    ("clock.svg", None),
    ("cpu.svg", None),
    ("disk.svg", None),
    ("users.svg", None),
    ("log.svg", None),
    ("vnet.svg", None),
    ("dns.svg", None),
    ("iso-media.svg", None),
    ("update.svg", None),
    ("vm.svg", None),
    ("certificate.svg", None),
    ("servers.svg", None),
    ("storage.svg", None),
    ("security.svg", None),
    ("integration.svg", None),
    ("download.svg", None),
    ("first-boot.svg", None),
];

/// Glyphs drawn once more in each of these bands, keyed "vm-linux", "gold-image-host": the
/// studio's machine colours (serverGlyphBand) - Linux yellow, client blue, server green.
const MAIL_BANDED: &[&str] = &["gold-image.svg", "vm.svg"];
const MACHINE_BANDS: &[&str] = &["linux", "host", "work"];

/// One theme from studio.js: "proxmox_dark", "Proxmox Dark", dark?, its colours by key
/// (bg, accent, ... and the bands studio, host, work, ident, deploy, linux).
struct Theme {
    id: String,
    name: String,
    dark: bool,
    colours: Vec<(String, String)>,
}

impl Theme {
    fn get(&self, k: &str) -> &str {
        self.colours.iter().find(|(n, _)| n == k).map_or("#9c9c9c", |(_, v)| v.as_str())
    }
    /// A glyph's hue: its band, or the accent.
    fn band(&self, b: &str) -> &str {
        if b == "accent" { self.get("accent") } else { self.get(b) }
    }
}

/// The FAMILIES list: each family's id and name, then its dark and light blocks of
/// `key: "#rrggbb"` pairs (the bands' keys do not clash with the others).
fn themes(js: &str) -> Vec<Theme> {
    let start = js.find("const FAMILIES = [").expect("FAMILIES in web/studio.js");
    let end = start + js[start..].find("const THEMES = (").expect("THEMES after FAMILIES");
    let block = &js[start..end];
    let pairs = |s: &str| -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut rest = s;
        while let Some(i) = rest.find(": \"#") {
            let key: String = rest[..i].chars().rev().take_while(|c| c.is_ascii_alphanumeric()).collect::<Vec<_>>().into_iter().rev().collect();
            let hex = &rest[i + 3..i + 10];
            out.push((key, hex.to_owned()));
            rest = &rest[i + 10..];
        }
        out
    };
    let mut out = Vec::new();
    for fam in block.split("id: \"").skip(1) {
        let id = fam.split('"').next().unwrap().to_owned();
        let name = fam.split("name: \"").nth(1).and_then(|n| n.split('"').next()).unwrap().to_owned();
        let (d, l) = (fam.find("dark: {").unwrap(), fam.find("light: {").unwrap());
        out.push(Theme { id: format!("{id}_dark"), name: format!("{name} Dark"), dark: true, colours: pairs(&fam[d..l]) });
        out.push(Theme { id: format!("{id}_light"), name: format!("{name} Light"), dark: false, colours: pairs(&fam[l..]) });
    }
    out
}

fn mix(a: &str, b: &str, t: f64) -> String {
    let p = |s: &str| u32::from_str_radix(&s[1..], 16).unwrap_or(0);
    let (pa, pb) = (p(a), p(b));
    let ch = |v: u32, sh: u32| ((v >> sh) & 255) as f64;
    let m = |sh| (ch(pa, sh) + (ch(pb, sh) - ch(pa, sh)) * t).round() as u32;
    format!("#{:02x}{:02x}{:02x}", m(16), m(8), m(0))
}

/// A glyph's band and markup from its line in studio.js: `"name.svg": ["band", ...markup]`,
/// the markup being '...' literals and the S constant joined by +.
fn glyph(js: &str, name: &str) -> Option<(String, String)> {
    let s_const = js.lines().find_map(|l| l.strip_prefix("const S = '")?.strip_suffix("';"))?.to_owned();
    let (band, expr) = if name.starts_with("mark") {
        ("accent".to_owned(), js.lines().find_map(|l| l.strip_prefix("const MARK = "))?.to_owned())
    } else {
        let line = js.lines().find(|l| l.trim_start().starts_with(&format!("\"{name}\": [")))?;
        let rest = line.split_once(": [")?.1;
        let band = rest.split('"').nth(1)?.to_owned();
        // The markup starts at the first single-quoted literal that opens a tag; a note before
        // it is double-quoted and may hold an apostrophe ("A job's log").
        let at = rest.find("'<")?;
        (band, rest[at..].to_owned())
    };
    let mut out = String::new();
    let mut it = expr.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\'' => {
                for c in it.by_ref() {
                    if c == '\'' {
                        break;
                    }
                    out.push(c);
                }
            }
            'S' => out.push_str(&s_const),
            ']' | ';' => break,
            _ => {}
        }
    }
    Some((band, out))
}

fn render_icons() {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let js = std::fs::read_to_string("web/studio.js").expect("web/studio.js");
    let themes = themes(&js);
    assert!(themes.iter().any(|t| t.id == "proxmox_dark"), "the Proxmox dark theme is gone from web/studio.js");
    let mut table = String::from("/// (id, name, dark, colours by key) - the studio's themes.\npub static THEMES: &[(&str, &str, bool, &[(&str, &str)])] = &[\n");
    for t in &themes {
        let c: String = t.colours.iter().map(|(k, v)| format!("(\"{k}\", \"{v}\"), ")).collect();
        table += &format!("    (\"{}\", \"{}\", {}, &[{c}]),\n", t.id, t.name, t.dark);
    }
    table += "];\n/// (theme id, icon key, PNG).\npub static ICONS: &[(&str, &str, &[u8])] = &[\n";
    let mut drawn: Vec<(&str, Option<&str>, Option<&str>)> = MAIL_ICONS.iter().map(|(n, ink)| (*n, *ink, None)).collect();
    for name in MAIL_BANDED {
        drawn.extend(MACHINE_BANDS.iter().map(|b| (*name, None, Some(*b))));
    }
    for t in &themes {
        for (name, ink, over) in &drawn {
            let (b, markup) = glyph(&js, name).unwrap_or_else(|| panic!("{name} is not in web/studio.js"));
            let b = over.map_or(b, str::to_owned);
            let hue = ink.map(|k| t.get(k).to_owned()).unwrap_or_else(|| t.band(&b).to_owned());
            // seamFor() on the page: towards the page colour in a dark theme, towards ink in a light one.
            let seam = if ink.is_some() || b == "accent" { hue.clone() } else { mix(&hue, if t.dark { t.get("bg") } else { "#14141a" }, 0.45) };
            let body = markup.replace("@H", &hue).replace("@S", &seam);
            let body = regex_free_band(&body, t);
            let svg = format!("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 18 18\">{body}</svg>");
            let tree = resvg::usvg::Tree::from_str(&svg, &resvg::usvg::Options::default()).unwrap_or_else(|e| panic!("{name}: {e}"));
            let mut px = resvg::tiny_skia::Pixmap::new(64, 64).unwrap();
            resvg::render(&tree, resvg::tiny_skia::Transform::from_scale(64.0 / 18.0, 64.0 / 18.0), &mut px.as_mut());
            let key = match over {
                Some(band) => format!("{}-{band}", name.trim_end_matches(".svg")),
                None => name.trim_end_matches(".svg").to_owned(),
            };
            let file = format!("mail-{}-{key}.png", t.id);
            std::fs::write(out_dir.join(&file), px.encode_png().unwrap()).unwrap();
            table += &format!("    (\"{}\", \"{key}\", include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{file}\"))),\n", t.id);
        }
    }
    table += "];\n/// (icon key, band) - the hue a glyph's tile is tinted with.\npub static ICON_BANDS: &[(&str, &str)] = &[\n";
    for (name, _) in MAIL_ICONS {
        let (b, _) = glyph(&js, name).unwrap();
        table += &format!("    (\"{}\", \"{b}\"),\n", name.trim_end_matches(".svg"));
    }
    for name in MAIL_BANDED {
        for b in MACHINE_BANDS {
            table += &format!("    (\"{}-{b}\", \"{b}\"),\n", name.trim_end_matches(".svg"));
        }
    }
    table += "];\n";
    std::fs::write(out_dir.join("mail_icons.rs"), table).unwrap();
}

/// `@B:<band>` - a second hue some glyphs carry - resolved the way the page does.
fn regex_free_band(s: &str, t: &Theme) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("@B:") {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 3..];
        let end = tail.find(|c: char| !c.is_ascii_alphabetic()).unwrap_or(tail.len());
        out.push_str(t.band(&tail[..end]));
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

fn main() {
    let commit = git(&["rev-parse", "--short=7", "HEAD"]).unwrap_or_default();
    let dirty = !commit.is_empty() && git(&["status", "--porcelain", "--untracked-files=no"]).is_some_and(|s| !s.is_empty());
    println!("cargo:rustc-env=STUDIO_COMMIT={commit}{}", if dirty { "-dirty" } else { "" });
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-changed=web/studio.js");
    render_icons();
}
