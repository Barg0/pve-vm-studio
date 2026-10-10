//! Changes to config.toml that keep everything else in it - comments, order, the keys the
//! console does not touch. One `key = value` line is replaced, added or removed, at the top
//! level or in one [section].

use std::path::Path;

use anyhow::{Context, Result};

/// The TOML for a string.
pub fn string(v: &str) -> String {
    toml::Value::String(v.to_owned()).to_string()
}

/// `value` None removes the key. Written to a temporary file and moved over the old one,
/// with the old one's owner and mode.
pub fn set(path: &Path, section: Option<&str>, key: &str, value: Option<&str>) -> Result<()> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let out = edit(&text, section, key, value);
    // Still a config the studio reads.
    toml::from_str::<toml::Value>(&out).context("the change would not be valid TOML")?;
    let tmp = path.with_extension("toml.new");
    std::fs::write(&tmp, out)?;
    if let Ok(meta) = std::fs::metadata(path) {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let _ = std::os::unix::fs::chown(&tmp, Some(meta.uid()), Some(meta.gid()));
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(meta.mode() & 0o7777));
    }
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn edit(text: &str, section: Option<&str>, key: &str, value: Option<&str>) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let is_header = |l: &str| l.trim_start().starts_with('[');
    let header_is = |l: &str, s: &str| l.trim() == format!("[{s}]");
    // The lines that belong to the section: after its header, up to the next one.
    let (start, end) = match section {
        None => (0, lines.iter().position(|l| is_header(l)).unwrap_or(lines.len())),
        Some(s) => match lines.iter().position(|l| header_is(l, s)) {
            Some(h) => (h + 1, lines[h + 1..].iter().position(|l| is_header(l)).map(|p| h + 1 + p).unwrap_or(lines.len())),
            None => {
                // No such section: it goes at the end.
                let mut out = text.trim_end().to_owned();
                if let Some(v) = value {
                    out.push_str(&format!("\n\n[{s}]\n{key} = {v}\n"));
                }
                if !out.ends_with('\n') {
                    out.push('\n');
                }
                return out;
            }
        },
    };
    let key_of = |l: &str| l.split('=').next().map(|k| k.trim().to_owned()).filter(|_| l.contains('=') && !l.trim_start().starts_with('#'));
    let found = (start..end).find(|&i| key_of(lines[i]).as_deref() == Some(key));
    let mut out: Vec<String> = lines.iter().map(|l| (*l).to_owned()).collect();
    match (found, value) {
        (Some(i), Some(v)) => out[i] = format!("{key} = {v}"),
        (Some(i), None) => {
            out.remove(i);
        }
        (None, Some(v)) => {
            // After the section's last key line, so it stays above a blank line or comment block.
            let at = (start..end).rev().find(|&i| key_of(lines[i]).is_some()).map(|i| i + 1).unwrap_or(start);
            out.insert(at, format!("{key} = {v}"));
        }
        (None, None) => {}
    }
    let mut s = out.join("\n");
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = "# PVE VM Studio\n\nlisten = \"0.0.0.0:443\"\nfqdn = \"studio.lab\"\n\n[pve]\nurl = \"https://10.0.0.1:8006\"\ntoken_id = \"a@pve!b\"\nca_file = \"/etc/x.pem\"\n";

    #[test]
    fn top_level_and_section() {
        let s = edit(CFG, None, "debug_tools", Some("true"));
        assert!(s.contains("fqdn = \"studio.lab\"\ndebug_tools = true\n\n[pve]"), "{s}");
        let s = edit(&s, None, "debug_tools", Some("false"));
        assert!(s.contains("debug_tools = false") && !s.contains("debug_tools = true"));
        let s = edit(CFG, Some("pve"), "url", Some(&string("https://10.0.0.2:8006")));
        assert!(s.contains("url = \"https://10.0.0.2:8006\"") && s.contains("listen = \"0.0.0.0:443\""));
        let s = edit(CFG, Some("pve"), "tls_name", Some(&string("pve-01.lab")));
        assert!(s.ends_with("ca_file = \"/etc/x.pem\"\ntls_name = \"pve-01.lab\"\n"), "{s}");
        let s = edit(&s, Some("pve"), "tls_name", None);
        assert!(!s.contains("tls_name"));
        assert!(s.starts_with("# PVE VM Studio\n"), "comments stay");
    }
}
