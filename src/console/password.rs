//! The console user's password: 32 characters from an alphabet without look-alikes, shown
//! once (install.sh, update-lxc.sh, `console-password --reset`), kept only as a PBKDF2 hash
//! in a root-only file beside config.toml. Dashes are for reading - they are not part of it.

use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::Engine;

/// No 0/O, 1/l/I: written down by hand and typed in again.
const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
const ITERATIONS: u32 = 600_000;
pub const MIN_LEN: usize = 16;
pub const USER: &str = "maint";

pub fn generate() -> String {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut out = String::with_capacity(32);
    // Rejection sampling keeps every character equally likely.
    let limit = 256 - (256 % ALPHABET.len());
    while out.len() < 32 {
        let mut b = [0u8; 64];
        rng.fill(&mut b).expect("system random");
        for x in b {
            if (x as usize) < limit && out.len() < 32 {
                out.push(ALPHABET[x as usize % ALPHABET.len()] as char);
            }
        }
    }
    out
}

/// In groups of four: Vq7m-Xr2c-...
pub fn grouped(pw: &str) -> String {
    pw.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join("-")
}

/// What is hashed and compared: spaces and dashes are reading aids.
fn normalize(pw: &str) -> String {
    pw.chars().filter(|c| !c.is_whitespace() && *c != '-').collect()
}

fn derive(pw: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, std::num::NonZeroU32::new(iterations).unwrap(), salt, normalize(pw).as_bytes(), &mut out);
    out
}

/// The file: one line, `pbkdf2-sha256$<iterations>$<salt>$<hash>$<set at>$<set by>`.
pub struct Stored {
    iterations: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
    pub set_at: String,
    pub set_by: String,
}

pub fn read(file: &Path) -> Result<Option<Stored>> {
    let text = match std::fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", file.display())),
    };
    let b64 = base64::engine::general_purpose::STANDARD;
    let p: Vec<&str> = text.trim().split('$').collect();
    if p.len() < 4 || p[0] != "pbkdf2-sha256" {
        bail!("{} is not a console password file", file.display());
    }
    Ok(Some(Stored {
        iterations: p[1].parse().context("iterations")?,
        salt: b64.decode(p[2]).context("salt")?,
        hash: b64.decode(p[3]).context("hash")?,
        set_at: p.get(4).unwrap_or(&"").to_string(),
        set_by: p.get(5).unwrap_or(&"").to_string(),
    }))
}

pub fn verify(stored: &Stored, pw: &str) -> bool {
    ring::pbkdf2::verify(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(stored.iterations.max(1)).unwrap(),
        &stored.salt,
        normalize(pw).as_bytes(),
        &stored.hash,
    )
    .is_ok()
}

/// Writes a new hash (root only, 0600), replacing the old one.
pub fn write(file: &Path, pw: &str, by: &str) -> Result<()> {
    use ring::rand::SecureRandom;
    let mut salt = [0u8; 16];
    ring::rand::SystemRandom::new().fill(&mut salt).map_err(|_| anyhow::anyhow!("no system random"))?;
    let hash = derive(pw, &salt, ITERATIONS);
    let b64 = base64::engine::general_purpose::STANDARD;
    let by: String = by.chars().filter(|c| *c != '$' && !c.is_control()).collect();
    let line = format!("pbkdf2-sha256${ITERATIONS}${}${}${}${by}\n", b64.encode(salt), b64.encode(hash), chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    let tmp = file.with_extension("pw.new");
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(line.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, file).with_context(|| format!("writing {}", file.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_and_checked() {
        let pw = generate();
        assert_eq!(pw.len(), 32);
        assert!(pw.bytes().all(|b| ALPHABET.contains(&b)));
        let dir = std::env::temp_dir().join(format!("pvs-pw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("console.pw");
        write(&f, &pw, "test").unwrap();
        let s = read(&f).unwrap().unwrap();
        assert!(verify(&s, &pw));
        assert!(verify(&s, &grouped(&pw)), "the dashes are reading aids");
        assert!(!verify(&s, "wrong"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
