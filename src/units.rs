//! The container's own files besides the binary - the systemd units and the self-update's
//! root helper - carried in the binary, so a self-update (Version → Update) brings them
//! along: pvs-update.sh runs `pve-vm-studio install-units` with the new binary, as root,
//! before it restarts the studio. install.sh and update-lxc.sh push the same files.

use std::path::Path;

use anyhow::{bail, Context, Result};

const FILES: [(&str, &str, u32); 5] = [
    ("/etc/systemd/system/pve-vm-studio.service", include_str!("../deploy/pve-vm-studio.service"), 0o644),
    ("/etc/systemd/system/pve-vm-studio-console.service", include_str!("../deploy/pve-vm-studio-console.service"), 0o644),
    ("/etc/systemd/system/pve-vm-studio-update.path", include_str!("../deploy/pve-vm-studio-update.path"), 0o644),
    ("/etc/systemd/system/pve-vm-studio-update.service", include_str!("../deploy/pve-vm-studio-update.service"), 0o644),
    ("/usr/local/lib/pve-vm-studio/pvs-update.sh", include_str!("../deploy/pvs-update.sh"), 0o755),
];

/// Writes the files that differ (a new file moved over the old one: the running updater
/// script keeps reading its own copy), reloads systemd and switches on what has to run.
pub fn install() -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("install-units changes systemd units - run it as root");
    }
    let mut changed = Vec::new();
    for (path, text, mode) in FILES {
        let p = Path::new(path);
        if std::fs::read_to_string(p).ok().as_deref() == Some(text) {
            continue;
        }
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let tmp = p.with_extension("pvs-new");
        std::fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        std::fs::rename(&tmp, p).with_context(|| format!("writing {path}"))?;
        changed.push(path);
    }
    let run = |args: &[&str]| std::process::Command::new("systemctl").args(args).status().map(|s| s.success()).unwrap_or(false);
    if !changed.is_empty() {
        run(&["daemon-reload"]);
    }
    // The updater's watch and the console run from now on; the console without a password
    // set answers with how to set one.
    run(&["enable", "--now", "pve-vm-studio-update.path"]);
    run(&["enable", "pve-vm-studio-console"]);
    for p in &changed {
        println!("updated {p}");
    }
    Ok(())
}
