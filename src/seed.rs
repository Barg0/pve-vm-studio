//! Seed ISOs: the files a VM finds on a CD at first boot (cloud-init's NoCloud "cidata",
//! later Windows answer files). Built here with xorriso, uploaded to an ISO storage, and
//! deleted again once the VM has read them - they hold passwords in clear.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

pub struct SeedIso {
    dir: PathBuf,
    pub iso: PathBuf,
}

impl SeedIso {
    /// Writes `files` (name, content) into a fresh directory and builds `<name>.iso` with
    /// the given volume label.
    pub async fn build(work: &Path, name: &str, label: &str, files: &[(&str, &str)]) -> Result<Self> {
        let dir = work.join(format!("{name}.d"));
        let iso = work.join(format!("{name}.iso"));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await?;
        for (f, content) in files {
            let path = dir.join(f);
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::write(&path, content).await.with_context(|| format!("writing {f}"))?;
        }
        let out = tokio::process::Command::new("xorriso")
            .args(["-as", "mkisofs", "-quiet", "-J", "-r", "-V", label, "-o"])
            .arg(&iso)
            .arg(&dir)
            .output()
            .await
            .context("running xorriso - is it installed?")?;
        if !out.status.success() {
            bail!("xorriso failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(Self { dir, iso })
    }

    pub async fn remove(self) {
        let _ = tokio::fs::remove_dir_all(&self.dir).await;
        let _ = tokio::fs::remove_file(&self.iso).await;
    }
}
