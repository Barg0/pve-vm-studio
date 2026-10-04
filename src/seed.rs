//! Seeds: the files a VM finds at first boot (cloud-init's NoCloud "cidata", the WinPE
//! passes' scripts, Windows answer files and GuestProvision). Each is a small disk image
//! built here, uploaded to an "import" storage, attached with import-from and deleted with
//! the disk once the VM has read it - seeds hold passwords in clear.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// A seed as a disk instead of a CD: one MBR partition with a FAT filesystem carrying the
/// files, under the same label (cloud-init's NoCloud reads a vfat volume labelled CIDATA as
/// it reads the ISO; WinPE and Windows mount it like any disk). Built without root:
/// sfdisk on the image file, mkfs.vfat at the partition's offset, mcopy into it.
pub struct SeedDisk {
    dir: PathBuf,
    pub image: PathBuf,
}

/// 32 MiB: FAT16 with room to spare for the largest seed (GuestProvision and its payload).
const SEED_DISK_MB: u64 = 32;

async fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let out = tokio::process::Command::new(cmd)
        .args(args)
        .env("MTOOLS_SKIP_CHECK", "1")
        .output()
        .await
        .with_context(|| format!("running {cmd} - is it installed (dosfstools, mtools)?"))?;
    if !out.status.success() {
        bail!("{cmd} failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

impl SeedDisk {
    pub async fn build(work: &Path, name: &str, label: &str, files: &[(&str, &str)]) -> Result<Self> {
        let bytes: Vec<(&str, &[u8])> = files.iter().map(|(f, c)| (*f, c.as_bytes())).collect();
        Self::build_bytes(work, name, label, &bytes).await
    }

    /// build(), for files that are not text (curl.exe on the media worker's seed).
    pub async fn build_bytes(work: &Path, name: &str, label: &str, files: &[(&str, &[u8])]) -> Result<Self> {
        let dir = work.join(format!("{name}.d"));
        let image = work.join(format!("{name}.raw"));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await?;
        for (f, content) in files {
            let path = dir.join(f);
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::write(&path, content).await.with_context(|| format!("writing {f}"))?;
        }
        let file = tokio::fs::File::create(&image).await?;
        file.set_len(SEED_DISK_MB << 20).await?;
        drop(file);
        // One FAT16 partition (type 0x0e, LBA) from 1 MiB to the end.
        let mut sf = tokio::process::Command::new("sfdisk")
            .args(["--quiet", "--no-reread", "--no-tell-kernel"])
            .arg(&image)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("running sfdisk")?;
        {
            use tokio::io::AsyncWriteExt;
            let mut stdin = sf.stdin.take().unwrap();
            stdin.write_all(b"label: dos\nstart=2048, type=e\n").await?;
        }
        let out = sf.wait_with_output().await?;
        if !out.status.success() {
            bail!("sfdisk failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        let img = image.display().to_string();
        let label_up = label.to_uppercase();
        run("mkfs.vfat", &["-F", "16", "--offset", "2048", "-n", &label_up, &img]).await?;
        let mut args = vec!["-s".to_owned(), "-i".to_owned(), format!("{img}@@1M")];
        let mut entries = tokio::fs::read_dir(&dir).await?;
        while let Some(e) = entries.next_entry().await? {
            args.push(e.path().display().to_string());
        }
        args.push("::/".to_owned());
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run("mcopy", &refs).await?;
        Ok(Self { dir, image })
    }

    pub async fn remove(self) {
        let _ = tokio::fs::remove_dir_all(&self.dir).await;
        let _ = tokio::fs::remove_file(&self.image).await;
    }
}

/// The node's storage for uploaded disk images (content "import"), `local` first.
pub async fn import_storage_on(pve: &crate::pve::Pve, node: &str) -> Result<String> {
    let res = pve.resources().await?;
    let mut fit: Vec<String> = res
        .iter()
        .filter(|r| r.kind == "storage" && r.node.as_deref() == Some(node) && r.has_content("import") && r.status.as_deref() == Some("available"))
        .filter_map(|r| r.storage.clone())
        .collect();
    fit.sort_by_key(|s| s != "local");
    fit.into_iter().next().ok_or_else(|| anyhow::anyhow!("no storage on {node} takes uploaded disk images (content \"import\") - enable it on one under Datacenter → Storage"))
}

/// Uploads a seed disk to the node's import storage and attaches it to the VM as `slot` - PVE
/// copies it into a VM disk on `disk_storage` (import-from) - then deletes the upload. From
/// here on the seed is one of the VM's disks: it goes with detach() or with the VM.
pub async fn attach(pve: &crate::pve::Pve, node: &str, vmid: u32, slot: &str, disk_storage: &str, seed: SeedDisk, name: &str) -> Result<()> {
    let import = import_storage_on(pve, node).await;
    let uploaded = match import {
        Ok(store) => pve.upload(node, &store, "import", &seed.image, &format!("{name}.raw")).await,
        Err(e) => Err(e),
    };
    seed.remove().await;
    let volid = uploaded?;
    let attached = pve
        .vm_set_task(node, vmid, crate::form![(slot, format!("{disk_storage}:0,import-from={volid}"))], |_| {})
        .await;
    let _ = pve.delete_volume(node, &volid).await;
    attached
}

/// Takes the seed disk off the VM and deletes it (force: physically, not left as unusedN).
/// A SATA disk cannot be unplugged from a running VM - call this with the VM off.
pub async fn detach(pve: &crate::pve::Pve, node: &str, vmid: u32, slot: &str) -> Result<()> {
    pve.vm_set(node, vmid, crate::form![("delete", slot), ("force", 1)]).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs sfdisk, dosfstools and mtools - skipped where they are missing.
    #[tokio::test]
    async fn seed_disk_has_a_labelled_fat_partition_with_the_files() {
        if std::process::Command::new("mcopy").arg("-V").output().is_err() || std::process::Command::new("mkfs.vfat").arg("--help").output().is_err() {
            return;
        }
        let work = std::env::temp_dir().join(format!("seedtest-{}", uuid::Uuid::new_v4().simple()));
        tokio::fs::create_dir_all(&work).await.unwrap();
        let d = SeedDisk::build(&work, "t", "cidata", &[("user-data", "#cloud-config\n"), ("pvs/pe.cmd", "@echo off\r\n")]).await.unwrap();
        let img = format!("{}@@1M", d.image.display());
        let out = std::process::Command::new("mdir").env("MTOOLS_SKIP_CHECK", "1").args(["-i", &img, "-/", "::/"]).output().unwrap();
        let listing = String::from_utf8_lossy(&out.stdout);
        assert!(listing.contains("CIDATA") && listing.to_lowercase().contains("user-data") && listing.contains("pe"), "{listing}");
        d.remove().await;
        let _ = tokio::fs::remove_dir_all(&work).await;
    }
}
