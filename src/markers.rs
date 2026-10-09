//! The guest's markers, as people read them. WinPE, the media worker and a Linux bake report
//! through short markers on the serial console or in a report file (PVS-PASS1-OK,
//! BAKE-PKG fastfetch ok): they are the studio's protocol and stay as they are - existing
//! WinPE ISOs and golds speak them. The job log shows this text instead.

/// (marker without its prefix, what the log says)
const TEXT: &[(&str, &str)] = &[
    // WinPE, both bake passes and the deploy pass
    ("PE-START", "WinPE is up"),
    ("PE-NO-SEED", "WinPE found no seed disk"),
    ("PASS1-START", "Pass 1: applying the image"),
    ("DISK", "Disks"),
    ("OS-DISK", "System disk"),
    ("PARTITIONED", "System disk partitioned"),
    ("APPLIED", "Image applied"),
    ("DRIVERS", "virtio drivers added to the image"),
    ("BCDBOOT", "Boot files written"),
    ("BCDBOOT-WITH", "Boot files with"),
    ("TARGET", "Edition target"),
    ("EDITION", "Edition set to"),
    ("EDITION-NOT-CHANGED", "Edition not changed, still"),
    ("PASS1-OK", "Pass 1 done"),
    ("PASS1-FAILED", "Pass 1 failed"),
    ("AUDIT-START", "Audit mode started"),
    ("VIRTIO", "virtio drivers installed, exit code"),
    ("QGA", "QEMU guest agent installed, exit code"),
    ("SYSPREP-START", "Sysprep started"),
    ("PASS2-START", "Pass 2: region, policies and key"),
    ("POLICY", "Policy"),
    ("GENERALIZED", "The image is generalized"),
    ("NOT-GENERALIZED", "The image is not generalized"),
    ("NO-SYSPREP-TAG", "Sysprep left no tag - it did not finish"),
    ("ANSWERFILE", "Answer file written"),
    ("TIMEZONE", "Time zone"),
    ("LOCALE", "Language and keyboard"),
    ("KEY", "Product key set"),
    ("NO-KEY", "No product key for this edition"),
    ("PASS2-OK", "Pass 2 done"),
    ("PASS2-FAILED", "Pass 2 failed"),
    ("DEPLOY-START", "Deploy pass started"),
    ("DEPLOY-OK", "Deploy pass done"),
    ("DEPLOY-FAILED", "Deploy pass failed"),
    ("FEATURE-OK", "Feature installed"),
    ("FEATURE-FAIL", "Feature failed"),
    ("CAP-OK", "Capability added"),
    ("CAP-FAIL", "Capability failed"),
    ("CAP-SKIP", "Capability skipped"),
    ("APP-REMOVED", "App removed"),
    ("APP-FAIL", "App not removed"),
    ("APPS-DONE", "Apps removed"),
    ("FALLBACK", "Falling back"),
    ("DISK-READONLY", "The disk is read-only"),
    ("FIRSTBOOT", "First boot"),
    ("FIRSTBOOT-OK", "First boot done"),
    ("NO-VIOSCSI", "WinPE has no vioscsi driver"),
    ("NO-OS-DISK", "No system disk found"),
    ("NO-INSTALL-WIM", "No install image on the ISO"),
    ("NO-WINDOWS", "No Windows on the disk"),
    ("NO-BOOTLOADER", "No boot loader"),
    ("NO-FIRSTBOOT", "No first-boot script"),
    ("NO-VIRTIO-CD", "No virtio-win disc"),
    // The media worker
    ("WORKER-START", "Worker started"),
    ("NO-CURL", "The worker has no curl"),
    ("NO-STUDIO", "The worker cannot reach the studio"),
    ("ONLINE", "The worker reached the studio"),
    ("NO-SCRATCH-DISK", "The worker found no scratch disk"),
    ("SCRATCH-FAILED", "The scratch disk could not be prepared"),
    ("COPY-IN", "Copying the image to the worker"),
    ("INDEX", "Servicing image"),
    ("UPD", "Applying"),
    ("UPD-OK", "Applied"),
    ("UPD-FAIL", "Failed"),
    ("CLEANUP", "Cleaning up image"),
    ("HEALTH", "Scanning the component store"),
    ("COMMIT", "Saving image"),
    ("WINRE", "Servicing WinRE"),
    ("EDGE", "Adding Microsoft Edge"),
    ("APPS", "Provisioning the inbox apps"),
    ("PROV-OK", "Provisioned"),
    ("PROV-FAIL", "Provisioning failed"),
    ("BOOT", "Servicing boot.wim"),
    ("EXPORT", "Exporting the images"),
    ("COPY-OUT", "Copying the result back"),
    ("WORKER-OK", "Worker done"),
    ("WORKER-FAILED", "Worker failed"),
    // A Linux bake's report
    ("OK", "Bake finished"),
    ("KERNEL", "Kernel"),
    ("RUNNING-KERNEL", "Running kernel"),
    ("REGION", "Region"),
    ("KEYMAP", "Keyboard"),
    ("KEYMAP-MISSING", "Keyboard layout missing"),
    ("CIS-BUNDLE", "CIS scripts unpacked"),
    ("CIS-REBOOT", "Rebooting into the hardened system"),
    ("CIS-CHECKING", "Checking the CIS rules"),
    ("CIS-SEALING", "Sealing the gold"),
    ("CIS-SNAPD-PURGED", "snapd removed"),
    ("CIS-SNAPD-KEPT", "snapd kept"),
    ("DIAG", "Diagnostics"),
    ("GROW-READY", "Ready for the bigger disk"),
    ("INITRD-REBUILT", "initramfs rebuilt"),
    ("INITRD-FAILED", "initramfs rebuild failed"),
    ("KIWI-REPART-OFF", "kiwi's repartitioning turned off"),
    ("LAYOUT", "Volumes laid out"),
    ("LAYOUT-FAILED", "Volume layout failed"),
    ("LVM-ROOT", "The root is on LVM"),
    ("RELABEL", "SELinux relabel"),
    ("RELABEL-FAILED", "SELinux relabel failed"),
    ("ROOT-SIZE", "Root size"),
];

/// The marker's text for the log: its sentence and its arguments. A marker without an entry
/// is still readable - its words, without the prefix.
pub fn text(line: &str) -> String {
    let rest = line.strip_prefix("PVS-").or_else(|| line.strip_prefix("BAKE-")).unwrap_or(line);
    let (key, args) = rest.split_once(' ').map(|(k, a)| (k, a.trim())).unwrap_or((rest, ""));
    // BAKE-PKG <name> ok|MISSING
    if line.starts_with("BAKE-PKG ") {
        let (name, state) = args.rsplit_once(' ').unwrap_or((args, ""));
        return if state.eq_ignore_ascii_case("missing") { format!("Package {name} is missing") } else { format!("Package {name} installed") };
    }
    // PVS-UPD[-OK|-FAIL] <image|winre> cleanup [code]: the component cleanup, not an update.
    let parts: Vec<&str> = args.split_whitespace().collect();
    if key.starts_with("UPD") && parts.get(1) == Some(&"cleanup") {
        let at = match parts[0] {
            "winre" => "WinRE".to_owned(),
            "pe" => "WinPE".to_owned(),
            b if b.starts_with("boot") => format!("boot.wim {}", &b[4..]),
            n => format!("image {n}"),
        };
        return match key {
            "UPD-OK" => format!("Cleaned up: {at}"),
            "UPD-FAIL" => format!("Cleanup failed: {at}, exit code {}", parts.get(2).unwrap_or(&"?")),
            _ => format!("Cleaning up: {at}"),
        };
    }
    // PVS-HEALTH <index>[-before|-updated|-cleaned]: the scan after each stage.
    if key == "HEALTH" {
        let (n, stage) = args.split_once('-').unwrap_or((args, ""));
        let when = match stage {
            "before" => " before the updates",
            "updated" => " after the updates",
            "cleaned" => " after the cleanup",
            _ => "",
        };
        return format!("Scanning the component store: image {n}{when}");
    }
    // PVS-EDGE <index>, PVS-BOOT <index>, PVS-APPS <index> <count>.
    if matches!(key, "EDGE" | "BOOT" | "APPS") {
        let head = TEXT.iter().find(|(k, _)| *k == key).map(|(_, t)| *t).unwrap_or_default();
        return match parts.as_slice() {
            [n, count] => format!("{head}: image {n}, {count} app(s)"),
            [n] => format!("{head}: image {n}"),
            _ => head.to_owned(),
        };
    }
    let head = match TEXT.iter().find(|(k, _)| *k == key) {
        Some((_, t)) => (*t).to_owned(),
        None => {
            let words = key.to_lowercase().replace('-', " ");
            let mut c = words.chars();
            c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
        }
    };
    if args.is_empty() { head } else { format!("{head}: {args}") }
}

/// Several markers for an error message.
pub fn list(markers: &[String]) -> String {
    markers.iter().map(|m| text(m)).collect::<Vec<_>>().join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_read_as_words() {
        assert_eq!(text("PVS-PASS1-OK"), "Pass 1 done");
        assert_eq!(text("PVS-POLICY rdp"), "Policy: rdp");
        assert_eq!(text("BAKE-PKG fastfetch ok"), "Package fastfetch installed");
        assert_eq!(text("BAKE-PKG htop MISSING"), "Package htop is missing");
        assert_eq!(text("PVS-SOMETHING-NEW 3"), "Something new: 3");
        assert!(!text("PVS-UPD-FAIL x.msu 5").contains("PVS"));
        assert_eq!(text("PVS-UPD 2 cleanup"), "Cleaning up: image 2");
        assert_eq!(text("PVS-UPD-OK winre cleanup"), "Cleaned up: WinRE");
    }
}
