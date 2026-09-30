//! What a VM's first boot does beyond name, account and network: domain join and Azure
//! Arc. The Linux half is Build-Vms.ps1's Get-LinuxDomainJoinPackages,
//! Get-LinuxDomainJoinCommands and Get-LinuxArcCommands, ported line for line - the
//! reasons for each step are in those functions' comments and in
//! docs/windows-provisioning.md §7; the short versions are repeated here.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainJoin {
    pub domain: String,
    pub user: String,
    #[serde(default, skip_serializing)]
    pub password: String,
    #[serde(default)]
    pub ou: String,
    #[serde(default)]
    pub sudo_groups: Vec<String>,
    #[serde(default)]
    pub login_groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureArc {
    /// servicePrincipal is the only mode off Hyper-V: hostContext used PowerShell Direct.
    pub auth_mode: String,
    pub app_id: String,
    #[serde(default, skip_serializing)]
    pub secret: String,
    pub tenant_id: String,
    pub subscription_id: String,
    pub resource_group: String,
    pub location: String,
}

/// 'value' for sh, with any ' inside closed, escaped and reopened.
pub fn shq(v: &str) -> String {
    format!("'{}'", v.replace('\'', "'\\''"))
}

/// What realmd needs installed - per family, not the same set spelled twice. oddjob is
/// RHEL's mkhomedir; Debian and Ubuntu use pam_mkhomedir through pam-auth-update.
pub fn join_packages(family: &str) -> &'static [&'static str] {
    match family {
        "rhel" => &["realmd", "sssd", "sssd-tools", "adcli", "krb5-workstation", "samba-common-tools", "oddjob", "oddjob-mkhomedir"],
        "suse" => &["realmd", "sssd", "sssd-tools", "sssd-ad", "adcli", "krb5-client", "bind-utils"],
        _ => &["realmd", "sssd", "sssd-tools", "adcli", "krb5-user", "libnss-sss", "libpam-sss", "samba-common-bin"],
    }
}

/// The join account as `realm join --user=` needs it: the bare name. With an @ in it,
/// Kerberos reads the rest as the realm, case-sensitively, and the KDC's reply "did not
/// match expectations".
pub fn realm_login_user(user: &str) -> String {
    let mut n = user.trim();
    if let Some(i) = n.rfind('\\') {
        n = n[i + 1..].trim();
    }
    if let Some(i) = n.find('@') {
        n = n[..i].trim();
    }
    n.to_owned()
}

/// A domain group as the joined box knows it: fully qualified (sssd's default), the
/// down-level DOMAIN\ prefix dropped - a backslash in sudoers is an escape character.
pub fn linux_group_name(group: &str, domain: &str) -> String {
    let mut n = group.trim();
    if let Some(i) = n.rfind('\\') {
        n = n[i + 1..].trim();
    }
    if n.is_empty() {
        return String::new();
    }
    if !n.contains('@') && !domain.trim().is_empty() {
        return format!("{n}@{}", domain.trim());
    }
    n.to_owned()
}

fn sudoers_token(group: &str, domain: &str) -> String {
    let n = linux_group_name(group, domain);
    if n.is_empty() { String::new() } else { format!("%{}", n.replace(' ', "\\ ")) }
}

/// The runcmd lines that join the domain and hand out sudo.
pub fn linux_join_commands(dj: &DomainJoin, family: &str) -> Vec<String> {
    let mut c = Vec::new();
    let domain = dj.domain.trim();
    let user = realm_login_user(&dj.user);
    if domain.is_empty() || user.is_empty() {
        return c;
    }
    // --install=/ stops realmd asking PackageKit (absent on these images) whether its
    // packages exist; RHEL's realmd never asks.
    let mut args = format!("--unattended --user={}", shq(&user));
    if matches!(family, "debian" | "suse") {
        args = format!("--install=/ {args}");
    }
    if !dj.ou.trim().is_empty() {
        args += &format!(" --computer-ou={}", shq(dj.ou.trim()));
    }
    // The sssd responder sockets off before the join - realm starts sssd, and with them
    // still enabled the socket units fail on the spot.
    if family == "debian" {
        c.push("systemctl disable --now sssd-nss.socket sssd-pam.socket sssd-pam-priv.socket sssd-pac.socket 2>/dev/null; true".into());
    }
    // The clock first: a join before NTP has stepped fails with "Cannot contact any KDC".
    c.push(r#"i=0; until [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = yes ] || [ $i -ge 90 ]; do sleep 1; i=$((i+1)); done; echo "TIME-SYNC $(timedatectl show -p NTPSynchronized --value 2>/dev/null) after ${i}s""#.into());
    // sssd's sudo provider off, before the join: nothing here asks sssd for sudo rules,
    // and left on it pulls sudoRole objects from the whole directory (CVE-2026-14474).
    let section = domain.trim_end_matches('.').to_lowercase();
    let drop_in = "/etc/sssd/conf.d/90-pve-vm-studio-sudo.conf";
    c.push(format!(
        "mkdir -p /etc/sssd/conf.d && printf '[domain/%s]\\nsudo_provider = none\\n' {} > {drop_in} && chmod 0600 {drop_in}",
        shq(&section)
    ));
    c.push(format!(
        "printf '%s' {} | realm join {args} {} && echo DOMAIN-JOIN-OK || {{ echo DOMAIN-JOIN-FAILED; rm -f {drop_in}; }}",
        shq(&dj.password),
        shq(domain)
    ));
    if family == "debian" || family == "suse" {
        c.push("systemctl enable --now sssd || true".into());
    }
    if family == "suse" {
        c.push(r#"[ -f /etc/nsswitch.conf ] || cp /usr/etc/nsswitch.conf /etc/nsswitch.conf; sed -i -E '/^(passwd|group):/{/[[:space:]]sss([[:space:]]|$)/!s/$/ sss/}' /etc/nsswitch.conf; grep -E '^(passwd|group):.*sss' /etc/nsswitch.conf >/dev/null && echo NSS-SSS-OK || echo NSS-SSS-MISSING"#.into());
        c.push("pam-config --add --sss --mkhomedir --mkhomedir-umask=0077 && echo MKHOMEDIR-OK || echo MKHOMEDIR-FAILED".into());
    } else if family == "rhel" {
        c.push("sed -i 's/^#*HOME_MODE.*/HOME_MODE\\t0700/' /etc/login.defs; grep -q '^HOME_MODE' /etc/login.defs || printf 'HOME_MODE\\t0700\\n' >> /etc/login.defs; systemctl enable --now oddjobd; authselect select sssd with-mkhomedir --force && echo MKHOMEDIR-OK || echo MKHOMEDIR-FAILED".into());
    } else {
        let lines = [
            "Name: Create home directory on login (private)",
            "Default: yes",
            "Priority: 0",
            "Session-Type: Additional",
            "Session-Interactive-Only: yes",
            "Session:",
            "\toptional\t\t\tpam_mkhomedir.so umask=0077",
        ];
        let mut w = "printf '%s\\n'".to_owned();
        for l in lines {
            w += &format!(" {}", shq(l));
        }
        w += " > /usr/share/pam-configs/mkhomedir-private; DEBIAN_FRONTEND=noninteractive pam-auth-update --enable mkhomedir-private && echo MKHOMEDIR-OK || echo MKHOMEDIR-FAILED";
        c.push(w);
    }
    // sudo for domain groups: each group resolved first (a typo is said, not swallowed),
    // the file validated with visudo before it goes live - an invalid sudoers.d file can
    // stop sudo altogether.
    let tokens: Vec<String> = dj.sudo_groups.iter().map(|g| sudoers_token(g, domain)).filter(|t| !t.is_empty()).collect();
    if !tokens.is_empty() {
        let mut sc = "tmp=$(mktemp); ".to_owned();
        for t in &tokens {
            let plain = t[1..].replace("\\ ", " ");
            sc += &format!("if getent group {} >/dev/null 2>&1; then ", shq(&plain));
            if family == "suse" {
                // openSUSE's sudoers asks for root's password (targetpw) by default.
                sc += &format!("printf 'Defaults:%s !targetpw\\n' {} >> $tmp; ", shq(t));
            }
            sc += &format!("printf '%s ALL=(ALL:ALL) ALL\\n' {} >> $tmp; ", shq(t));
            sc += &format!("else echo {}; fi; ", shq(&format!("SUDO-GROUP-UNRESOLVED {plain}")));
        }
        sc += "if [ -s $tmp ] && visudo -cf $tmp >/dev/null 2>&1; then install -m 0440 -o root -g root $tmp /etc/sudoers.d/90-domain-sudo && echo SUDO-OK; else echo SUDO-NOT-INSTALLED; fi; rm -f $tmp";
        c.push(sc);
    }
    // realm permit only with a list: a plain join already permits every domain user.
    let logins: Vec<String> = dj.login_groups.iter().map(|g| linux_group_name(g, domain)).filter(|n| !n.is_empty()).collect();
    if !logins.is_empty() {
        let mut p = "realm deny --all; ".to_owned();
        for n in &logins {
            p += &format!("realm permit -g {}; ", shq(n));
        }
        p += "echo DOMAIN-LOGIN-RESTRICTED";
        c.push(p);
    }
    c
}

/// The runcmd lines that install the Connected Machine agent and onboard the VM. The
/// secret never goes on a command line (cloud-init's log is world readable): a 0600
/// file, passed with --config, removed whatever happens. Exit 42 is usually RBAC still
/// propagating - three tries, a minute apart and growing.
pub fn linux_arc_commands(a: &AzureArc) -> Vec<String> {
    if a.auth_mode != "servicePrincipal" || a.secret.is_empty() {
        return vec![];
    }
    let json = serde_json::json!({
        "service-principal-id": a.app_id,
        "service-principal-secret": a.secret,
        "tenant-id": a.tenant_id,
        "subscription-id": a.subscription_id,
        "resource-group": a.resource_group,
        "location": a.location,
    })
    .to_string();
    let cfg = "/etc/azcmagent-connect.json";
    vec![
        "curl -sSL -o /tmp/install_linux_azcmagent.sh https://aka.ms/azcmagent && bash /tmp/install_linux_azcmagent.sh && echo ARC-AGENT-OK || echo ARC-AGENT-FAILED".into(),
        format!(
            "umask 077; printf '%s' {} > {cfg}; trap 'rm -f {cfg}' EXIT INT TERM; n=0; while [ $n -lt 3 ]; do /opt/azcmagent/bin/azcmagent connect --config {cfg} && {{ echo ARC-CONNECT-OK; break; }}; n=$((n+1)); [ $n -lt 3 ] && {{ echo ARC-CONNECT-RETRY; sleep $((n*60)); }} || echo ARC-CONNECT-FAILED; done; rm -f {cfg}",
            shq(&json)
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(realm_login_user("AD\\Administrator"), "Administrator");
        assert_eq!(realm_login_user("administrator@ad.example"), "administrator");
        assert_eq!(linux_group_name("AD\\Domain Admins", "ad.example"), "Domain Admins@ad.example");
        assert_eq!(sudoers_token("Domain Admins", "ad.example"), "%Domain\\ Admins@ad.example");
        assert_eq!(shq("it's"), "'it'\\''s'");
    }

    #[test]
    fn join_debian() {
        let dj = DomainJoin {
            domain: "ad.example".into(),
            user: "Administrator@ad.example".into(),
            password: "p'w".into(),
            ou: String::new(),
            sudo_groups: vec!["Domain Admins".into()],
            login_groups: vec![],
        };
        let c = linux_join_commands(&dj, "debian");
        assert!(c.iter().any(|l| l.contains("realm join --install=/ --unattended --user='Administrator' 'ad.example'")));
        assert!(c.iter().any(|l| l.contains("visudo -cf")));
        assert!(!c.iter().any(|l| l.contains("realm permit")));
    }
}
