//! The studio's own network: the address, gateway and DNS servers of the container it
//! runs in, read and set through the PVE API (the container's net0 and nameserver).
//! The studio does not keep its container's id - it finds itself by the MAC address of
//! its eth0, which PVE keeps as the hwaddr of that container's net0.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::pve::{enc, Pve};

/// Where the studio runs: its container and the netN entry carrying eth0.
#[derive(Debug, Clone, Serialize)]
pub struct Own {
    pub node: String,
    pub vmid: u32,
    pub iface: String,
    pub bridge: String,
    pub vlan: String,
    /// "dhcp" or "static".
    pub mode: String,
    /// CIDR, as PVE keeps it (static only).
    pub ip: String,
    pub gw: String,
    /// What the container really has now - the lease, under DHCP.
    pub current_ip: String,
    pub current_gw: String,
    pub dns: Vec<String>,
    pub searchdomain: String,
    pub hostname: String,
}

#[derive(Debug, Deserialize)]
pub struct Change {
    pub mode: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub gw: String,
    #[serde(default)]
    pub dns: Vec<String>,
}

fn own_mac() -> Result<String> {
    let mac = std::fs::read_to_string("/sys/class/net/eth0/address")?;
    Ok(mac.trim().to_ascii_lowercase())
}

/// "name=eth0,bridge=vmbr0,hwaddr=..,ip=dhcp" as ordered key/value pairs.
fn parse_net(s: &str) -> Vec<(String, String)> {
    s.split(',').filter_map(|kv| kv.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned()))).collect()
}

fn get<'a>(kv: &'a [(String, String)], k: &str) -> &'a str {
    kv.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_str()).unwrap_or("")
}

/// The container whose netN carries this process's eth0 MAC. Containers tagged
/// pve-vm-studio are asked first, so a normal install costs one config read.
async fn locate(pve: &Pve) -> Result<(String, u32, String, HashMap<String, Value>)> {
    let mac = own_mac()?;
    let mut cts: Vec<_> = pve.resources().await?.into_iter().filter(|r| r.kind == "lxc").collect();
    cts.sort_by_key(|r| !r.tags.as_deref().unwrap_or("").split([';', ',', ' ']).any(|t| t == "pve-vm-studio"));
    for r in cts {
        let (Some(node), Some(vmid)) = (r.node.clone(), r.vmid) else { continue };
        let Ok(cfg) = pve.get::<HashMap<String, Value>>(&format!("/nodes/{}/lxc/{vmid}/config", enc(&node))).await else { continue };
        for (k, v) in &cfg {
            if !k.starts_with("net") {
                continue;
            }
            let net = parse_net(v.as_str().unwrap_or(""));
            if get(&net, "hwaddr").eq_ignore_ascii_case(&mac) {
                return Ok((node, vmid, k.clone(), cfg));
            }
        }
    }
    bail!("the studio's container was not found in PVE (no container has a network device with MAC {mac})")
}

/// The address and gateway eth0 has right now (the DHCP lease, or the static one).
fn current() -> (String, String) {
    let run = |args: &[&str]| std::process::Command::new("ip").args(args).output().ok().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    let addr = run(&["-4", "-o", "addr", "show", "dev", "eth0"]);
    let ip = addr.split_whitespace().skip_while(|w| *w != "inet").nth(1).unwrap_or("").to_owned();
    let route = run(&["-4", "route", "show", "default"]);
    let gw = route.split_whitespace().skip_while(|w| *w != "via").nth(1).unwrap_or("").to_owned();
    (ip, gw)
}

pub async fn read(pve: &Pve) -> Result<Own> {
    let (node, vmid, iface, cfg) = locate(pve).await?;
    let net = parse_net(cfg.get(&iface).and_then(Value::as_str).unwrap_or(""));
    let ip = get(&net, "ip");
    let (current_ip, current_gw) = current();
    let s = |k: &str| cfg.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    Ok(Own {
        node,
        vmid,
        bridge: get(&net, "bridge").to_owned(),
        vlan: get(&net, "tag").to_owned(),
        mode: if ip == "dhcp" || ip.is_empty() { "dhcp".into() } else { "static".into() },
        ip: if ip == "dhcp" { String::new() } else { ip.to_owned() },
        gw: get(&net, "gw").to_owned(),
        current_ip,
        current_gw,
        dns: s("nameserver").split_whitespace().map(str::to_owned).collect(),
        searchdomain: s("searchdomain"),
        hostname: s("hostname"),
        iface,
    })
}

fn cidr_ok(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (a, p) = s.split_once('/')?;
    let a: Ipv4Addr = a.parse().ok()?;
    let p: u8 = p.parse().ok()?;
    (8..=32).contains(&p).then_some((a, p))
}

fn same_net(a: Ipv4Addr, b: Ipv4Addr, prefix: u8) -> bool {
    let m = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
    u32::from(a) & m == u32::from(b) & m
}

/// Checks a change and returns the container's new net entry and its DNS servers.
pub fn plan(own_net: &str, c: &Change) -> Result<(String, Vec<String>)> {
    let mut net = parse_net(own_net);
    net.retain(|(k, _)| k != "ip" && k != "gw");
    match c.mode.as_str() {
        "dhcp" => net.push(("ip".into(), "dhcp".into())),
        "static" => {
            let (addr, prefix) = cidr_ok(c.ip.trim()).ok_or_else(|| anyhow!("'{}' is not an address with prefix, like 10.10.0.20/24", c.ip))?;
            let gw: Ipv4Addr = c.gw.trim().parse().map_err(|_| anyhow!("'{}' is not a gateway address", c.gw))?;
            if gw == addr {
                bail!("the gateway cannot be the studio's own address");
            }
            if !same_net(addr, gw, prefix) {
                bail!("gateway {gw} is outside {addr}/{prefix}");
            }
            net.push(("ip".into(), format!("{addr}/{prefix}")));
            net.push(("gw".into(), gw.to_string()));
        }
        m => bail!("'{m}' is not an address mode - dhcp or static"),
    }
    let mut dns = Vec::new();
    for d in c.dns.iter().map(|d| d.trim()).filter(|d| !d.is_empty()) {
        let a: std::net::IpAddr = d.parse().map_err(|_| anyhow!("'{d}' is not a DNS server address"))?;
        if !dns.contains(&a.to_string()) {
            dns.push(a.to_string());
        }
    }
    let line = net.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(",");
    Ok((line, dns))
}

/// Writes the change into the container's config. Takes effect with the reboot that follows.
pub async fn apply(pve: &Pve, c: &Change, fqdn: &str) -> Result<Own> {
    let (node, vmid, iface, cfg) = locate(pve).await?;
    let (line, dns) = plan(cfg.get(&iface).and_then(Value::as_str).unwrap_or(""), c)?;
    let mut form = vec![(iface.clone(), line)];
    let mut delete = Vec::new();
    if dns.is_empty() { delete.push("nameserver") } else { form.push(("nameserver".into(), dns.join(" "))) }
    // The search domain is the DNS name's domain, as the installer set it.
    if let Some((_, domain)) = fqdn.split_once('.') {
        form.push(("searchdomain".into(), domain.to_owned()));
    }
    if !delete.is_empty() {
        form.push(("delete".into(), delete.join(",")));
    }
    let _: Value = pve.put(&format!("/nodes/{}/lxc/{vmid}/config", enc(&node)), form).await?;
    read(pve).await
}

/// The studio's time zone: what its container's config says ("host" follows the node, as the
/// installer set it) and the zone the container runs on now. Maintenance windows are in it.
#[derive(Debug, Clone, Serialize)]
pub struct TimeZone {
    pub node: String,
    pub vmid: u32,
    pub config: String,
    pub current: String,
}

fn current_zone() -> String {
    std::fs::read_to_string("/etc/timezone")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| std::fs::read_link("/etc/localtime").ok().and_then(|p| p.to_string_lossy().split("zoneinfo/").nth(1).map(str::to_owned)))
        .unwrap_or_else(|| "UTC".into())
}

pub async fn read_timezone(pve: &Pve) -> Result<TimeZone> {
    let (node, vmid, _, cfg) = locate(pve).await?;
    Ok(TimeZone { node, vmid, config: cfg.get("timezone").and_then(Value::as_str).unwrap_or("host").to_owned(), current: current_zone() })
}

/// "host", or an IANA zone the container knows (its tzdata has the file).
pub fn zone_ok(tz: &str) -> bool {
    tz == "host"
        || (!tz.is_empty()
            && tz.len() <= 64
            && !tz.contains("..")
            && tz.chars().all(|c| c.is_ascii_alphanumeric() || "/_-+".contains(c))
            && std::path::Path::new("/usr/share/zoneinfo").join(tz).is_file())
}

/// Writes the zone into the container's config; it takes effect with the reboot that follows.
pub async fn set_timezone(pve: &Pve, tz: &str) -> Result<TimeZone> {
    if !zone_ok(tz) {
        bail!("'{tz}' is not a time zone");
    }
    let (node, vmid, _, _) = locate(pve).await?;
    let _: Value = pve.put(&format!("/nodes/{}/lxc/{vmid}/config", enc(&node)), vec![("timezone".into(), tz.to_owned())]).await?;
    Ok(TimeZone { node, vmid, config: tz.to_owned(), current: current_zone() })
}

/// Restarts the studio's container so the new network is in place - the studio stops
/// with it, so this is called after the answer went out.
pub async fn reboot(pve: &Pve, node: &str, vmid: u32) -> Result<()> {
    let _: Value = pve.post(&format!("/nodes/{}/lxc/{vmid}/status/reboot", enc(node)), vec![]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ch(mode: &str, ip: &str, gw: &str, dns: &[&str]) -> Change {
        Change { mode: mode.into(), ip: ip.into(), gw: gw.into(), dns: dns.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn static_keeps_the_rest_of_the_device() {
        let (line, dns) = plan("name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=dhcp,tag=20,type=veth", &ch("static", "10.10.0.21/24", "10.10.0.1", &["10.10.0.1", " ", "10.10.0.1", "1.1.1.1"])).unwrap();
        assert_eq!(line, "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,tag=20,type=veth,ip=10.10.0.21/24,gw=10.10.0.1");
        assert_eq!(dns, ["10.10.0.1", "1.1.1.1"]);
    }

    #[test]
    fn dhcp_drops_the_gateway() {
        let (line, _) = plan("name=eth0,bridge=vmbr0,gw=10.10.0.1,ip=10.10.0.20/24", &ch("dhcp", "", "", &[])).unwrap();
        assert_eq!(line, "name=eth0,bridge=vmbr0,ip=dhcp");
    }

    #[test]
    fn refuses_what_cannot_work() {
        assert!(plan("name=eth0", &ch("static", "10.10.0.21", "10.10.0.1", &[])).is_err());
        assert!(plan("name=eth0", &ch("static", "10.10.0.21/24", "10.10.1.1", &[])).is_err());
        assert!(plan("name=eth0", &ch("static", "10.10.0.21/24", "10.10.0.21", &[])).is_err());
        assert!(plan("name=eth0", &ch("static", "10.10.0.21/24", "10.10.0.1", &["dns.example"])).is_err());
    }
}
