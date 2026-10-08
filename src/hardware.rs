//! VM hardware defaults (VM settings → Hardware defaults) and what the cluster's nodes are
//! made of. The design keeps the defaults (`defaults.hardware`), a VM card may override
//! them; "auto" is settled at deploy against the nodes as PVE reports them.
//!
//! Sources (docs/vm-tuning.md): PVE admin guide, CPU type - `host` when every node has the
//! same CPU (and microcode), otherwise the lowest model all run; x86-64-vX for Intel and AMD
//! mixed. The generic x86-64-vX types carry no CPU security flags and no nesting.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::pve::{enc, Pve};

/// One node's processor, from `/nodes/{node}/status`.
#[derive(Debug, Clone, Serialize)]
pub struct NodeCpu {
    pub node: String,
    pub model: String,
    pub vendor: String,
    pub sockets: u32,
    /// Cores per socket.
    pub cores: u32,
    /// Threads in all.
    pub cpus: u32,
    pub memory_gb: u64,
    /// The node is itself a VM (its CPU says "hypervisor").
    pub virtual_node: bool,
    /// Right now: CPU load 0-1 and memory in use, as PVE's resource list has them.
    pub cpu_load: f64,
    pub memory_used_gb: f64,
    #[serde(skip)]
    pub flags: Vec<String>,
}

pub async fn cluster(pve: &Pve) -> Result<Vec<NodeCpu>> {
    #[derive(Deserialize)]
    struct Info {
        #[serde(default)]
        model: String,
        #[serde(default)]
        vendor: String,
        #[serde(default)]
        sockets: u32,
        #[serde(default)]
        cores: u32,
        #[serde(default)]
        cpus: u32,
        #[serde(default)]
        flags: String,
    }
    #[derive(Deserialize)]
    struct Mem {
        #[serde(default)]
        total: u64,
    }
    #[derive(Deserialize)]
    struct Status {
        cpuinfo: Info,
        memory: Mem,
    }
    let mut out = Vec::new();
    for r in pve.resources().await?.into_iter().filter(|r| r.kind == "node" && r.status.as_deref() == Some("online")) {
        let Some(node) = r.node.clone() else { continue };
        let Ok(s) = pve.get::<Status>(&format!("/nodes/{}/status", enc(&node))).await else { continue };
        let flags: Vec<String> = s.cpuinfo.flags.split_whitespace().map(str::to_owned).collect();
        out.push(NodeCpu {
            node,
            model: short_model(&s.cpuinfo.model),
            vendor: s.cpuinfo.vendor,
            sockets: s.cpuinfo.sockets.max(1),
            cores: s.cpuinfo.cores.max(1),
            cpus: s.cpuinfo.cpus,
            memory_gb: s.memory.total / (1 << 30),
            virtual_node: flags.iter().any(|f| f == "hypervisor"),
            cpu_load: r.cpu.unwrap_or(0.0),
            memory_used_gb: r.mem.unwrap_or(0) as f64 / (1u64 << 30) as f64,
            flags,
        });
    }
    out.sort_by(|a, b| a.node.cmp(&b.node));
    Ok(out)
}

/// The processor's name without the marketing around it: "11th Gen Intel(R) Core(TM)
/// i9-11900K @ 3.50GHz" is "Intel Core i9-11900K", "AMD EPYC 9654 96-Core Processor" is
/// "AMD EPYC 9654".
pub fn short_model(raw: &str) -> String {
    let s = raw.replace("(R)", "").replace("(TM)", "").replace("(tm)", "");
    let s = s.split(" @ ").next().unwrap_or(&s);
    s.split_whitespace()
        .filter(|w| !matches!(*w, "CPU" | "Processor" | "Gen"))
        .filter(|w| !(w.ends_with("th") || w.ends_with("st") || w.ends_with("nd") || w.ends_with("rd")) || !w.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .filter(|w| !w.ends_with("-Core"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The design's defaults (`defaults.hardware`), PVE's own where the design has none.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Defaults {
    /// "auto" or a PVE CPU type (host, x86-64-v3, a named or custom model).
    pub cpu: String,
    /// "auto": the vendor's security flags on a generic x86-64-vX type; "off": none.
    pub security_flags: String,
    pub nested: bool,
    pub ksm: bool,
    /// "auto" (one queue per vCPU, 8 at most, on servers), "off".
    pub queues: String,
    pub protection: bool,
}

impl Default for Defaults {
    fn default() -> Self {
        Self { cpu: "auto".into(), security_flags: "auto".into(), nested: true, ksm: true, queues: "auto".into(), protection: true }
    }
}

const V3: &[&str] = &["avx", "avx2", "bmi1", "bmi2", "f16c", "fma", "abm", "movbe", "xsave", "aes", "popcnt", "sse4_2", "ssse3"];
const V2_AES: &[&str] = &["aes", "popcnt", "sse4_2", "ssse3"];

fn all_have(nodes: &[NodeCpu], flags: &[&str]) -> bool {
    nodes.iter().all(|n| flags.iter().all(|f| n.flags.iter().any(|x| x == f)))
}

/// "auto" for these nodes, and why: `host` when every node has the same CPU, else the
/// newest generic level all of them run.
pub fn pick_cpu(nodes: &[NodeCpu]) -> (String, String) {
    let real: Vec<&NodeCpu> = nodes.iter().filter(|n| !n.virtual_node).collect();
    if nodes.is_empty() {
        return ("x86-64-v3".into(), "no node answered".into());
    }
    if real.len() == nodes.len() && nodes.iter().all(|n| n.model == nodes[0].model && n.vendor == nodes[0].vendor) {
        let why = if nodes.len() == 1 { "the only node".to_owned() } else { format!("all {} nodes have the same CPU", nodes.len()) };
        return ("host".into(), why);
    }
    if real.len() < nodes.len() {
        return ("x86-64-v3".into(), "a node is itself a VM".into());
    }
    if all_have(nodes, V3) {
        ("x86-64-v3".into(), "the nodes have different CPUs".into())
    } else if all_have(nodes, V2_AES) {
        ("x86-64-v2-AES".into(), "a node predates AVX2".into())
    } else {
        ("x86-64-v2".into(), "a node predates AES-NI".into())
    }
}

/// A generic type's security flags every node can give (PVE's flag names): md-clear, pcid,
/// spec-ctrl, ssbd on Intel; ibpb, amd-ssbd, virt-ssbd on AMD. Empty for host and named
/// models, which carry their own.
pub fn security_flags(nodes: &[NodeCpu], cpu: &str) -> Vec<&'static str> {
    if !cpu.starts_with("x86-64-v") || nodes.is_empty() {
        return vec![];
    }
    let intel = nodes.iter().all(|n| n.vendor == "GenuineIntel");
    let amd = nodes.iter().all(|n| n.vendor == "AuthenticAMD");
    let map: &[(&str, &str)] = if intel {
        &[("md-clear", "md_clear"), ("pcid", "pcid"), ("spec-ctrl", "ibrs"), ("ssbd", "ssbd")]
    } else if amd {
        &[("ibpb", "ibpb"), ("amd-ssbd", "ssbd"), ("virt-ssbd", "virt_ssbd")]
    } else {
        &[]
    };
    map.iter().filter(|(_, cpuinfo)| all_have(nodes, &[cpuinfo])).map(|(pve, _)| *pve).collect()
}

/// PVE's `cpu` value: the type and its flags. Nesting is a flag (`nested-virt`, PVE 9.1+) on
/// host and named models; a generic type has none to give.
pub fn cpu_value(cpu: &str, nested: bool, flags: &[&str], nested_flag: bool) -> String {
    let mut f: Vec<String> = flags.iter().map(|x| format!("+{x}")).collect();
    let generic = cpu.starts_with("x86-64-v") || matches!(cpu, "kvm64" | "qemu64" | "kvm32" | "qemu32");
    if !generic && nested_flag {
        match (cpu == "host", nested) {
            // host carries vmx/svm already.
            (true, true) => {}
            (true, false) => f.push("-nested-virt".into()),
            (false, true) => f.push("+nested-virt".into()),
            (false, false) => {}
        }
    }
    if f.is_empty() { cpu.to_owned() } else { format!("{cpu},flags={}", f.join(";")) }
}

/// A VM's sockets: as many as the node it lands on has, so with NUMA (always on) its
/// memory and cores split the way the node's do - on a one-socket node one NUMA node, the
/// same as NUMA off. Fewer where its cores do not split evenly, and two at most for a
/// Windows client (Pro and Enterprise use two sockets, no more).
pub fn sockets_for(node: Option<&NodeCpu>, cores: u32, client: bool) -> u32 {
    let mut s = node.map_or(1, |n| n.sockets.max(1)).min(cores.max(1));
    if client {
        s = s.min(2);
    }
    while s > 1 && cores % s != 0 {
        s -= 1;
    }
    s
}

/// PVE 9.1 brought the `nested-virt` flag.
pub async fn nested_flag(pve: &Pve) -> bool {
    pve.version().await.ok().is_some_and(|v| {
        let mut it = v.release.split('.').map(|x| x.parse::<u32>().unwrap_or(0));
        let (maj, min) = (it.next().unwrap_or(0), it.next().unwrap_or(0));
        maj > 9 || (maj == 9 && min >= 1)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, model: &str, vendor: &str, sockets: u32, flags: &str) -> NodeCpu {
        NodeCpu { node: name.into(), model: model.into(), vendor: vendor.into(), sockets, cores: 8, cpus: 16, memory_gb: 64, virtual_node: false, cpu_load: 0.0, memory_used_gb: 0.0, flags: flags.split(' ').map(str::to_owned).collect() }
    }

    #[test]
    fn short_names() {
        assert_eq!(short_model("11th Gen Intel(R) Core(TM) i9-11900K @ 3.50GHz"), "Intel Core i9-11900K");
        assert_eq!(short_model("AMD EPYC 9654 96-Core Processor"), "AMD EPYC 9654");
        assert_eq!(short_model("Intel(R) Xeon(R) CPU E5-2690 v4 @ 2.60GHz"), "Intel Xeon E5-2690 v4");
    }

    #[test]
    fn picks() {
        let all = "avx avx2 bmi1 bmi2 f16c fma abm movbe xsave aes popcnt sse4_2 ssse3 md_clear pcid ibrs ssbd";
        let a = node("pve-01", "i9-11900K", "GenuineIntel", 1, all);
        assert_eq!(pick_cpu(&[a.clone(), a.clone()]).0, "host");
        let b = node("pve-03", "Xeon E5-2690 v4", "GenuineIntel", 2, all);
        assert_eq!(pick_cpu(&[a.clone(), b.clone()]).0, "x86-64-v3");
        let old = node("pve-04", "Xeon X5670", "GenuineIntel", 2, "aes popcnt sse4_2 ssse3");
        assert_eq!(pick_cpu(&[a.clone(), old]).0, "x86-64-v2-AES");
        assert_eq!(security_flags(&[a.clone(), b], "x86-64-v3"), vec!["md-clear", "pcid", "spec-ctrl", "ssbd"]);
        assert!(security_flags(&[a.clone()], "host").is_empty());
        assert_eq!(cpu_value("host", true, &[], true), "host");
        assert_eq!(cpu_value("host", false, &[], true), "host,flags=-nested-virt");
        assert_eq!(cpu_value("x86-64-v3", true, &["md-clear", "pcid"], true), "x86-64-v3,flags=+md-clear;+pcid");
        assert_eq!(cpu_value("Skylake-Client-v4", true, &[], true), "Skylake-Client-v4,flags=+nested-virt");
        assert_eq!(sockets_for(Some(&a), 4, false), 1);
        assert_eq!(sockets_for(None, 4, false), 1);
        let two = node("big", "EPYC", "AuthenticAMD", 2, all);
        assert_eq!(sockets_for(Some(&two), 4, false), 2);
        assert_eq!(sockets_for(Some(&two), 3, false), 1);
        assert_eq!(sockets_for(Some(&two), 1, false), 1);
        let four = node("huge", "Xeon", "GenuineIntel", 4, all);
        assert_eq!(sockets_for(Some(&four), 8, false), 4);
        assert_eq!(sockets_for(Some(&four), 6, false), 3);
        assert_eq!(sockets_for(Some(&four), 8, true), 2);
    }
}
