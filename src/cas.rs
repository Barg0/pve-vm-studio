//! The CAs the studio trusts for PVE's certificate beyond the system's public roots: the
//! cluster CA the installer put in (config ca_file), and the ones an admin added in Studio
//! settings - an internal CA (AD CS and the like) a PVE certificate may come from. The
//! added ones live in one PEM file in the data directory.

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// One certificate as the card shows it.
#[derive(Debug, Clone, Serialize)]
pub struct CaInfo {
    pub name: String,
    pub issuer: String,
    /// "root" (self-signed) or "intermediate".
    pub kind: String,
    pub not_after: String,
    /// SHA-256 of the DER, upper-case hex with colons - also the id a delete names.
    pub fingerprint: String,
    #[serde(skip)]
    pub der: Vec<u8>,
}

/// What a file held: the CAs in it, and the names of what was not a CA.
#[derive(Debug, Default, Serialize)]
pub struct Parsed {
    pub cas: Vec<CaInfo>,
    pub skipped: Vec<String>,
}

pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join("trusted-cas.pem")
}

fn cn(name: &x509_parser::x509::X509Name) -> String {
    name.iter_common_name().next().and_then(|c| c.as_str().ok()).map(str::to_owned).unwrap_or_else(|| name.to_string())
}

pub fn fingerprint(der: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, der).as_ref().iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// Every certificate in a blob of DER: a lone certificate, or the ones a PKCS#7 bundle
/// (.p7b) carries - found by reading a certificate wherever one starts and stepping over it.
fn certs_in_der(der: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 < der.len() {
        if der[i] == 0x30 {
            if let Ok((rest, _)) = x509_parser::parse_x509_certificate(&der[i..]) {
                let len = der.len() - i - rest.len();
                out.push(der[i..i + len].to_vec());
                i += len;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Whatever Windows or OpenSSL exports: PEM (CERTIFICATE or PKCS7 blocks, one or many),
/// DER, or a DER .p7b.
pub fn parse(bytes: &[u8]) -> Result<Parsed> {
    let text = String::from_utf8_lossy(bytes);
    let mut blobs = Vec::new();
    if text.contains("-----BEGIN ") {
        let mut rest = text.as_ref();
        while let Some(start) = rest.find("-----BEGIN ") {
            let after = &rest[start..];
            let Some(head_end) = after[11..].find("-----").map(|e| 11 + e + 5) else { break };
            let Some(end) = after.find("-----END ") else { break };
            let b64: String = after[head_end..end].chars().filter(|c| !c.is_whitespace()).collect();
            if let Ok(d) = base64::engine::general_purpose::STANDARD.decode(b64) {
                blobs.push(d);
            }
            rest = &after[end + 9..];
        }
    } else {
        blobs.push(bytes.to_vec());
    }
    let mut out = Parsed::default();
    for der in blobs.iter().flat_map(|b| certs_in_der(b)) {
        let (_, c) = x509_parser::parse_x509_certificate(&der).context("reading a certificate")?;
        let name = cn(c.subject());
        let is_ca = c.basic_constraints().ok().flatten().is_some_and(|b| b.value.ca);
        if !is_ca {
            out.skipped.push(name);
            continue;
        }
        let fp = fingerprint(&der);
        if out.cas.iter().any(|x| x.fingerprint == fp) {
            continue;
        }
        out.cas.push(CaInfo {
            kind: if c.subject() == c.issuer() { "root".into() } else { "intermediate".into() },
            issuer: cn(c.issuer()),
            not_after: c.validity().not_after.to_datetime().date().to_string(),
            fingerprint: fp,
            name,
            der,
        });
    }
    if out.cas.is_empty() && out.skipped.is_empty() {
        bail!("no certificate found - a .cer, .crt, .pem, .der or .p7b file is expected");
    }
    Ok(out)
}

pub fn read_file(p: &Path) -> Vec<CaInfo> {
    std::fs::read(p).ok().and_then(|b| parse(&b).ok()).map(|p| p.cas).unwrap_or_default()
}

fn to_pem(cas: &[CaInfo]) -> String {
    cas.iter()
        .map(|c| {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&c.der);
            let lines: Vec<&str> = b64.as_bytes().chunks(64).map(|l| std::str::from_utf8(l).unwrap_or("")).collect();
            format!("# {} ({})\n-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", c.name, c.fingerprint, lines.join("\n"))
        })
        .collect()
}

/// Adds CAs to the file, skipping ones it holds already; the whole list after.
pub fn add(data_dir: &Path, new: Vec<CaInfo>) -> Result<Vec<CaInfo>> {
    let mut all = read_file(&path(data_dir));
    for c in new {
        if !all.iter().any(|x| x.fingerprint == c.fingerprint) {
            all.push(c);
        }
    }
    write(data_dir, &all)?;
    Ok(all)
}

pub fn remove(data_dir: &Path, fingerprint: &str) -> Result<Vec<CaInfo>> {
    let mut all = read_file(&path(data_dir));
    let before = all.len();
    all.retain(|c| !c.fingerprint.eq_ignore_ascii_case(fingerprint));
    if all.len() == before {
        bail!("no such CA");
    }
    write(data_dir, &all)?;
    Ok(all)
}

fn write(data_dir: &Path, all: &[CaInfo]) -> Result<()> {
    let p = path(data_dir);
    let tmp = p.with_extension("pem.new");
    std::fs::write(&tmp, to_pem(all))?;
    std::fs::rename(&tmp, &p)?;
    Ok(())
}

// ---- single certificates, trusted by fingerprint ----

/// A node certificate trusted as it is (the maintenance console's "Trust this certificate
/// only"): no CA behind it the studio knows. It stops working when the node renews it.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct Pin {
    pub node: String,
    pub subject: String,
    pub not_after: String,
    /// SHA-256 of the DER, as `fingerprint` writes it.
    pub fingerprint: String,
    pub added_by: String,
    pub added_at: String,
}

pub fn pins_path(data_dir: &Path) -> PathBuf {
    data_dir.join("pinned-certs.json")
}

pub fn read_pins(data_dir: &Path) -> Vec<Pin> {
    std::fs::read(pins_path(data_dir)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// The fingerprints as raw SHA-256, what the PVE client compares a certificate with.
pub fn pin_digests(pins: &[Pin]) -> Vec<Vec<u8>> {
    pins.iter()
        .filter_map(|p| p.fingerprint.split(':').map(|h| u8::from_str_radix(h, 16).ok()).collect::<Option<Vec<u8>>>())
        .filter(|d| d.len() == 32)
        .collect()
}

pub fn write_pins(data_dir: &Path, pins: &[Pin]) -> Result<()> {
    let p = pins_path(data_dir);
    let tmp = p.with_extension("json.new");
    std::fs::write(&tmp, serde_json::to_vec_pretty(pins)?)?;
    std::fs::rename(&tmp, &p)?;
    Ok(())
}

/// One certificate of a chain as the console shows it.
#[derive(Debug, Clone, Serialize)]
pub struct CertSummary {
    pub subject: String,
    pub issuer: String,
    pub names: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub is_ca: bool,
    pub self_signed: bool,
    pub fingerprint: String,
    /// Where its issuer is published (AIA caIssuers): ldap:// and http:// URLs.
    pub aia: Vec<String>,
}

pub fn summary(der: &[u8]) -> Result<CertSummary> {
    let (_, c) = x509_parser::parse_x509_certificate(der).context("not a certificate")?;
    let mut names = Vec::new();
    let mut aia = Vec::new();
    for ext in c.extensions() {
        match ext.parsed_extension() {
            x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => {
                for n in &san.general_names {
                    match n {
                        x509_parser::extensions::GeneralName::DNSName(d) => names.push(format!("DNS:{d}")),
                        x509_parser::extensions::GeneralName::IPAddress(ip) => {
                            let s = match ip.len() {
                                4 => std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string(),
                                16 => <[u8; 16]>::try_from(*ip).map(|b| std::net::Ipv6Addr::from(b).to_string()).unwrap_or_default(),
                                _ => String::new(),
                            };
                            names.push(format!("IP:{s}"));
                        }
                        _ => {}
                    }
                }
            }
            x509_parser::extensions::ParsedExtension::AuthorityInfoAccess(a) => {
                for d in &a.accessdescs {
                    if d.access_method.to_id_string() == "1.3.6.1.5.5.7.48.2"
                        && let x509_parser::extensions::GeneralName::URI(u) = &d.access_location
                    {
                        aia.push((*u).to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    let day = |t: x509_parser::time::ASN1Time| t.to_datetime().date().to_string();
    Ok(CertSummary {
        subject: c.subject().to_string(),
        issuer: c.issuer().to_string(),
        names,
        not_before: day(c.validity().not_before),
        not_after: day(c.validity().not_after),
        is_ca: c.is_ca(),
        self_signed: c.subject() == c.issuer(),
        fingerprint: fingerprint(der),
        aia,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca(cn: &str) -> (rcgen::Certificate, rcgen::Issuer<'static, rcgen::KeyPair>) {
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        let k = rcgen::KeyPair::generate().unwrap();
        let c = p.self_signed(&k).unwrap();
        (c, rcgen::Issuer::new(p, k))
    }

    #[test]
    fn pem_der_and_a_bundle() {
        let (root, issuer) = ca("Contoso Root CA");
        let mut ip = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ip.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ip.distinguished_name.push(rcgen::DnType::CommonName, "Contoso Issuing CA");
        let inter = ip.signed_by(&rcgen::KeyPair::generate().unwrap(), &issuer).unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["pve-01.contoso.local".to_owned()]).unwrap().signed_by(&rcgen::KeyPair::generate().unwrap(), &issuer).unwrap();

        // DER, as Windows exports a .cer
        let p = parse(root.der()).unwrap();
        assert_eq!((p.cas.len(), p.cas[0].name.as_str(), p.cas[0].kind.as_str()), (1, "Contoso Root CA", "root"));
        // PEM with a chain and the server certificate
        let pem = format!("{}{}{}", leaf.pem(), inter.pem(), root.pem());
        let p = parse(pem.as_bytes()).unwrap();
        assert_eq!(p.cas.iter().map(|c| (c.name.as_str(), c.kind.as_str())).collect::<Vec<_>>(), [("Contoso Issuing CA", "intermediate"), ("Contoso Root CA", "root")]);
        assert_eq!(p.skipped.len(), 1, "the server certificate is not a CA");
        // A bundle: certificates one after another inside an outer structure (as .p7b holds them)
        let mut p7 = vec![0x30, 0x82, 0x00, 0x00, 0x06, 0x09, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa0, 0x00];
        p7.extend_from_slice(root.der());
        p7.extend_from_slice(inter.der());
        let p = parse(&p7).unwrap();
        assert_eq!(p.cas.len(), 2);
        assert!(parse(b"not a certificate").is_err());
    }

    #[test]
    fn add_and_remove_keep_one_file() {
        let dir = std::env::temp_dir().join(format!("pvs-cas-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (root, _) = ca("Fabrikam Root CA");
        let c = parse(root.der()).unwrap().cas;
        let fp = c[0].fingerprint.clone();
        assert_eq!(add(&dir, c.clone()).unwrap().len(), 1);
        assert_eq!(add(&dir, c).unwrap().len(), 1, "added twice is once");
        assert_eq!(read_file(&path(&dir))[0].fingerprint, fp);
        assert!(remove(&dir, &fp).unwrap().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }
}
