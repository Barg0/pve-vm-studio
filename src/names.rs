//! What the studio calls things, the same everywhere - job titles, the activity list, logs,
//! mails: an image by the name the page gives it (IMAGE_CATALOG in web/studio.js, read by
//! build.rs), a gold as "W11 Enterprise 26H2 26300.9711 (c864831d)", an edition in the
//! studio's words - never Microsoft's EditionID (ServerDatacenterCor, Professional).

use crate::golds::{self, GoldRow};

include!(concat!(env!("OUT_DIR"), "/image_names.rs"));

/// An image's name: "Windows 11 Enterprise", "Windows Server 2025 Datacenter Core" - and a
/// virtual edition's gold ("Windows 11 Education"), which the page lists under its source.
pub fn image(id: &str) -> Option<&'static str> {
    IMAGE_NAMES.iter().find(|(i, _)| *i == id).map(|(_, l)| *l).or_else(|| crate::windows::virtual_label(id))
}

/// An image's short name, for a narrow label: "W11 Enterprise".
pub fn image_short(id: &str) -> String {
    short(image(id).unwrap_or(id))
}

/// A Windows media product's short name: "W11 26H2", "WS2025", "W11 Insider Beta".
pub fn product(id: &str) -> String {
    crate::uup::product(id).map(|p| short(&p.name.replace(", version", "").replace(',', ""))).unwrap_or_else(|| id.to_owned())
}

/// The short form for lists: "Windows Server 2025 ..." is WS2025, "Windows Server vNext ..."
/// WS vNext, "Windows 11 ..." W11. Other names stay as they are.
pub fn short(name: &str) -> String {
    if let Some(rest) = name.strip_prefix("Windows Server ") {
        return if rest.starts_with(|c: char| c.is_ascii_digit()) { format!("WS{rest}") } else { format!("WS {rest}") };
    }
    match name.strip_prefix("Windows 11 ") {
        Some(rest) => format!("W11 {rest}"),
        None => name.to_owned(),
    }
}

/// A Windows build as it is read: 26300.9711, without Windows' own 10.0.
pub fn build(raw: &str) -> &str {
    let raw = raw.trim();
    raw.strip_prefix("10.0.").filter(|r| r.contains('.')).unwrap_or(raw)
}

/// A gold's name from its parts. `iso` is the ISO it is baked from (its name says the
/// Insider channel); `build` the Windows build ("" for Linux: its version is in the name).
/// Windows 11 names its release (26H2) - an Insider build its channel; Server needs neither.
/// `fallback` names an image the studio has no name for (Windows' own: DISM's or the
/// sidecar's displayName); without one, the id.
pub fn gold_from(image_id: &str, build_raw: &str, iso: &str, id: &str, long: bool, fallback: &str) -> String {
    let name = image(image_id).map(str::to_owned).unwrap_or_else(|| if fallback.is_empty() { image_id.to_owned() } else { fallback.to_owned() });
    let mut out = if long { name } else { short(&name) };
    let b = build(build_raw);
    if image_id.starts_with("w11") && !b.is_empty() {
        let major: u64 = b.split('.').next().and_then(|m| m.parse().ok()).unwrap_or(0);
        let rel = match golds::CLIENT_RELEASES.iter().find(|(m, _)| *m == major) {
            Some((_, r)) => r,
            None => crate::uup::insider_of_iso(iso).map(|p| p.channel()).filter(|c| !c.is_empty()).unwrap_or(golds::INSIDER),
        };
        out = format!("{out} {rel}");
    }
    if b.contains('.') {
        out = format!("{out} {b}");
    }
    if id.is_empty() { out } else { format!("{out} ({id})") }
}

/// The id a gold is known by: its sidecar's id, else the first 8 of its own.
pub fn gold_id(g: &GoldRow) -> String {
    let m: serde_json::Value = serde_json::from_str(&g.manifest).unwrap_or_default();
    m["id"].as_str().map(str::to_owned).unwrap_or_else(|| g.id.chars().take(8).collect())
}

/// (build, ISO, Windows' own name) from a gold's sidecar and bake options.
fn gold_parts(g: &GoldRow) -> (String, String, String) {
    let m: serde_json::Value = serde_json::from_str(&g.manifest).unwrap_or_default();
    let build = if g.os == "windows" { m["build"].as_str().unwrap_or("").to_owned() } else { String::new() };
    let iso = serde_json::from_str::<crate::windows::WinBakeOptions>(&g.options).map(|o| o.iso).unwrap_or_default();
    (build, iso, m["displayName"].as_str().unwrap_or("").to_owned())
}

/// "W11 Enterprise 26H2 26300.9711 (c864831d)" - for lists, job titles and logs.
pub fn gold(g: &GoldRow) -> String {
    let (b, iso, own) = gold_parts(g);
    gold_from(&g.image_id, &b, &iso, &gold_id(g), false, &own)
}

/// "Windows 11 Enterprise 26H2" - the long name without build and id, for a mail's row that
/// shows those beside it. A Linux gold by its sidecar's name, codename included ("Ubuntu
/// 26.04 LTS (Resolute)").
pub fn gold_long(g: &GoldRow) -> String {
    let (b, iso, own) = gold_parts(g);
    if g.os == "linux" && !own.is_empty() {
        return own;
    }
    let full = gold_from(&g.image_id, &b, &iso, "", true, &own);
    let b = build(&b);
    full.strip_suffix(&format!(" {b}")).filter(|_| b.contains('.')).map(str::to_owned).unwrap_or(full)
}

/// An edition in the studio's words, from Microsoft's EditionID and installation type:
/// ServerDatacenter + Server Core is "Datacenter Core", Professional is "Pro".
pub fn edition(edition_id: &str, installation_type: &str) -> String {
    let id = edition_id.trim_end_matches("Eval");
    let eval = if edition_id.ends_with("Eval") { " Evaluation" } else { "" };
    if let Some(server) = id.strip_prefix("Server") {
        let base = match server.trim_end_matches("Cor").trim_end_matches("Core") {
            "Datacenter" => "Datacenter",
            "Standard" => "Standard",
            "Turbine" | "Azure" | "AzureEdition" => "Datacenter: Azure Edition",
            "Rdsh" => return "Enterprise multi-session".into(),
            other => other,
        };
        let shape = match installation_type {
            "Server Core" => " Core",
            "Server" => " Desktop",
            _ if server.ends_with("Cor") || server.ends_with("Core") => " Core",
            _ => "",
        };
        return format!("{base}{shape}{eval}");
    }
    let name = match id {
        "Professional" => "Pro",
        "ProfessionalN" => "Pro N",
        "ProfessionalEducation" => "Pro Education",
        "ProfessionalEducationN" => "Pro Education N",
        "ProfessionalWorkstation" => "Pro for Workstations",
        "ProfessionalWorkstationN" => "Pro for Workstations N",
        "Core" => "Home",
        "CoreN" => "Home N",
        "CoreSingleLanguage" => "Home Single Language",
        "CoreCountrySpecific" => "Home China",
        "ProfessionalSingleLanguage" => "Pro Single Language",
        "ProfessionalCountrySpecific" => "Pro China",
        "CloudEdition" => "SE",
        "CloudEditionN" => "SE N",
        "IoTEnterpriseK" => "IoT Enterprise K",
        "EnterpriseG" => "Enterprise G",
        "EnterpriseGN" => "Enterprise G N",
        "EnterpriseS" => "Enterprise LTSC",
        "EnterpriseSN" => "Enterprise LTSC N",
        "EnterpriseMultiSession" => "Enterprise multi-session",
        "IoTEnterprise" => "IoT Enterprise",
        "IoTEnterpriseS" => "IoT Enterprise LTSC",
        "EducationN" => "Education N",
        "EnterpriseN" => "Enterprise N",
        other => other,
    };
    format!("{name}{eval}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn images_by_the_pages_names() {
        assert_eq!(image("w11-enterprise"), Some("Windows 11 Enterprise"));
        assert_eq!(image("ws2025-datacenter-core"), Some("Windows Server 2025 Datacenter Core"));
        assert_eq!(short("Windows Server 2025 Datacenter Core"), "WS2025 Datacenter Core");
        assert_eq!(short("Windows Server vNext Standard Desktop"), "WS vNext Standard Desktop");
        assert_eq!(short("Windows 11 Enterprise multi-session"), "W11 Enterprise multi-session");
        assert_eq!(short("Ubuntu 26.04 LTS"), "Ubuntu 26.04 LTS");
        assert_eq!(product("w11-26h2"), "W11 26H2");
        assert_eq!(product("ws2025"), "WS2025");
        assert_eq!(product("w11-beta"), "W11 Insider Beta");
        assert_eq!(product("ws-insider"), "WS vNext");
        // Every Windows image the studio bakes has a name.
        for id in ["ws2022-standard-core", "ws2025-datacenter-az-desktop", "wsvnext-datacenter-core", "w11-pro-n", "w11-enterprise-ms"] {
            assert!(image(id).is_some(), "{id}");
        }
        // Every image id a bake can produce has a name - from any edition, any virtual one.
        for v in crate::windows::VIRTUAL_EDITIONS {
            let img = crate::wim::WimImage { edition_id: if v.from.is_empty() { "Professional".into() } else { v.from.into() }, installation_type: "Client".into(), build: "26300".into(), ..Default::default() };
            let id = crate::windows::gold_image_id(&img, v.key);
            assert!(image(&id).is_some(), "{} makes {id}, which has no name", v.key);
        }
        // And every edition on the media the studio builds from.
        for ed in ["Professional", "ProfessionalN", "Enterprise", "EnterpriseN"] {
            let img = crate::wim::WimImage { edition_id: ed.into(), installation_type: "Client".into(), build: "26300".into(), ..Default::default() };
            let id = crate::windows::image_id(&img);
            assert!(image(&id).is_some(), "{ed} makes {id}, which has no name");
        }
    }

    #[test]
    fn gold_names() {
        let iso = "local:iso/enus-w11-26300.9711.iso";
        assert_eq!(gold_from("w11-enterprise", "10.0.26300.9711", iso, "c864831d", false, ""), "W11 Enterprise 26H2 26300.9711 (c864831d)");
        assert_eq!(gold_from("w11-pro", "26200.9550", iso, "", true, ""), "Windows 11 Pro 25H2 26200.9550");
        assert_eq!(gold_from("w11-pro", "29683.1000", "local:iso/enus-w11-future-pro-29683.1000.iso", "ab12cd34", false, ""), "W11 Pro Future Platforms 29683.1000 (ab12cd34)");
        assert_eq!(gold_from("w11-pro", "26220.9606", "local:iso/enus-w11-beta-pro-26220.9606.iso", "ab12cd34", false, ""), "W11 Pro Beta 26220.9606 (ab12cd34)");
        // An Insider build whose channel the ISO's name does not tell.
        assert_eq!(gold_from("w11-pro", "26220.9606", "local:iso/somebody-elses.iso", "", false, ""), "W11 Pro Insider Preview 26220.9606");
        assert_eq!(gold_from("ws2025-datacenter-core", "10.0.26100.33650", "", "f04f3865", false, ""), "WS2025 Datacenter Core 26100.33650 (f04f3865)");
        assert_eq!(gold_from("ubuntu2604", "", "", "1691da27", false, ""), "Ubuntu 26.04 LTS (1691da27)");
        // No name of the studio's: Windows' own, else the id.
        assert_eq!(gold_from("w11-core", "26300.9711", iso, "1691da27", false, "Windows 11 Home"), "W11 Home 26H2 26300.9711 (1691da27)");
        assert_eq!(gold_from("unknown-image", "", "", "1691da27", false, ""), "unknown-image (1691da27)");
    }

    #[test]
    fn editions_in_the_studios_words() {
        assert_eq!(edition("ServerDatacenter", "Server Core"), "Datacenter Core");
        assert_eq!(edition("ServerDatacenterCor", ""), "Datacenter Core");
        assert_eq!(edition("ServerStandard", "Server"), "Standard Desktop");
        assert_eq!(edition("ServerStandardEval", "Server"), "Standard Desktop Evaluation");
        assert_eq!(edition("ServerTurbine", "Server Core"), "Datacenter: Azure Edition Core");
        assert_eq!(edition("Professional", "Client"), "Pro");
        assert_eq!(edition("EnterpriseS", "Client"), "Enterprise LTSC");
        assert_eq!(edition("ServerRdsh", "Client"), "Enterprise multi-session");
        assert_eq!(edition("Enterprise", "Client"), "Enterprise");
        // Every target DISM listed for a Pro index on 2026-10-15, in the studio's words.
        let targets = ["Education", "ProfessionalCountrySpecific", "ProfessionalEducation", "ProfessionalSingleLanguage", "ProfessionalWorkstation", "Enterprise", "IoTEnterprise", "IoTEnterpriseK", "ServerRdsh", "CloudEdition"];
        let named: Vec<String> = targets.iter().map(|t| edition(t, "Client")).collect();
        assert_eq!(named, ["Education", "Pro China", "Pro Education", "Pro Single Language", "Pro for Workstations", "Enterprise", "IoT Enterprise", "IoT Enterprise K", "Enterprise multi-session", "SE"]);
    }
}
