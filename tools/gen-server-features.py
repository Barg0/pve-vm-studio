#!/usr/bin/env python3
"""Server Manager feature names -> DISM feature names, read from Windows' own manifests.

Install-WindowsFeature takes Server Manager names (AD-Domain-Services); DISM, the only tool
WinPE has, takes the CBS update names (DirectoryServices-DomainController). Windows keeps the
mapping in its package manifests: every <update name="..."> that is a Server Manager
component carries a <ServerComponent UniqueName="..."> - plus its NonAncestorDependencies
(what Install-WindowsFeature adds on its own) and, on the management tools, an
<OptionalCompanionFor Type="RSAT" UniqueName="..."> (what -IncludeManagementTools adds). Role
services name their role as Parent= (Install-WindowsFeature brings the role along).

Regenerate from a Server ISO (Desktop Experience index - a superset of Core):
    7z e <server.iso> sources/install.wim
    wimlib-imagex extract install.wim 4 /Windows/servicing --dest-dir=svc --no-acls
    tools/gen-server-features.py svc/servicing/Packages > data/server-features-<build>.json
"""
import glob, json, sys, xml.etree.ElementTree as ET

NS = "{urn:schemas-microsoft-com:asm.v3}"
comps = {}
for f in glob.glob(sys.argv[1] + "/*.mum"):
    try:
        root = ET.parse(f).getroot()
    except ET.ParseError:
        continue
    for upd in root.iter(NS + "update"):
        dism = upd.get("name")
        for sc in upd.iter():
            # A definition has a DisplayName; a bare <ServerComponent UniqueName=...> is a
            # reference (a dependency, a member list).
            if not sc.tag.endswith("ServerComponent") or not sc.get("DisplayName"):
                continue
            e = comps.setdefault(sc.get("UniqueName"), {"dism": set(), "deps": set(), "tools_for": set(), "parent": ""})
            if sc.get("Parent"):
                e["parent"] = sc.get("Parent")
            # What it deploys, when it says so (<Deploys><Update Name=...>), else the update
            # it is defined in. The *_ua updates are user-assistance (help), not the feature.
            deploys = [d.get("Name") for d in sc.iter() if d.tag.endswith("Update") and d.get("Name")]
            for name in deploys or [dism]:
                if not name.endswith("_ua"):
                    e["dism"].add(name)
            for child in sc.iter():
                tag = child.tag.split("}")[-1]
                if tag == "NonAncestorDependencies":
                    e["deps"].update(d.get("UniqueName") for d in child if d.get("UniqueName"))
                if tag == "OptionalCompanionFor" and child.get("Type") == "RSAT":
                    e["tools_for"].add(child.get("UniqueName"))
tools = {}
for name, e in comps.items():
    for t in e["tools_for"]:
        tools.setdefault(t, set()).add(name)
out = {
    name: {"dism": sorted(e["dism"]), "parent": e["parent"], "deps": sorted(e["deps"]), "tools": sorted(tools.get(name, []))}
    for name, e in sorted(comps.items())
    if e["dism"]
}
json.dump(out, sys.stdout, indent=1, sort_keys=True)
print()
