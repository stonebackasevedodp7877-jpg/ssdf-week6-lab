#!/usr/bin/env python3
"""RV.1.1 / RV.2.1 remediation report from the image SBOM + grype results.

Flags:
  * Python packages that are obsolete (behind the latest PyPI release)
  * Python packages with known vulnerabilities and the fixed version
  * OS / other packages with fixable Critical/High findings
Output: Markdown report suitable for a ticket or PR description.
"""
import argparse
import datetime as dt
import json
import urllib.request
from pathlib import Path

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Negligible": 4, "Unknown": 5}
SLA = {"Critical": "7 days", "High": "30 days", "Medium": "90 days", "Low": "next release"}


def version_key(v: str):
    parts = []
    for p in v.replace("-", ".").split("."):
        parts.append((0, int(p)) if p.isdigit() else (1, p))
    return parts


def latest_pypi(name: str):
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json", timeout=10) as r:
            return json.load(r)["info"]["version"]
    except Exception:  # offline or package not on PyPI
        return None


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--sbom", required=True)
    p.add_argument("--grype", required=True)
    p.add_argument("--requirements", default="app/requirements.txt")
    p.add_argument("--image", default="")
    p.add_argument("--out", required=True)
    a = p.parse_args()

    bom = json.loads(Path(a.sbom).read_text())
    grype = json.loads(Path(a.grype).read_text())

    direct = set()
    rp = Path(a.requirements)
    if rp.exists():
        for line in rp.read_text().splitlines():
            line = line.split("#")[0].strip()
            if "==" in line:
                direct.add(line.split("==")[0].strip().lower())

    vulns_by_pkg = {}
    for m in grype.get("matches", []):
        v, art = m["vulnerability"], m["artifact"]
        key = (art["name"].lower(), art["version"])
        vulns_by_pkg.setdefault(key, {})[v["id"]] = {
            "id": v["id"],
            "severity": v.get("severity", "Unknown"),
            "fix": ", ".join(v.get("fix", {}).get("versions", [])) or "-",
            "state": v.get("fix", {}).get("state", "unknown"),
            "type": art.get("type", ""),
            "name": art["name"],
            "version": art["version"],
        }

    py_rows = []
    for c in bom.get("components", []):
        purl = c.get("purl", "")
        if not purl.startswith("pkg:pypi/"):
            continue
        name, ver = c["name"], c.get("version", "")
        latest = latest_pypi(name)
        if latest is None:
            status = "unknown (PyPI unreachable)"
        elif version_key(ver) < version_key(latest):
            status = "OBSOLETE"
        else:
            status = "current"
        vl = sorted(vulns_by_pkg.get((name.lower(), ver), {}).values(), key=lambda x: SEV_ORDER.get(x["severity"], 9))
        py_rows.append((name, ver, latest or "?", status, vl, name.lower() in direct))
    py_rows.sort(key=lambda r: (r[3] != "OBSOLETE", not r[4], r[0].lower()))

    all_v = [v for d in vulns_by_pkg.values() for v in d.values()]
    counts = {s: sum(1 for v in all_v if v["severity"] == s) for s in SEV_ORDER}
    blocking = sorted((v for v in all_v if v["severity"] in ("Critical", "High")),
                      key=lambda x: (SEV_ORDER[x["severity"]], x["name"]))

    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    db = grype.get("descriptor", {}).get("db", {})
    db_built = db.get("built") or db.get("status", {}).get("built", "n/a")
    out = [
        "# SBOM Vulnerability Remediation Report",
        "",
        f"- **Image:** `{a.image or 'n/a'}`",
        f"- **SBOM:** `{a.sbom}` ({len(bom.get('components', []))} components, CycloneDX {bom.get('specVersion', '?')})",
        f"- **Scanner:** grype {grype.get('descriptor', {}).get('version', '?')} (DB built {db_built})",
        f"- **Generated:** {now}",
        "- **SSDF practices:** RV.1.1 (identify vulnerabilities continuously), RV.2.1 (assess, prioritize, remediate)",
        "",
        "## Severity summary",
        "",
        "| Critical | High | Medium | Low | Negligible/Unknown |",
        "|---:|---:|---:|---:|---:|",
        f"| {counts['Critical']} | {counts['High']} | {counts['Medium']} | {counts['Low']} | {counts['Negligible'] + counts['Unknown']} |",
        "",
        "## Python dependencies",
        "",
        "| Package | Direct | Installed | Latest on PyPI | Status | Known vulnerabilities | Action |",
        "|---|:---:|---|---|---|---|---|",
    ]
    for name, ver, latest, status, vl, is_direct in py_rows:
        vtxt = "<br>".join(f"{v['severity']} {v['id']} (fix {v['fix']})" for v in vl) or "none"
        if vl:
            action = "Upgrade to fixed version (SLA " + SLA.get(vl[0]["severity"], "next release") + ")"
        elif status == "OBSOLETE":
            action = f"Bump to {latest} via Dependabot/Renovate PR"
        else:
            action = "-"
        out.append(f"| {name} | {'yes' if is_direct else 'transitive'} | {ver} | {latest} | {status} | {vtxt} | {action} |")

    out += ["", "## Critical / High findings (all package types)", ""]
    if blocking:
        out += ["| Severity | ID | Package | Type | Installed | Fixed in | Fix state | SLA |",
                "|---|---|---|---|---|---|---|---|"]
        for v in blocking:
            out.append(f"| {v['severity']} | {v['id']} | {v['name']} | {v['type']} | {v['version']} | {v['fix']} | {v['state']} | {SLA[v['severity']]} |")
        out += ["",
                "Fix state `fixed`: rebuild on the patched base image / bump the package. "
                "Fix state `not-fixed` or `wont-fix`: no upstream patch; either switch base image "
                "or record a time-boxed risk acceptance in `policy/exceptions.json` (id, package, "
                "justification, expires). The deployment gate blocks until one of these is done."]
    else:
        out.append("None. The image meets the zero Critical/High threshold enforced by `attestation.rego`.")

    obsolete = [r for r in py_rows if r[3] == "OBSOLETE"]
    out += ["", "## Automated remediation", "",
            f"{len(obsolete)} obsolete Python package(s) detected. Automated pull requests are configured in "
            "`.github/dependabot.yml` (pip, docker, github-actions ecosystems; security updates grouped) and "
            "`renovate.json` (digest pinning, vulnerability alerts). Each bump PR re-runs "
            "`hardened_pipeline.yml`, so a new SBOM, signature, provenance and policy decision are produced "
            "before merge.", ""]
    Path(a.out).write_text("\n".join(out) + "\n")
    print(f"wrote {a.out}: {len(py_rows)} python pkgs, {len(obsolete)} obsolete, "
          f"{counts['Critical']} critical, {counts['High']} high")


if __name__ == "__main__":
    main()
