#!/usr/bin/env python3
"""Assemble policy_input.json for conftest from VERIFIED evidence only.

Inputs (all produced by verification commands, not by the build itself):
  --signature-json   stdout of `cosign verify`            (+ --signature-rc)
  --sbom-att         stdout of `cosign verify-attestation --type cyclonedx`
  --prov-att         stdout of `cosign verify-attestation --type slsaprovenance1`
                     or `gh attestation verify --format json`
  --grype            grype JSON report for the SBOM
A failed verification (non-zero rc) always yields verified=false.
"""
import argparse
import base64
import json
from pathlib import Path


def json_docs(path: str):
    """Yield JSON documents from a file holding one JSON value or JSON lines."""
    p = Path(path) if path else None
    if not p or not p.exists():
        return
    text = p.read_text().strip()
    if not text:
        return
    try:
        doc = json.loads(text)
        yield from (doc if isinstance(doc, list) else [doc])
        return
    except json.JSONDecodeError:
        pass
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("{", "[")):
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield from (doc if isinstance(doc, list) else [doc])


def statements(path: str):
    """Extract in-toto statements from cosign DSSE output or gh attestation output."""
    for doc in json_docs(path):
        if "verificationResult" in doc:  # gh attestation verify --format json
            st = doc["verificationResult"].get("statement")
            if st:
                yield st
        elif "payload" in doc:  # cosign verify-attestation (DSSE envelope)
            try:
                yield json.loads(base64.b64decode(doc["payload"]))
            except (ValueError, json.JSONDecodeError):
                continue
        elif "predicateType" in doc:
            yield doc


def subject_digests(st) -> list:
    return sorted({f"sha256:{s['digest']['sha256']}" for s in st.get("subject", []) if "sha256" in s.get("digest", {})})


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def components(bom) -> set:
    return {(c.get("name"), c.get("version"), c.get("purl")) for c in bom.get("components", [])}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--image-ref", required=True)
    p.add_argument("--digest", required=True)
    p.add_argument("--signature-json", required=True)
    p.add_argument("--signature-rc", type=int, required=True)
    p.add_argument("--signature-method", default="key")
    p.add_argument("--sbom", required=True, help="SBOM that was scanned by grype")
    p.add_argument("--sbom-att", required=True)
    p.add_argument("--sbom-att-rc", type=int, required=True)
    p.add_argument("--prov-att", required=True)
    p.add_argument("--prov-att-rc", type=int, required=True)
    p.add_argument("--grype", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args()

    # --- signature -------------------------------------------------------
    signed = sorted({
        d["critical"]["image"]["docker-manifest-digest"]
        for d in json_docs(a.signature_json)
        if isinstance(d, dict) and "critical" in d
    })
    signature = {
        "verified": a.signature_rc == 0 and bool(signed),
        "method": a.signature_method,
        "signed_digests": signed,
    }

    # --- signed SBOM attestation ------------------------------------------
    scanned = json.loads(Path(a.sbom).read_text())
    sbom_att = {"verified": False, "matches_scanned_sbom": False, "component_count": 0}
    if a.sbom_att_rc == 0:
        for st in statements(a.sbom_att):
            if "cyclonedx" not in st.get("predicateType", "").lower() or a.digest not in subject_digests(st):
                continue
            pred = st.get("predicate", {})
            sbom_att = {
                "verified": True,
                "matches_scanned_sbom": canonical(pred) == canonical(scanned) or components(pred) == components(scanned),
                "component_count": len(pred.get("components", [])),
            }

    # --- SLSA provenance --------------------------------------------------
    prov = {"verified": False}
    if a.prov_att_rc == 0:
        for st in statements(a.prov_att):
            pt = st.get("predicateType", "")
            if "slsa.dev/provenance" not in pt:
                continue
            pred = st.get("predicate", {})
            if pt.endswith("/v1"):
                builder = pred.get("runDetails", {}).get("builder", {}).get("id", "")
                wf = pred.get("buildDefinition", {}).get("externalParameters", {}).get("workflow", {})
            else:  # v0.2
                builder = pred.get("builder", {}).get("id", "")
                wf = {}
            prov = {
                "verified": True,
                "predicate_type": pt,
                "builder_id": builder,
                "subject_digests": subject_digests(st),
            }
            if wf:
                prov["workflow_path"] = wf.get("path", "")
                prov["workflow_ref"] = wf.get("ref", "")
                prov["workflow_repository"] = wf.get("repository", "")
            if a.digest in prov["subject_digests"]:
                break  # prefer the attestation bound to this exact digest

    # --- vulnerabilities (grype) -----------------------------------------
    vulns = {"scanned": False, "scanner": "grype", "matches": []}
    gp = Path(a.grype)
    if gp.exists() and gp.read_text().strip():
        g = json.loads(gp.read_text())
        seen = set()
        for m in g.get("matches", []):
            v, art = m.get("vulnerability", {}), m.get("artifact", {})
            key = (v.get("id"), art.get("name"), art.get("version"))
            if key in seen:
                continue
            seen.add(key)
            fix = v.get("fix", {})
            vulns["matches"].append({
                "id": v.get("id"),
                "severity": v.get("severity", "Unknown"),
                "package": art.get("name"),
                "version": art.get("version"),
                "type": art.get("type"),
                "fix": ", ".join(fix.get("versions", [])) or "none",
                "fix_state": fix.get("state", "unknown"),
            })
        vulns["scanned"] = True
        vulns["db_built"] = g.get("descriptor", {}).get("db", {}).get("built") or \
            g.get("descriptor", {}).get("db", {}).get("status", {}).get("built")

    doc = {
        "image": {"reference": a.image_ref, "digest": a.digest},
        "signature": signature,
        "sbom_attestation": sbom_att,
        "provenance": prov,
        "vulnerabilities": vulns,
    }
    Path(a.out).write_text(json.dumps(doc, indent=2) + "\n")

    sev = {}
    for m in vulns["matches"]:
        sev[m["severity"]] = sev.get(m["severity"], 0) + 1
    print(f"policy input -> {a.out}")
    print(f"  signature verified : {signature['verified']} {signed}")
    print(f"  sbom attestation   : {sbom_att}")
    print(f"  provenance         : verified={prov.get('verified')} builder={prov.get('builder_id')}")
    print(f"  vulnerabilities    : {sev or 'none'}")


if __name__ == "__main__":
    main()
