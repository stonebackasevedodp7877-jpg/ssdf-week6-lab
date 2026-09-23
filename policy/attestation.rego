# NIST SP 800-218 SSDF v1.1 - deployment gate for PS.2.1 / PS.3.1 / PW.5.1 / RV.2.1
#
#   conftest test policy_input.json --policy policy --data policy/exceptions.json
#
# policy_input.json is produced by scripts/build_policy_input.py from the
# OUTPUT OF VERIFICATION COMMANDS (cosign verify, cosign verify-attestation /
# gh attestation verify) and the grype scan of the SBOM. Unverified,
# self-reported metadata is never accepted as evidence.
package main

import rego.v1

# ---------------------------------------------------------------------------
# Trust configuration
# ---------------------------------------------------------------------------

# SLSA builder IDs allowed to produce release artifacts.
#   github-hosted : actions/attest-build-provenance in hardened_pipeline.yml
#   run_lab.sh    : local lab builder (LAB ONLY - delete before production use)
github_hosted_builder := "https://github.com/actions/runner/github-hosted"

authorized_builders := {
	github_hosted_builder,
	"https://ssdf-week6-lab.local/builders/run_lab.sh@v1",
}

# A GitHub-hosted build must also come from the release workflow on main.
authorized_workflow_path := ".github/workflows/hardened_pipeline.yml"

authorized_workflow_ref := "refs/heads/main"

accepted_provenance_types := {
	"https://slsa.dev/provenance/v1",
	"https://slsa.dev/provenance/v0.2",
}

blocking_severities := {"Critical", "High"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

image_digest := object.get(input, ["image", "digest"], "")

valid_digest(d) if regex.match(`^sha256:[a-f0-9]{64}$`, d)

# A Critical/High finding may only be waived by a documented, unexpired
# risk-acceptance record naming the exact CVE and package (RV.2.1).
excepted(v) if {
	some e in data.vulnerability_exceptions
	e.id == v.id
	e.package == v.package
	count(trim_space(e.justification)) >= 20
	time.parse_rfc3339_ns(e.expires) > time.now_ns()
}

blocking_vulns contains v if {
	some v in input.vulnerabilities.matches
	v.severity in blocking_severities
	not excepted(v)
}

# ---------------------------------------------------------------------------
# 1. Immutable image identity
# ---------------------------------------------------------------------------

deny contains "image: digest missing or not sha256; only immutable references are evaluated" if {
	not valid_digest(image_digest)
}

# ---------------------------------------------------------------------------
# 2. Cryptographic signature verification (PS.2.1)
# ---------------------------------------------------------------------------

deny contains "signature: cosign signature verification did not pass" if {
	not input.signature.verified == true
}

deny contains "signature: cosign reported no signed digest" if {
	count(object.get(input, ["signature", "signed_digests"], [])) == 0
}

deny contains msg if {
	some d in input.signature.signed_digests
	d != image_digest
	msg := sprintf("signature: signed digest %v does not match image digest %v", [d, image_digest])
}

# ---------------------------------------------------------------------------
# 3. Signed SBOM attestation (PS.3.1)
# ---------------------------------------------------------------------------

deny contains "sbom: signed CycloneDX SBOM attestation did not verify" if {
	not input.sbom_attestation.verified == true
}

deny contains "sbom: SBOM inside the signed attestation differs from the SBOM that was scanned" if {
	input.sbom_attestation.verified == true
	not input.sbom_attestation.matches_scanned_sbom == true
}

# ---------------------------------------------------------------------------
# 4. SLSA provenance from an authorized CI builder (PS.2.1, PO.5.1)
# ---------------------------------------------------------------------------

deny contains "provenance: no verified SLSA provenance attestation" if {
	not input.provenance.verified == true
}

deny contains msg if {
	input.provenance.verified == true
	not input.provenance.predicate_type in accepted_provenance_types
	msg := sprintf("provenance: unsupported predicate type %v", [input.provenance.predicate_type])
}

deny contains msg if {
	input.provenance.verified == true
	not input.provenance.builder_id in authorized_builders
	msg := sprintf("provenance: builder %v is not an authorized CI builder", [input.provenance.builder_id])
}

deny contains "provenance: provenance subject does not reference the image digest" if {
	input.provenance.verified == true
	not image_digest in object.get(input, ["provenance", "subject_digests"], [])
}

deny contains msg if {
	input.provenance.builder_id == github_hosted_builder
	wf := object.get(input, ["provenance", "workflow_path"], "")
	wf != authorized_workflow_path
	msg := sprintf("provenance: workflow %v is not the authorized release workflow", [wf])
}

deny contains msg if {
	input.provenance.builder_id == github_hosted_builder
	ref := object.get(input, ["provenance", "workflow_ref"], "")
	ref != authorized_workflow_ref
	msg := sprintf("provenance: build ref %v is not %v", [ref, authorized_workflow_ref])
}

# ---------------------------------------------------------------------------
# 5. Zero Critical / High vulnerabilities in the image SBOM (PW.5.1, RV.2.1)
# ---------------------------------------------------------------------------

deny contains "vulnerabilities: no scan result; zero Critical/High cannot be proven" if {
	not input.vulnerabilities.scanned == true
}

deny contains msg if {
	some v in blocking_vulns
	msg := sprintf("vulnerabilities: %v %v in %v %v (fixed in: %v)", [v.severity, v.id, v.package, v.version, v.fix])
}

# ---------------------------------------------------------------------------
# Non-blocking visibility
# ---------------------------------------------------------------------------

warn contains msg if {
	n := count([v | some v in input.vulnerabilities.matches; v.severity == "Medium"])
	n > 0
	msg := sprintf("vulnerabilities: %v Medium finding(s) tracked in the remediation backlog", [n])
}

warn contains msg if {
	n := count([v |
		some v in input.vulnerabilities.matches
		v.severity in blocking_severities
		excepted(v)
	])
	n > 0
	msg := sprintf("vulnerabilities: %v Critical/High finding(s) waived by documented exception", [n])
}
