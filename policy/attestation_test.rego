# Unit tests for attestation.rego  ->  conftest verify --policy policy
package main

import rego.v1

digest := concat("", ["sha256:", concat("", [c | some _ in numbers.range(1, 64); c := "a"])])

other_digest := concat("", ["sha256:", concat("", [c | some _ in numbers.range(1, 64); c := "b"])])

base := {
	"image": {"reference": "localhost:5001/ssdf-app:v6.0", "digest": digest},
	"signature": {"verified": true, "method": "key", "signed_digests": [digest]},
	"sbom_attestation": {"verified": true, "matches_scanned_sbom": true, "component_count": 120},
	"provenance": {
		"verified": true,
		"predicate_type": "https://slsa.dev/provenance/v1",
		"builder_id": "https://ssdf-week6-lab.local/builders/run_lab.sh@v1",
		"subject_digests": [digest],
	},
	"vulnerabilities": {"scanned": true, "scanner": "grype", "matches": []},
}

ci_base := object.union(base, {"provenance": {
	"verified": true,
	"predicate_type": "https://slsa.dev/provenance/v1",
	"builder_id": "https://github.com/actions/runner/github-hosted",
	"subject_digests": [digest],
	"workflow_path": ".github/workflows/hardened_pipeline.yml",
	"workflow_ref": "refs/heads/main",
}})

critical := {"id": "CVE-2024-9999", "severity": "Critical", "package": "openssl", "version": "3.0.0", "fix": "3.0.15", "fix_state": "fixed"}

with_vuln(v) := object.union(base, {"vulnerabilities": {"scanned": true, "scanner": "grype", "matches": [v]}})

test_compliant_local_build_passes if {
	count(deny) == 0 with input as base
}

test_compliant_ci_build_passes if {
	count(deny) == 0 with input as ci_base
}

test_unsigned_image_denied if {
	deny["signature: cosign signature verification did not pass"] with input as object.union(base, {"signature": {"verified": false, "signed_digests": [digest]}})
}

test_signature_for_other_digest_denied if {
	some msg in deny with input as object.union(base, {"signature": {"verified": true, "signed_digests": [other_digest]}})
	startswith(msg, "signature: signed digest")
}

test_mutable_tag_denied if {
	some msg in deny with input as object.union(base, {"image": {"reference": "ssdf-app:latest", "digest": "latest"}})
	startswith(msg, "image:")
}

test_unauthorized_builder_denied if {
	inp := object.union(base, {"provenance": object.union(base.provenance, {"builder_id": "https://attacker.example/runner"})})
	some msg in deny with input as inp
	contains(msg, "not an authorized CI builder")
}

test_missing_provenance_denied if {
	deny["provenance: no verified SLSA provenance attestation"] with input as object.remove(base, ["provenance"])
}

test_ci_build_from_feature_branch_denied if {
	inp := object.union(ci_base, {"provenance": object.union(ci_base.provenance, {"workflow_ref": "refs/heads/feature-x"})})
	some msg in deny with input as inp
	startswith(msg, "provenance: build ref")
}

test_ci_build_from_other_workflow_denied if {
	inp := object.union(ci_base, {"provenance": object.union(ci_base.provenance, {"workflow_path": ".github/workflows/evil.yml"})})
	some msg in deny with input as inp
	startswith(msg, "provenance: workflow")
}

test_critical_cve_denied if {
	some msg in deny with input as with_vuln(critical)
	contains(msg, "CVE-2024-9999")
}

test_high_cve_denied if {
	some msg in deny with input as with_vuln(object.union(critical, {"severity": "High"}))
	contains(msg, "High CVE-2024-9999")
}

test_medium_cve_only_warns if {
	inp := with_vuln(object.union(critical, {"severity": "Medium"}))
	count(deny) == 0 with input as inp
	count(warn) == 1 with input as inp
}

test_missing_scan_denied if {
	deny["vulnerabilities: no scan result; zero Critical/High cannot be proven"] with input as object.remove(base, ["vulnerabilities"])
}

test_documented_exception_waives_cve if {
	exc := [{
		"id": "CVE-2024-9999", "package": "openssl",
		"justification": "Not reachable: TLS is terminated at the load balancer, app never links libssl.",
		"expires": "2099-01-01T00:00:00Z",
	}]
	count(deny) == 0 with input as with_vuln(critical) with data.vulnerability_exceptions as exc
}

test_expired_exception_does_not_waive if {
	exc := [{
		"id": "CVE-2024-9999", "package": "openssl",
		"justification": "Not reachable: TLS is terminated at the load balancer, app never links libssl.",
		"expires": "2020-01-01T00:00:00Z",
	}]
	some msg in deny with input as with_vuln(critical) with data.vulnerability_exceptions as exc
	contains(msg, "CVE-2024-9999")
}

test_sbom_mismatch_denied if {
	deny["sbom: SBOM inside the signed attestation differs from the SBOM that was scanned"] with input as object.union(base, {"sbom_attestation": {"verified": true, "matches_scanned_sbom": false}})
}
