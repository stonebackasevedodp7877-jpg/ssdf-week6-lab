# Task 1 - Pipeline Inspection Findings (PO.5.1)

**Workflow inspected:** `deploy.yml` (the Week 5 `ci_hardened.yml`, copied to `reference/deploy.yml`)
**Refactored workflow:** `hardened_pipeline.yml`

The Week 5 pipeline closed the obvious Week 5 gaps (SAST, secret scanning, dependency audit, SBOM archive, gated deploy). Reviewed against the Week 6 supply-chain threat model, it still trusts mutable inputs and cannot prove what it shipped.

| # | Finding in `deploy.yml` | Risk | SSDF | Fix in `hardened_pipeline.yml` |
|---:|---|---|---|---|
| 1 | Top-level `permissions: contents: read` only; no explicit read-all baseline, and no per-job scoping for the signing/push scopes Week 6 needs. | Adding signing later tends to widen the global token. | PO.5.1 | `permissions: read-all` at top level; only `release` gets `packages: write`, `id-token: write`, `attestations: write`. |
| 2 | Actions referenced by mutable tags: `actions/checkout@v4`, `actions/setup-python@v5`, `gitleaks/gitleaks-action@v2`, `actions/upload-artifact@v4`. | A moved or compromised tag runs attacker code with the job token (e.g. the 2025 `tj-actions/changed-files` tag compromise). | PO.5.1, PS.1.1 | All 24 `uses:` pinned to 40-character commit SHAs with the version as a comment; Dependabot `github-actions` keeps pins current. |
| 3 | `GITHUB_TOKEN` passed as env to a third-party action (gitleaks) in the same job that installs packages. | Token exposure to third-party code. | PO.5.1 | Gate jobs are read-only; the token cannot push or sign there. |
| 4 | Scanners installed from PyPI at runtime with no hash check; no runner egress control. | Toolchain substitution. | PO.5.1 | Scanner versions pinned; grype/conftest binaries verified by sha256; `step-security/harden-runner` audits egress. |
| 5 | No artifact is built or signed; the deploy job only echoes. Nothing binds the deployed bits to the reviewed source. | Unverifiable release; tampering between build and deploy is undetectable. | PS.2.1 | Image pushed and deployed **by digest**; keyless cosign signature via ephemeral GitHub OIDC token (no stored key). |
| 6 | SBOM is generated from `requirements.txt`, not from the shipped artifact, and is unsigned. | OS packages and the base image are missing; SBOM can be swapped. | PS.3.1 | syft SBOM of the pushed container, signed with `cosign attest --type cyclonedx`. |
| 7 | No build provenance. | Consumers cannot tell which builder/workflow/commit produced the artifact. | PS.2.1, PO.5.1 | SLSA v1 provenance via `actions/attest-build-provenance`, verified with `gh attestation verify --signer-workflow`. |
| 8 | Deploy gate is job ordering only; no machine-checked release criteria. | A skipped or misconfigured check still ships. | PW.5.1, PS.2.1 | `verify` job runs conftest on `attestation.rego`: signature, SBOM attestation, authorized builder, workflow/branch, zero Critical/High. |
| 9 | Base image and Python wheels resolved at build time by tag/version only. | Non-hermetic, non-reproducible build. | PO.5.1, PW.4.1 | Base image resolved to a digest before build; `pip install --require-hashes --only-binary=:all:`. |
| 10 | No continuous re-scan of the shipped artifact and no automated update PRs. | New CVEs in shipped components go unnoticed. | RV.1.1, RV.2.1 | grype scans the SBOM every run; remediation report; Dependabot/Renovate PRs re-run the pipeline. |
