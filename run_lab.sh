#!/usr/bin/env bash
# =============================================================================
# SSDF Week 6 lab runner - Tasks 2, 3 and 4 end to end, local workstation
#
#   build ssdf-app:v6.0 -> push to local registry -> syft CycloneDX SBOM
#   -> cosign sign / attach sbom / attest SBOM / attest SLSA provenance
#   -> cosign verify + extract payloads -> grype scan -> remediation report
#   -> conftest policy gate -> package [Student]_SSDF_Week6.zip
#
# Every command and its real output is appended to verification_log.txt.
# Works on macOS (bash 3.2, Docker Desktop) and Ubuntu 22.04 / WSL2.
#
# Usage:  ./run_lab.sh                      (defaults below)
#         STUDENT=ShuchenMeng REG_PORT=5001 ./run_lab.sh
# =============================================================================
set -uo pipefail

STUDENT="${STUDENT:-ShuchenMeng}"
REG_PORT="${REG_PORT:-5001}"            # 5000 is taken by AirPlay on macOS
REG="localhost:${REG_PORT}"
REPO_NAME="ssdf-app"
TAG="v6.0"
IMAGE_LOCAL="${REPO_NAME}:${TAG}"
IMAGE="${REG}/${REPO_NAME}:${TAG}"
BASE_IMAGE="${BASE_IMAGE:-python:3.11-slim}"
EV="evidence"
LOG="verification_log.txt"
SBOM="sbom.cyclonedx.json"

export COSIGN_PASSWORD="${COSIGN_PASSWORD:-}"      # lab-only key, empty password
export SYFT_REGISTRY_INSECURE_USE_HTTP=true        # local registry is plain HTTP
export GRYPE_REGISTRY_INSECURE_USE_HTTP=true

cd "$(dirname "$0")" || exit 1
mkdir -p "$EV"
: > "$LOG"

# ----------------------------------------------------------------- helpers ---
log()     { printf '%s\n' "$*" | tee -a "$LOG"; }
section() { log ""; log "=========================================================================="; log "$*"; log "=========================================================================="; }
run() {
  log "\$ $*"
  "$@" 2>&1 | tee -a "$LOG"
  local rc=${PIPESTATUS[0]}
  log "[exit code: ${rc}]"
  return "$rc"
}
# run a command, stdout -> file, stderr -> log; print a short preview of stdout
capture() {
  local out="$1"; shift
  log "\$ $* > ${out}"
  "$@" > "$out" 2> "${out}.stderr"
  local rc=$?
  tee -a "$LOG" < "${out}.stderr"
  rm -f "${out}.stderr"
  return "$rc"
}
die()  { log "FATAL: $*"; echo; echo ">>> 运行中止：$*（详见 ${LOG}）" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1"; }

# print predicateType / subject / key fields of verified attestations
summarize_attestations() {
  python3 - "$1" <<'PY'
import base64, json, sys
sys.path.insert(0, "scripts")
from build_policy_input import statements
for st in statements(sys.argv[1]):
    subj = [f"{s.get('name')}@sha256:{s['digest'].get('sha256','')[:16]}..." for s in st.get("subject", [])]
    pred = st.get("predicate", {})
    print(f"  predicateType : {st.get('predicateType')}")
    print(f"  subject       : {subj}")
    if "runDetails" in pred:
        print(f"  builder.id    : {pred['runDetails']['builder']['id']}")
        print(f"  buildType     : {pred['buildDefinition']['buildType']}")
        for d in pred["buildDefinition"].get("resolvedDependencies", []):
            print(f"  dependency    : {d['uri']} {d['digest']}")
    if "components" in pred:
        print(f"  CycloneDX     : specVersion {pred.get('specVersion')}, {len(pred['components'])} components")
PY
}

# =============================================================================
section "SSDF Week 6 - Verification Log | student: ${STUDENT}"
log "Date (UTC)     : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Host           : $(uname -srm)"
for t in docker cosign syft grype conftest python3 curl zip; do need "$t"; done
docker info >/dev/null 2>&1 || die "Docker daemon is not running"
log "docker         : $(docker version --format '{{.Server.Version}}')"
log "cosign         : $(cosign version 2>/dev/null | awk '/GitVersion/{print $2}')"
log "syft           : $(syft version 2>/dev/null | awk '/^Version/{print $2}')"
log "grype          : $(grype version 2>/dev/null | awk '/^Version/{print $2}')"
log "conftest       : $(conftest --version 2>/dev/null | tr '\n' ' ')"
log "python         : $(python3 --version 2>&1)"

# =============================================================================
section "TASK 2.0 - Local OCI registry (cosign stores signatures next to the image)"
if ! docker ps --format '{{.Names}}' | grep -qx ssdf-registry; then
  docker rm -f ssdf-registry >/dev/null 2>&1
  run docker run -d --name ssdf-registry -p "127.0.0.1:${REG_PORT}:5000" registry:3 \
    || run docker run -d --name ssdf-registry -p "127.0.0.1:${REG_PORT}:5000" registry:2 \
    || die "could not start local registry"
  sleep 3
fi
run curl -sf "http://${REG}/v2/" || die "registry ${REG} not reachable"

# =============================================================================
section "TASK 2.1 - Hermetic build of ${IMAGE_LOCAL} (digest-pinned base, hash-locked deps)"
run docker pull "$BASE_IMAGE" || die "cannot pull ${BASE_IMAGE}"
BASE_DIGEST="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$BASE_IMAGE" | head -1 | cut -d@ -f2)"
[ -n "$BASE_DIGEST" ] || die "cannot resolve base image digest"
BASE_PINNED="${BASE_IMAGE}@${BASE_DIGEST}"
log "Base image pinned to: ${BASE_PINNED}"

STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run docker build --provenance=false --sbom=false \
  --build-arg "BASE_IMAGE=${BASE_PINNED}" \
  -t "$IMAGE_LOCAL" -t "$IMAGE" . || die "docker build failed"
run docker image inspect --format 'User={{.Config.User}}  Cmd={{.Config.Cmd}}  Size={{.Size}}' "$IMAGE_LOCAL"
run docker push "$IMAGE" || die "docker push failed"

DIGEST="$(curl -sfI \
  -H 'Accept: application/vnd.oci.image.index.v1+json' \
  -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
  -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
  -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
  "http://${REG}/v2/${REPO_NAME}/manifests/${TAG}" | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}')"
case "$DIGEST" in sha256:*) ;; *) die "could not read image digest from registry";; esac
REF="${REG}/${REPO_NAME}@${DIGEST}"
log "Immutable image reference: ${REF}"

# =============================================================================
section "TASK 2.2 - Container-level CycloneDX SBOM (syft)"
run syft "registry:${REF}" -o "cyclonedx-json=${SBOM}" || die "syft failed"
run python3 - "$SBOM" <<'PY'
import collections, json, sys
b = json.load(open(sys.argv[1]))
assert b.get("bomFormat") == "CycloneDX", "not a CycloneDX document"
types = collections.Counter(c.get("purl", "?").split("/")[0] for c in b.get("components", []))
print(f"bomFormat={b['bomFormat']} specVersion={b['specVersion']} serialNumber={b.get('serialNumber')}")
print(f"metadata.component={b.get('metadata',{}).get('component',{}).get('name')}")
print(f"components={len(b['components'])} by purl type: {dict(types)}")
py = sorted(f"{c['name']}=={c['version']}" for c in b["components"] if c.get("purl","").startswith("pkg:pypi/"))
print("python packages:", ", ".join(py))
PY
[ $? -eq 0 ] || die "SBOM validation failed"

# =============================================================================
section "TASK 2.3 - Sign image, attach SBOM, sign SBOM attestation, sign SLSA provenance"
if [ ! -f cosign.key ]; then
  run cosign generate-key-pair || die "key generation failed"
fi
log "Public key (cosign.pub):"; tee -a "$LOG" < cosign.pub

run cosign sign --key cosign.key --allow-http-registry --yes "$REF" || die "cosign sign failed"

log ""
log "# Assignment command as written ('cosign attache sbom' is a typo for 'attach')."
log "# 'attach sbom' is deprecated in cosign and stores the SBOM UNSIGNED; the signed"
log "# SBOM used by the policy gate is the in-toto attestation created right after."
run cosign attach sbom --sbom "$SBOM" --type cyclonedx --allow-http-registry "$REF" \
  || log "(attach sbom not available in this cosign build - covered by 'cosign attest' below)"

run cosign attest --key cosign.key --type cyclonedx --predicate "$SBOM" \
  --allow-http-registry --yes "$REF" || die "cosign attest (SBOM) failed"

run python3 scripts/make_provenance.py --image "$IMAGE" --base-image "$BASE_PINNED" \
  --started-on "$STARTED" --out "${EV}/provenance.predicate.json" || die "provenance generation failed"
run cosign attest --key cosign.key --type slsaprovenance1 --predicate "${EV}/provenance.predicate.json" \
  --allow-http-registry --yes "$REF" || die "cosign attest (provenance) failed"

# =============================================================================
section "TASK 2.4 - Verify signatures and extract attached payloads"
capture "${EV}/cosign_verify.json" cosign verify --key cosign.pub --allow-http-registry "$REF"
SIG_RC=$?; log "[exit code: ${SIG_RC}]"
python3 - "${EV}/cosign_verify.json" <<'PY' | tee -a "$LOG"
import json, sys
for d in json.load(open(sys.argv[1])):
    c = d["critical"]
    print(f"  signed: {c['identity']['docker-reference']}  digest={c['image']['docker-manifest-digest']}  type={c['type']}")
PY

capture "${EV}/sbom_attestation.jsonl" cosign verify-attestation --key cosign.pub --type cyclonedx \
  --allow-http-registry "$REF"
SBOM_RC=$?; log "[exit code: ${SBOM_RC}]"
summarize_attestations "${EV}/sbom_attestation.jsonl" | tee -a "$LOG"
log "Extracting signed SBOM payload -> ${EV}/sbom_from_attestation.json"
python3 - "${EV}/sbom_attestation.jsonl" "$SBOM" "${EV}/sbom_from_attestation.json" <<'PY' | tee -a "$LOG"
import json, sys
sys.path.insert(0, "scripts")
from build_policy_input import statements, canonical
sts = [s for s in statements(sys.argv[1]) if "cyclonedx" in s.get("predicateType", "")]
pred = sts[-1]["predicate"]
json.dump(pred, open(sys.argv[3], "w"), indent=2)
same = canonical(pred) == canonical(json.load(open(sys.argv[2])))
print(f"  extracted {len(pred.get('components', []))} components; identical to {sys.argv[2]}: {same}")
PY

capture "${EV}/provenance_attestation.jsonl" cosign verify-attestation --key cosign.pub --type slsaprovenance1 \
  --allow-http-registry "$REF"
PROV_RC=$?; log "[exit code: ${PROV_RC}]"
summarize_attestations "${EV}/provenance_attestation.jsonl" | tee -a "$LOG"

log ""
log "# Download the (unsigned, deprecated) attached SBOM for comparison"
capture "${EV}/sbom_attached_download.json" cosign download sbom --allow-http-registry "$REF" \
  && log "  downloaded $(wc -c < "${EV}/sbom_attached_download.json" | tr -d ' ') bytes" \
  || log "  (no attached SBOM to download)"

log ""
log "# NEGATIVE TEST: verification with an untrusted key must FAIL"
[ -f "${EV}/untrusted.pub" ] || COSIGN_PASSWORD='' cosign generate-key-pair --output-key-prefix "${EV}/untrusted" >/dev/null 2>&1
capture "${EV}/negative_verify.json" cosign verify --key "${EV}/untrusted.pub" --allow-http-registry "$REF"
NEG_RC=$?; log "[exit code: ${NEG_RC}]"
if [ "$NEG_RC" -ne 0 ]; then log "RESULT: rejected as expected (signature not made by the trusted key)"; else log "RESULT: UNEXPECTED PASS"; fi
rm -f "${EV}/untrusted.key"

# =============================================================================
section "TASK 4.1 - Vulnerability scan of ${SBOM} (grype)"
run grype db status || true
run grype "sbom:${SBOM}" -o table -o "json=${EV}/grype_results.json"
[ -s "${EV}/grype_results.json" ] || die "grype produced no JSON report"

# =============================================================================
section "TASK 4.2 - Automated remediation report (obsolete / vulnerable dependencies)"
run python3 scripts/remediation_report.py --sbom "$SBOM" --grype "${EV}/grype_results.json" \
  --requirements app/requirements.txt --image "$REF" --out remediation_report.md
tee -a "$LOG" < remediation_report.md

# =============================================================================
section "TASK 3 - Policy-as-code gate (conftest + attestation.rego)"
run python3 scripts/build_policy_input.py \
  --image-ref "$IMAGE" --digest "$DIGEST" \
  --signature-json "${EV}/cosign_verify.json" --signature-rc "$SIG_RC" --signature-method key \
  --sbom "$SBOM" \
  --sbom-att "${EV}/sbom_attestation.jsonl" --sbom-att-rc "$SBOM_RC" \
  --prov-att "${EV}/provenance_attestation.jsonl" --prov-att-rc "$PROV_RC" \
  --grype "${EV}/grype_results.json" --out "${EV}/policy_input.json"

log ""
log "# Policy unit tests"
run conftest verify --policy policy --no-color

log ""
log "# Gate decision for ${REF}"
run conftest test "${EV}/policy_input.json" --policy policy --data policy/exceptions.json --no-color
POLICY_RC=$?

log ""
log "# NEGATIVE TEST: tampered metadata (unsigned, rogue builder, Critical CVE) must be DENIED"
run conftest test policy/fixtures/tampered_input.json --policy policy --data policy/exceptions.json --no-color
if [ $? -ne 0 ]; then log "RESULT: denied as expected"; else log "RESULT: UNEXPECTED PASS"; fi

# =============================================================================
section "SUMMARY"
ok() { if [ "$1" -eq 0 ]; then echo PASS; else echo FAIL; fi; }
log "Image                    : ${REF}"
log "Signature (cosign verify): $(ok "$SIG_RC")"
log "SBOM attestation         : $(ok "$SBOM_RC")"
log "SLSA provenance          : $(ok "$PROV_RC")"
log "Untrusted key rejected   : $([ "$NEG_RC" -ne 0 ] && echo PASS || echo FAIL)"
log "Policy gate (conftest)   : $(ok "$POLICY_RC")"
log "Completed (UTC)          : $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ================================================================ package ===
ZIP="${STUDENT}_SSDF_Week6.zip"
STAGE="$(mktemp -d)/${STUDENT}_SSDF_Week6"
mkdir -p "$STAGE/supporting/policy" "$STAGE/supporting/evidence" "$STAGE/supporting/.github"
cp .github/workflows/hardened_pipeline.yml "$STAGE/hardened_pipeline.yml"
cp "$SBOM" "$STAGE/"
cp policy/attestation.rego "$STAGE/attestation.rego"
cp "$LOG" "$STAGE/"
cp -R app Dockerfile .dockerignore run_lab.sh scripts pipeline_findings.md remediation_report.md \
      renovate.json cosign.pub reference "$STAGE/supporting/"
cp .github/dependabot.yml "$STAGE/supporting/.github/"
cp policy/attestation_test.rego policy/exceptions.json "$STAGE/supporting/policy/"
cp -R policy/fixtures "$STAGE/supporting/policy/"
cp "${EV}"/policy_input.json "${EV}"/grype_results.json "${EV}"/provenance.predicate.json \
   "${EV}"/sbom_from_attestation.json "$STAGE/supporting/evidence/" 2>/dev/null
find "$STAGE" -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null
rm -f "$ZIP"
( cd "$(dirname "$STAGE")" && zip -qr "$OLDPWD/$ZIP" "$(basename "$STAGE")" )
echo
echo "打包完成: $(pwd)/${ZIP}"
unzip -l "$ZIP"
if [ "$POLICY_RC" -ne 0 ]; then
  echo
  echo ">>> 策略门禁未通过（通常是基础镜像里有 High/Critical CVE）。"
  echo "    看 remediation_report.md 的 Critical/High 表：fix state 为 fixed 的，重新拉最新基础镜像再跑；"
  echo "    wont-fix/not-fixed 的，按 README 第 5 节处理，然后重跑 ./run_lab.sh。"
fi
