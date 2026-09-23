#!/usr/bin/env python3
"""Generate a SLSA v1 provenance *predicate* for the locally built image.

The predicate is signed and bound to the image digest by:
    cosign attest --type slsaprovenance1 --predicate provenance.predicate.json <image@digest>
Only the verified attestation (cosign verify-attestation) is used by the policy.
"""
import argparse
import datetime as dt
import hashlib
import json
import platform
import subprocess
import uuid
from pathlib import Path

BUILDER_ID = "https://ssdf-week6-lab.local/builders/run_lab.sh@v1"
BUILD_TYPE = "https://ssdf-week6-lab.local/buildtypes/dockerfile@v1"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cmd(*args: str) -> str:
    try:
        return subprocess.run(args, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--image", required=True, help="image reference that was built")
    p.add_argument("--base-image", required=True, help="digest-pinned base image")
    p.add_argument("--started-on", required=True, help="RFC 3339 build start time")
    p.add_argument("--out", required=True)
    a = p.parse_args()

    deps = []
    commit = cmd("git", "rev-parse", "HEAD")
    remote = cmd("git", "config", "--get", "remote.origin.url")
    if commit:
        deps.append({"uri": f"git+{remote or 'local'}", "digest": {"gitCommit": commit}})
    if "@sha256:" in a.base_image:
        name, digest = a.base_image.split("@sha256:")
        deps.append({"uri": f"pkg:docker/{name}", "digest": {"sha256": digest}})
    for f in ("Dockerfile", "app/requirements.txt", "app/main.py"):
        path = Path(f)
        if path.exists():
            deps.append({"uri": f"file:{f}", "digest": {"sha256": sha256_file(path)}})

    predicate = {
        "buildDefinition": {
            "buildType": BUILD_TYPE,
            "externalParameters": {
                "dockerfile": "Dockerfile",
                "context": ".",
                "image": a.image,
                "buildArgs": {"BASE_IMAGE": a.base_image},
            },
            "internalParameters": {
                "hostPlatform": f"{platform.system()}-{platform.machine()}",
                "dockerVersion": cmd("docker", "version", "--format", "{{.Server.Version}}"),
            },
            "resolvedDependencies": deps,
        },
        "runDetails": {
            "builder": {"id": BUILDER_ID},
            "metadata": {
                "invocationId": str(uuid.uuid4()),
                "startedOn": a.started_on,
                "finishedOn": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        },
    }
    Path(a.out).write_text(json.dumps(predicate, indent=2) + "\n")
    print(f"wrote {a.out} (builder.id={BUILDER_ID}, {len(deps)} resolved dependencies)")


if __name__ == "__main__":
    main()
