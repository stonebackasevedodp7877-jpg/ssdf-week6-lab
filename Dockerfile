# Hermetic, least-privilege container build (PO.5.1, PW.4.1, PS.3.1)
#
# BASE_IMAGE must be passed as a digest-pinned reference, e.g.
#   --build-arg BASE_IMAGE=python:3.11-slim@sha256:<digest>
# run_lab.sh and hardened_pipeline.yml resolve the digest before building,
# so the exact base layers are recorded in the SLSA provenance.
ARG BASE_IMAGE=python:3.11-slim

# ---- build stage: resolve dependencies from a hash-locked manifest ---------
FROM ${BASE_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /build
COPY app/requirements.txt .
# --require-hashes: every wheel must match a pinned sha256
# --only-binary   : no sdists, so no arbitrary setup.py code runs at build time
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes --only-binary=:all: -r requirements.txt \
 && /opt/venv/bin/pip uninstall -y wheel setuptools pip

# ---- runtime stage ---------------------------------------------------------
FROM ${BASE_IMAGE}
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# Remove package-management tooling not needed at runtime (smaller SBOM and
# attack surface). No network is needed for this step.
RUN --network=none python -m pip uninstall -y pip setuptools wheel 2>/dev/null || true
WORKDIR /app
COPY --from=build /opt/venv /opt/venv
COPY app/main.py .
# Numeric UID/GID (nobody:nogroup) so runtime policies can verify non-root.
USER 65534:65534
EXPOSE 8080
CMD ["python", "main.py"]
