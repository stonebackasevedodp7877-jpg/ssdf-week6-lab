# SBOM Vulnerability Remediation Report

- **Image:** `localhost:5001/ssdf-app@sha256:0e56bbf023f29a45a61cc40e5414854d090bdce49569f4e86e38928e3a9218c3`
- **SBOM:** `sbom.cyclonedx.json` (2765 components, CycloneDX 1.7)
- **Scanner:** grype 0.119.0 (DB built 2026-09-23T06:31:39Z)
- **Generated:** 2026-09-23 22:52 UTC
- **SSDF practices:** RV.1.1 (identify vulnerabilities continuously), RV.2.1 (assess, prioritize, remediate)

## Severity summary

| Critical | High | Medium | Low | Negligible/Unknown |
|---:|---:|---:|---:|---:|
| 0 | 50 | 58 | 9 | 45 |

## Python dependencies

| Package | Direct | Installed | Latest on PyPI | Status | Known vulnerabilities | Action |
|---|:---:|---|---|---|---|---|
| click | yes | 8.3.3 | 8.5.0 | OBSOLETE | none | Bump to 8.5.0 via Dependabot/Renovate PR |
| blinker | yes | 1.9.0 | 1.9.0 | current | none | - |
| flask | yes | 3.1.3 | 3.1.3 | current | none | - |
| itsdangerous | yes | 2.2.0 | 2.2.0 | current | none | - |
| jinja2 | yes | 3.1.6 | 3.1.6 | current | none | - |
| markupsafe | yes | 3.0.3 | 3.0.3 | current | none | - |
| packaging | transitive | 26.3 | 26.3 | current | none | - |
| werkzeug | yes | 3.1.8 | 3.1.8 | current | none | - |

## Critical / High findings (all package types)

| Severity | ID | Package | Type | Installed | Fixed in | Fix state | SLA |
|---|---|---|---|---|---|---|---|
| High | CVE-2026-76642 | bsdutils | deb | 1:2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78409 | bsdutils | deb | 1:2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78408 | bsdutils | deb | 1:2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78410 | bsdutils | deb | 1:2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-54369 | libacl1 | deb | 2.3.2-2+b1 | - | wont-fix | 30 days |
| High | CVE-2026-54370 | libacl1 | deb | 2.3.2-2+b1 | - | wont-fix | 30 days |
| High | CVE-2026-76642 | libblkid1 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78409 | libblkid1 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78408 | libblkid1 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78410 | libblkid1 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-19499 | libc-bin | deb | 2.41-12+deb13u4 | - | wont-fix | 30 days |
| High | CVE-2026-5435 | libc-bin | deb | 2.41-12+deb13u4 | - | wont-fix | 30 days |
| High | CVE-2026-19499 | libc6 | deb | 2.41-12+deb13u4 | - | wont-fix | 30 days |
| High | CVE-2026-5435 | libc6 | deb | 2.41-12+deb13u4 | - | wont-fix | 30 days |
| High | CVE-2026-76642 | liblastlog2-2 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78409 | liblastlog2-2 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78408 | liblastlog2-2 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78410 | liblastlog2-2 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-76642 | libmount1 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78409 | libmount1 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78408 | libmount1 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78410 | libmount1 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2025-69720 | libncursesw6 | deb | 6.5+20250216-2 | - | wont-fix | 30 days |
| High | CVE-2026-76642 | libsmartcols1 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78409 | libsmartcols1 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78408 | libsmartcols1 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78410 | libsmartcols1 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2025-69720 | libtinfo6 | deb | 6.5+20250216-2 | - | wont-fix | 30 days |
| High | CVE-2026-76642 | libuuid1 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78409 | libuuid1 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78408 | libuuid1 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78410 | libuuid1 | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-76642 | login | deb | 1:4.16.0-2+really2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78409 | login | deb | 1:4.16.0-2+really2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78408 | login | deb | 1:4.16.0-2+really2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78410 | login | deb | 1:4.16.0-2+really2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-76642 | mount | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78409 | mount | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78408 | mount | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78410 | mount | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2025-69720 | ncurses-base | deb | 6.5+20250216-2 | - | wont-fix | 30 days |
| High | CVE-2025-69720 | ncurses-bin | deb | 6.5+20250216-2 | - | wont-fix | 30 days |
| High | CVE-2026-82560 | perl-base | deb | 5.40.1-6+deb13u1 | - | not-fixed | 30 days |
| High | CVE-2026-9538 | perl-base | deb | 5.40.1-6+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-82049 | python | binary | 3.11.16 | 3.14.0b1 | fixed | 30 days |
| High | CVE-2026-76642 | util-linux | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78409 | util-linux | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78408 | util-linux | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-78410 | util-linux | deb | 2.41.5-0+deb13u1 | - | wont-fix | 30 days |
| High | CVE-2026-85091 | zlib1g | deb | 1:1.3.dfsg+really1.3.1-1+b1 | - | not-fixed | 30 days |

Fix state `fixed`: rebuild on the patched base image / bump the package. Fix state `not-fixed` or `wont-fix`: no upstream patch; either switch base image or record a time-boxed risk acceptance in `policy/exceptions.json` (id, package, justification, expires). The deployment gate blocks until one of these is done.

## Automated remediation

1 obsolete Python package(s) detected. Automated pull requests are configured in `.github/dependabot.yml` (pip, docker, github-actions ecosystems; security updates grouped) and `renovate.json` (digest pinning, vulnerability alerts). Each bump PR re-runs `hardened_pipeline.yml`, so a new SBOM, signature, provenance and policy decision are produced before merge.

