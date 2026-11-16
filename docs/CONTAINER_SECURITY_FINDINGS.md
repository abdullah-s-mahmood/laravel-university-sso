# Container security findings — unresolved release gate

The SDK's enforced container scan reported six HIGH findings in its third-party
Keycloak integration fixture. This is not a Composer dependency audit failure.
No production exploitability determination or security waiver is asserted.

Evidence:
- SDK runtime checks: run 43820813588, head ea8c201, all six jobs passed and
  all five actual-provider browser tests passed (9.1 seconds).
- Security run: 43820813493. Secrets and dependencies jobs passed;
  keycloak-image failed as configured (exit-code 1, HIGH/CRITICAL, unfixed included).
- Artifact: keycloak-container-security, ID 14204890403.
- Report SHA-256: 19551e4dc199d7388a570edfc6a2d09e9c38be4d023b7332afac1c85b213c621.
- Image: quay.io/keycloak/keycloak:26.8.2.
- Digest: sha256:c68e286cacd87b942ac1939a0a1481461109d6acd3a57dc496969a319a76bbf0.
- Scanner: Trivy 0.76.2; scan timestamp 2026-11-16 07:01 UTC.

| Finding | Component / installed version | Scanner status / fixed version |
| --- | --- | --- |
| CVE-2026-91403 | java-21-openjdk-headless 1:21.0.13.0.9-1.2.el9 | will_not_fix; no fixed version in report |
| CVE-2026-119373 | sqlite-libs 3.34.1-11.el9_8 | affected; no fixed version in report |
| CVE-2026-119374 | sqlite-libs 3.34.1-11.el9_8 | affected; no fixed version in report |
| CVE-2026-119379 | sqlite-libs 3.34.1-11.el9_8 | affected; no fixed version in report |
| CVE-2026-119586 | sqlite-libs 3.34.1-11.el9_8 | affected; no fixed version in report |
| CVE-2026-102554 | com.google.guava:guava 33.6.0-jre | fixed in 33.7.2 |

These are scanner findings requiring upstream/vendor applicability review and
remediation. The SDK does not own the identity provider distribution. Do not
silently replace runtime jars, suppress findings or weaken the scan to get green.
Coordinate a supported provider image/runtime update, re-run both security and
browser suites, and obtain review before comprehensive stable acceptance.
The public library contains no institution deployment data or credentials.

Sources: the immutable workflow artifact and
https://github.com/abdullah-s-mahmood/laravel-university-sso/actions/runs/43820813493.
