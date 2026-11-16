# Implementation status

Development snapshots only; no stable tag or comprehensive release acceptance.

## Accepted hosted provider baselines

- Run 43781772392, head 765a7e2: four jobs passed; three browser tests passed
  in 5.8 seconds. Confidential clients on separate hosts proved PKCE/SSO,
  cookie isolation and local logout isolation; redirect/missing-PKCE rejection
  and a separate native public-client code exchange also passed.
- Run 43782693712, head f4aa4cf: four jobs and all four browser tests passed,
  adding actual RP/global logout and provider-signed backchannel delivery.
  https://github.com/abdullah-s-mahmood/laravel-university-sso/actions/runs/43782693712
- PR 3 merged as 7aeff84; PR 4 merged as 1a58b7d after hosted green checks,
  adding the narrowly typed JWKS refresh signal without duplicate validation.

These fixtures use a FAKE BROKER that verifies real provider access tokens.
They do not establish production Broker/Gate/Persons/resource-policy acceptance.

## Current branch feat/sdk-refresh-rotation

Based on public main 1a58b7d. Implements opt-in rotating refresh with encrypted
server-side credentials, one-use replay fingerprints, proactive expiry handling,
same-identity and unchanged-epoch/version checks, renewed ID-token validation and
local session ID rotation. Preserves original session iat for backchannel checks.
Registry events add refreshed/refresh_failed and previous hashed session reference.
No public AccessTokenValidator API change; existing consumers keep refresh disabled.

Hosted run 43820813588 at ea8c201 passed all six SDK jobs: locked installation,
Laravel 12/13 on PHP 8.4/8.5, and Keycloak. All five browser tests passed in 9.1s,
including two consecutive confidential SDK refreshes, registry hook delivery and
native provider rejection of a retired refresh token:
https://github.com/abdullah-s-mahmood/laravel-university-sso/actions/runs/43820813588

Local verification: Laravel 13 / PHP 8.4: 35 tests, 112 assertions, Pint and
PHPStan level 5 pass. Laravel 12 / PHP 8.4 also passes the final 35 tests / 112 assertions.
Composer validation/audit and dependency license check pass. Gitleaks 8.30.1
scanned the source snapshot with redaction and found no leaks.
Local PHP 8.5 test attempt could not start: DOM/mbstring/XMLWriter extensions
are unavailable. Hosted PHP 8.5 matrix jobs installed these extensions and passed.
Security run 43820813493 passed secrets and dependency/license/SBOM checks but
FAILED the enforced container scan with six HIGH findings in the official
Keycloak 26.8.2 fixture image. See docs/CONTAINER_SECURITY_FINDINGS.md.
No scan suppression, severity downgrade, ignore-unfixed or waiver was introduced.

Remaining before stable: container finding remediation and re-scan, independent
security review of lifecycle/refresh, release/upgrade acceptance and
publication/versioning verification. Publication is already authorized by the task; no additional approval is inferred. No stable tag or Packagist
ownership claim. Parent controls PR publication and merges; main is protected.


## Additional lifecycle hardening — local verification 2026-11-17

45 tests / 144 assertions passed on PHP 8.4 / Laravel 13, with Pint and PHPStan
passing. Added ID-token profile and nbf separation, bounded Broker-context expiry
renewal, client-scoped backchannel replay keys and persistence failure handling.
These changes require fresh hosted matrix/Keycloak execution; earlier hosted
runs do not cover this revision. Existing container findings remain unresolved.
