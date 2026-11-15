# Implementation status

Development snapshot; no stable release or P1 acceptance declared.

P0 SDK foundation validated: independent MIT Composer package, PHP 8.4,
Laravel 12/13, Testbench, committed dependency locks, style/static/security CI,
English/Arabic docs. No Livewire dependency or institutional private data.

P1 implemented for review: authorization code + PKCE S256, state/nonce,
RS256 verification using firebase/php-jwt, issuer/audience/azp/time checks,
JSON-compatible server sessions, bootstrap DTO/facade/contracts, fresh permission
checks with resource policy hooks, authoritative session middleware, local and
RP logout, signed backchannel handling with locked idempotent markers.
Shared AccessTokenValidator interface supports broker API validation independently
of ID-token nonce checks.

Verified locally:
- Laravel 13/Testbench 11: 19 tests, 60 assertions pass.
- Laravel 12/Testbench 10: 19 tests, 60 assertions pass.
- Pint and PHPStan level 5 pass.
- Composer validation and audit pass; no advisories reported at execution.
- Independent Composer consumer smoke passes; independent Laravel HTTP consumer
  boots and denies unauthenticated access.
- Keycloak runner shell and JavaScript syntax checked.

Actual Keycloak browser acceptance is PENDING. First hosted run failed before
provider tests (runner OS/Playwright mismatch and DTO config coupling); corrections
are committed in abce302 and require the next hosted run. Local harness attempt stopped
because Docker daemon socket is unavailable. Hosted CI defines a pinned Keycloak
26.8.2 fixture, confidential clients on separate hosts, real PKCE login and
cross-client SSO, cookie isolation, local logout isolation, invalid redirect and
missing-PKCE rejection. These tests are authored, NOT claimed passed.
The fixture uses a FAKE BROKER that validates real provider access tokens.
Production Broker/Gate bootstrap and resource-policy acceptance remain separate.

Remaining: hosted Keycloak run and fixes, full security review, production Broker
integration, operational interoperability and release acceptance. Refresh-token
renewal is not implemented; expired tokens require a new authorization flow.

Publication: owner authorized public repository creation after source review;
origin configured by parent. Parent controls push after this local commit.
No stable tag until full acceptance. Composer vendor name is provisional and
does not assert Packagist ownership.
