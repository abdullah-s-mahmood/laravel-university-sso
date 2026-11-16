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

Actual scoped provider evidence: hosted run 43781772392 succeeded at
765a7e2fc1063d051838f3d4abd25dbf02096265:
https://github.com/abdullah-s-mahmood/laravel-university-sso/actions/runs/43781772392
All four jobs passed (Laravel 12, Laravel 13, locked install, Keycloak).
Three browser tests passed in 5.8 seconds: confidential web clients on separate
hosts perform PKCE login and SSO, host-only cookies remain isolated, local logout
preserves the other app and provider SSO, unregistered redirects and missing PKCE
are rejected, and a public native client exchanges code with S256 without a secret.
The fixture uses a FAKE BROKER validating real provider access tokens.
This is not production Broker/Gate acceptance, nor evidence for actual provider
global logout, signed backchannel delivery, refresh rotation or registry integration.

Remaining: broader provider lifecycle coverage, refresh/rotation, registry hooks,
context middleware and checklist documentation, full security review, production Broker
integration, operational interoperability and release acceptance. Refresh-token
renewal is not implemented; expired tokens require a new authorization flow.

Publication: owner authorized public repository creation after source review;
origin configured by parent. Parent controls push after this local commit.
No stable tag until full acceptance. Composer vendor name is provisional and
does not assert Packagist ownership.

Feature branch feat/sdk-lifecycle-context extends the accepted baseline:
- university.context guard requires fresh session middleware and checks active context.
- UniversityIdentity facade alias and token-free SessionLifecycle registry hooks.
- Actual-provider RP/global logout and signed backchannel test authored; pending CI.
- Current local Laravel 13 verification: 22 tests, 67 assertions; Pint/PHPStan pass.
Refresh-token rotation remains pending and no stable tag is authorized.
