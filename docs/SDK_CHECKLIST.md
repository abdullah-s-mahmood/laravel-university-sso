# Mandatory library checklist audit

No stable release is declared. Implemented code and actual-provider evidence
are separate. Hosted runs 43781772392 and 43782693712 establish scoped baselines;
43820813588 adds successful refresh and PHP 8.5 evidence.

| Requirement | Current evidence / remaining acceptance |
| --- | --- |
| Generic config, Composer MIT, provider/discovery/PKCE | Actual confidential separate-host web and public native code flows passed |
| Trusted cryptographic verification | firebase/php-jwt; strict RS256/claims; reusable access contract; independent review still required |
| DTO surface / single bootstrap | Implemented; identity/client/version-bound session snapshot; new bootstrap only after authentication or refresh |
| UniversityIdentity facade | Implemented explicit facade and auto-discovered alias |
| auth/permission/context/session-valid | Implemented and tested; context/permission guards require fresh session middleware |
| Resource policy hooks | hasPermission checks authoritative state and optional resource policy |
| 401/403/503 / revocation | Fake-broker regressions pass; production policies remain external |
| RP logout / signed backchannel | Actual provider delivery passed run 43782693712; duplicate/out-of-order unit tests pass |
| Session registry | Token-free lifecycle integration hooks; actual fake-consumer listener delivery passed for refresh; production registry adapter remains consumer-owned |
| Refresh rotation | Implemented opt-in, encrypted credentials, atomic one-use marker, same-identity and epoch/version checks; actual provider refresh/native replay passed run 43820813588 |
| JWKS rotation | Fresh fetch + narrowly typed refresh signal; caller owns bounded cache; regression tests cover signature/unknown-kid distinction |
| Independent consumer | Composer locks, actual standalone Laravel consumer in hosted tests; controller/routes/Blade/env examples now included |
| Matrix/static/style | Laravel 12/13 on PHP 8.4 validated; PHP 8.5 jobs passed run 43820813588 |
| Security/license/SBOM | MIT and permissive dependency options checked; Gitleaks source scan clean; hosted secret/dependency/license/SBOM jobs passed; container scan failed six HIGH findings (see report) |
| Documentation | English/Arabic, architecture/security/contracts, changelog, upgrade guide and environment/examples supplied |
| SemVer/tags/Packagist | Deferred until all mandatory acceptance and owner review; vendor ownership unverified |

No institution-specific domain logic, personnel data, IdP administrator credentials
or production infrastructure configuration belongs in the package.
