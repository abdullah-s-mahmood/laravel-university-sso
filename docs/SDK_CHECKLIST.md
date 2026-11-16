# Mandatory library checklist audit

Baseline evidence: hosted run 43781772392 at 765a7e2, all four jobs passed.
No stable release is declared. This audit distinguishes implemented code from
actual provider interoperability.

| Requirement | Baseline state / remaining work |
| --- | --- |
| Generic config, Composer MIT, provider/discovery/PKCE | Implemented; actual confidential web and public native provider tests passed |
| Trusted cryptographic JWT validation | firebase/php-jwt; RS256/claims; reusable access contract; independent security review still required |
| DTO surface, bootstrap once | Implemented; per-session arrays isolated by application and identity; no cross-user positive context cache |
| UniversityIdentity facade name | Sso facade exists; compatibility alias still needed |
| auth/permission/session-valid middleware | Implemented and tested; resource hook performs fresh status check |
| context middleware | Missing in baseline; implement freshness plus explicit active context restriction |
| 401/403/503 and revocation | Tested with fake broker; production broker policies remain external |
| Global logout/backchannel | Code and signed unit fixtures exist; actual-provider delivery not yet tested |
| Session registry integration | No lifecycle integration hook in baseline |
| Refresh-token rotation | Missing; do not claim implemented |
| JWKS signing-key rotation | Fresh JWKS retrieval exists; dedicated regression evidence still needed |
| Independent installation | Composer lock + Laravel HTTP example and hosted smoke pass |
| Matrix/static/style/dependency audit | Laravel 12/13 on PHP 8.4 pass; broader supported PHP versions not yet tested |
| Security/license/SBOM | MIT, dependency inventory and audit exist; automated secret scan/container scan and uploaded SBOM still need CI completion |
| Documentation/examples | English/Arabic and architecture/security/contracts exist; changelog, upgrade guide, env/controller/Blade examples missing |
| SemVer/tags/releases | Deferred until all mandatory library acceptance passes; Packagist ownership unverified |

This package never owns personnel logic, production broker migrations, IdP
administrator credentials, institution configuration or production Gate UI.
