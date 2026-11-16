# Public contracts

See docs/INTEGRATION.md, docs/bootstrap.schema.json and docs/openapi.json.

New refresh API (development): UniversitySso/Sso::refresh(Session): BootstrapContext.
Opt-in only. Existing public methods remain compatible. Refresh credentials stay
encrypted in server session storage; no credentials are exposed through the DTO,
facade, registry events or browser examples. See docs/UPGRADING.md for failure
semantics and concurrency requirements.

TokenValidator::validateRefreshedIdToken(jwt, jwks, issuer, client, subject,
originalNonce): array verifies signed refreshed identity tokens, including optional
nonce matching and unchanged subject. AccessTokenValidator remains unchanged.

Facade aliases: UniversitySso, UniversityIdentity. Explicit classes live under
UniversitySso/Facades (use PHP namespace separators).

Lifecycle event: UniversitySso/Events/SessionLifecycle. Operations: registered,
local_logout, provider_logout, backchannel_logout, refreshed, refresh_failed.
Identity payload is allowlisted and contains no bearer/refresh/ID credential.
