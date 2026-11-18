# Development API upgrades

The library has no stable release yet. Pin a reviewed public commit and keep your
consumer composer.lock; do not silently track changing main in production.

Existing authorizationUrl, callback, bootstrap, status, logout, facade getters,
DTOs and middleware aliases remain available. Pass Request::session(), not the
session() manager, to methods typed as the Session contract.

Refresh is disabled by default. Old Gate consumers do not need route or session
changes. To enable it, require a rotating provider refresh policy, shared atomic
cache, APP_KEY, server-side sessions and session-blocked consumer routes.
Set SSO_REFRESH_ENABLED=true (or config university-sso.refresh.enabled).
Existing sessions without encrypted refresh credentials must authenticate again.

Sso::refresh(Session): BootstrapContext explicitly rotates credentials. The
university.session-valid guard also refreshes proactively when expires_in is known
and the access token is within refresh.before_expiry seconds (default 30).
Returned ID tokens are checked for signature, issuer, audience, subject and, when
present, original nonce/auth_time/sid and access-token hash. Providers may omit
the refreshed ID token. New refresh credentials are mandatory and must differ.

Refresh performs one new bootstrap and will not accept a changed identity, epoch
or authorization version. It cannot revive a centrally revoked session. It checks
backchannel markers before and after the exchange; original session iat is retained.

A pre-grant service outage returns a typed 503 failure and preserves an unconsumed
credential. Once a refresh grant is claimed, any ambiguous or invalid result ends
the local session: automatic retry of a potentially spent credential is forbidden.
The token POST is never retried. The replay cache stores only hashed fingerprints.
Set refresh.replay_retention to cover maximum local session lifetime; use a cache
with atomic add and make provider rotation authoritative. Session-block all routes
that can refresh, including protected routes when proactive refresh is enabled.

Registry listeners now receive refreshed and refresh_failed. refreshed includes
previous_session_reference so adapters can retire the old hashed local reference.
Neither event exposes tokens. Make registry listeners idempotent. Out-of-order
backchannel markers remain monotonic and duplicate jti delivery is suppressed.

AuthenticationException::shouldRefreshJwks() is a bounded cache hint only. Refetch
at most once with a shared cooldown on signature/unknown-key failures, then fully
revalidate. Claim/expiry/malformed failures must never cause broad refetches.
Do not cache positive revocation decisions in the JWKS cache.
