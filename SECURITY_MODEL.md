# Security model

See SECURITY.md for reporting and operational requirements.

Trust boundaries: browser input is untrusted; provider discovery is trusted only
when fetched using a configured HTTPS issuer with exact issuer match. JWKS are
accepted from that discovery document and restricted to RS256 RSA signature keys.
Configuration is operator-owned. allowed_hosts can restrict discovery, token,
JWKS and broker endpoint hostnames. Network egress policy remains important.

Callback rejects wrong/expired/reused state, validates nonce and JWT signature,
issuer, audience, authorized party and registered token times. at_hash is checked
when present. No password grant, implicit flow, insecure TLS or token query-string
transport is used. Configure exact redirect URIs at the provider.

Broker identity binding compares bootstrap identity with the validated ID token
when present. Set require_identity_binding for strict deployments. Broker itself
must verify the access token and derive the returned identity; SDK cannot infer
trusted identity from an unverified access-token payload.

Authentication failure -> 401, authorization denial -> 403, upstream unavailable
or malformed -> 503. Epoch/version changes reject stale permissions. Fresh service
permission checks also invoke optional caller resource policy after validating
broker state. DTO snapshots are not authority for sensitive operations.

JSON session data is arrays only. Use server-side sessions, per-application
host-only cookies, secure flags, CSRF on consumer mutations, and session blocking.
The package does not configure production proxy trust or frontend error pages.

Backchannel requires issuer/audience/signature/iat/jti/events and nonempty sid or
sub, rejects nonce, supports optional exp for legacy providers and validates exp
if present. Shared-cache locks prevent marker regressions on out-of-order events.
Cache compromise, wrong session lifetime or permissive broker authorization are
outside what JWT cryptography can fix.

No certification, penetration-test result or stable security acceptance is claimed.
