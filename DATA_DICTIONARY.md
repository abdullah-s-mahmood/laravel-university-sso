# Public data and stored state

BootstrapContext implements Contracts/IdentityContext. Methods expose universityId,
person, activeContext, roles, permissions and applications. id, epoch and
authorizationVersion are readonly properties. can() reads a snapshot only.
person contains allowlisted university_id, type, status and full_name. Broker
filters catalog and active-context content. DTO construction uses strict scalar
checks; no names or email addresses are account-linking keys.

Session key sso.transaction: state, nonce, verifier, time. Consumed before token
exchange even when callback fails. One outstanding transaction per session.
Session key sso.identity: issuer, sub, sid (optional), iat, access_token, id_token,
context (plain array). ID token is retained for RP logout hint. Refresh tokens are discarded by default; when enabled, only Laravel-encrypted
refresh ciphertext is retained, with original nonce/auth_time and optional access
expiry timestamp for proactive renewal. Server session lifetime must fit logout marker retention.

Broker bootstrap: authenticated bool, identity issuer/subject (optional unless
configured required), user university_id, application client_id/allowed,
roles/permissions string lists, security integer session_epoch and
authorization_version. Context/catalog are optional arrays.

Broker status: active bool, university_id string, session_epoch and
authorization_version integers. Fields are compared strictly on each protected
request; malformed responses mean service unavailable, not anonymous identity.

Cache keys are SHA-256-derived from issuer plus sid/sub/jti, never plaintext
subjects. Logout markers contain the event's iat. Marker lifetime defaults to
86400 seconds and must exceed consumer session lifetime; replay lifetime 600.

Cache key sso:refresh:{SHA256(issuer, client, refresh-token)} stores a boolean
one-use marker, never the token. Registry refreshed events carry new and previous
hashed session references. Refresh cannot replace a stale session with a context
at a different security epoch or authorization version.
