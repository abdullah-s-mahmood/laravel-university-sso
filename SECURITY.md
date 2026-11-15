# Security model and reporting

Do not publish secrets or personal data in issues. Report suspected issues privately
to the repository maintainer through GitHub private vulnerability reporting
when enabled; never include tokens or personal data in a public issue.

JWT signatures and registered time checks use firebase/php-jwt. The SDK additionally
pins RS256, issuer, client audience, azp, subject and transaction nonce. Discovery
and JWKS are fetched anew, allowing key rotation. Configuration and discovery are
trusted operator-controlled inputs; permit egress only to your IdP and broker.
HTTPS peer verification remains enabled; redirects are rejected.

Use Redis/database server-side sessions, host-only Secure HttpOnly SameSite=Lax
cookies, session blocking on login/callback routes, and shared durable cache.
Do not use the cookie session driver: access tokens are held in the server session.
Local session lifetime must not exceed logout_retention. Access tokens must never
appear in logs, browser URLs or client storage. Restrict access to session stores.

Every protected request checks authoritative broker state. This cannot retract
an operation already in progress when revocation commits. Broker owns durable
epochs, API audience validation and transaction-level authorization.
Backchannel is an accelerator. Cache markers use atomic locks; all application
workers must share the same durable cache and support its locking API.
DTO can() and facade context getters expose snapshots only. Sensitive decisions
require authoritative middleware or hasPermission() with a resource policy.

No real provider interoperability, penetration test or production review has been
performed. Initial source review authorized public repository creation. Final security
acceptance and a successful actual-provider run are still required for a stable release.
No-exp logout tokens are accepted for older-provider compatibility under a
five-minute iat window; when exp is present it is strictly checked.
