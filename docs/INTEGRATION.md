# Integration contract (development; not stable release)

Provisional Composer name: university-sso/laravel-university-sso.
Namespace: UniversitySso. MIT. PHP 8.4+, Laravel 12/13, no Livewire dependency.
The vendor name is not a claim of Packagist ownership.

## Composer path integration

In the independent Laravel consumer's composer.json:

```json
{
  "repositories": [{"type":"path","url":"../laravel-university-sso"}],
  "require": {"university-sso/laravel-university-sso":"dev-main"}
}
```

Provider UniversitySso\SsoServiceProvider is discovered automatically.
Configuration key: university-sso. Required issuer, client_id, redirect_uri,
broker_url; client_secret for confidential clients. Scopes default to ['openid'].
Consumers requiring an optional broker audience scope MUST set scopes to
['openid', 'broker-api'] (or their provider's configured scope).
allowed_hosts optionally restricts every SDK endpoint to listed hostnames;
otherwise trusted discovery can supply cross-origin HTTPS endpoints.
post_logout_redirect_uri must be registered exactly with the provider.

## Public APIs

- Sso::authorizationUrl(Session): string
- Sso::callback(Session, string state, string code): BootstrapContext
- Sso::bootstrap(string accessToken, ?string issuer = null, ?string subject = null): BootstrapContext
- Sso::status(string accessToken): array
- Sso::context(?Session = null): BootstrapContext
- Sso::logout(Session): void (local only)
- Sso::logoutUrl(Session): string (RP logout URL and local session destruction)
- BackchannelLogout::handle(string logoutToken): void

Facade UniversitySso\Facades\Sso delegates to Sso.
Both Sso and BootstrapContext expose person(), activeContext(), roles(),
permissions(), applications(), universityId(). BootstrapContext additionally exposes
can(string permission), toArray(), id, epoch and authorizationVersion.
person() is the minimal user summary, not a private personnel record.

Contracts: UniversitySso\Contracts\IdentityContext and
UniversitySso\Contracts\BrokerClient. BrokerClient resolves to Sso.
AccessTokenValidator is a separate interface bound to TokenValidator:

```php
$claims = app(UniversitySso\AccessTokenValidator::class)->validateAccessToken(
    $jwt, $jwks, $issuer, $brokerAudience, $allowedClientIds, 'Bearer'
);
```

The access method verifies RS256 signature, issuer, audience, required nonempty
subject, allowed azp, exp, iat/nbf and payload token type. It never requires nonce.
'Bearer' matches Keycloak's access-token typ claim; generic providers may configure
a different expected value explicitly. Do not use the ID-token validate method
to authorize APIs. Broker still owns revocation and resource authorization.

## Broker HTTP contract

GET /api/v1/me/bootstrap uses Authorization: Bearer ACCESS_TOKEN.

```json
{"authenticated":true,"identity":{"issuer":"https://id.example.invalid","subject":"synthetic-subject"},"user":{"university_id":"person-demo","type":"guest","status":"active","full_name":"Synthetic User"},"application":{"client_id":"demo","allowed":true,"roles":["reader"],"permissions":["documents.read"]},"active_context":null,"applications":[],"security":{"session_epoch":1,"authorization_version":2}}
```

identity is optional for legacy brokers, but when returned MUST match the validated
ID-token issuer and subject. Enable require_identity_binding=true to require it
during callback. Broker must derive that identity from its verified access token.
No email-based account linking occurs.

GET /api/v1/session/status uses the same access token:

```json
{"active":true,"university_id":"person-demo","session_epoch":1,"authorization_version":2}
```

Strict types are required. Changed epoch/version, disabled status, identity
mismatch or 401 invalidates the session and returns 401. A remote 403 returns 403.
Network errors, upstream 5xx and malformed responses return 503 fail closed while
preserving the local session for recovery. Positive status is never cached.
GET transport retries once; authorization-code POST is not retried.

The broker MUST validate API access-token audience and authorized client itself.
ID tokens are not API credentials. SDK allowlists person summary fields and keeps
roles, permissions, active context and applications. Broker must filter context
and catalog content before sending it. No HR payload is requested or persisted.

## Middleware and sessions

Apply web then university.session-valid (aliases university.auth and sso),
then university.permission:documents.read
or university.role:reader. These expose request attribute sso.context.
Resource-state authorization remains the application's job.
Context/facade reads are snapshots and do not independently recheck revocation;
use them only behind university.auth for protected operations.

Session identity and context are plain arrays, compatible with Laravel JSON session
serialization. Require a server-side session driver, secure host-only cookies,
HttpOnly, SameSite=Lax and route session blocking for concurrent callbacks.
Do not use the cookie session driver. Separate local apps need separate cookie
names, even on localhost where cookies are not isolated by port.

Back-channel route is consumer-owned: POST logout_token, invoke handle and return
200; invalid tokens return 400, upstream outage 503. Exempt only this exact route
from CSRF, rate limit it and restrict body size. No SDK routes are auto-installed.
Use shared durable cache with atomic locks. Markers are locked during update;
logout_retention (default 86400 seconds) must exceed maximum local session lifetime.
Duplicate logout delivery is idempotent. The central status check remains authority.

No refresh-token persistence/renewal or automatic local User provisioning is supplied.

Permission/role middleware MUST follow university.session-valid on the same request.
Running permission middleware alone returns 401 even if a context snapshot exists
in the session. DTO can() is only a UI hint; it does not refresh authorization.
Sso::hasPermission(string permission, ?callable resourcePolicy = null, ?Session = null)
performs a fresh authoritative status check and invokes the policy with
BootstrapContext only after the permission matches. Use a resource policy for
resource-sensitive decisions; the SDK cannot infer document workflow rules.

## Context and registry lifecycle extension

UniversityIdentity is an additional auto-discovered facade alias; the explicit
class is UniversitySso/Facades/UniversityIdentity (PHP namespace separators).

Apply university.session-valid before university.context. With no argument,
university.context requires a nonempty active_context.context_id. With an argument
(e.g. university.context:workspace-demo), it requires that exact active context.
It never switches contexts or grants access to an arbitrary requested context;
context activation remains a broker-authorized operation.

Consumers can listen for UniversitySso/Events/SessionLifecycle to integrate
their durable session registry. operation is registered, local_logout,
provider_logout or backchannel_logout. identity contains only issuer, client_id,
subject, sid and applicable hashed session_reference, university_id,
session_epoch, authorization_version and expires_at. No token, secret or raw local
session ID is emitted. Treat registry storage as personal/security data.

Register a Laravel event listener that performs the consumer's authenticated,
idempotent registry operation. No broker-private route or protocol is assumed.
Listener failure during registration prevents the new local identity from being
stored. Local logout always destroys the session, including when a listener fails.
Backchannel markers remain authoritative even if a listener fails; delivery may
retry, so consumers must make listeners idempotent. These are integration hooks,
not proof of a production registry implementation.
