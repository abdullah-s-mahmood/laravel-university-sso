# Architecture

The consumer owns its routes, Laravel user model, server session and resource
policies. The provider owns credentials, authentication, SSO and token issuance.
The broker owns institutional identity, scoped authorization and durable
revocation. The package neither administers the provider nor imports broker code.

Login: discovery -> random state/nonce/verifier in local session -> browser
authorization code with S256 challenge -> one-use callback transaction -> code
exchange -> trusted-library signature validation and explicit OIDC claim checks
-> one broker bootstrap -> rotate local session ID and store plain-array context.

Protected request: local session -> backchannel marker check -> authoritative
broker status -> compare identity/epoch/authorization version -> expose request
context -> permission/role guard -> consumer resource policy. Broker unavailability
fails closed with 503 and preserves the session for retry.

Backchannel logout verifies a provider-signed event and writes a monotonic marker
under an atomic cache lock. It does not attempt deleting another host's cookie.
Local logout destroys only the current consumer session; RP logout additionally
returns the provider's registered end-session URL.

AccessTokenValidator is independent of Laravel session state. Broker applications
may reuse it for signature/issuer/API-audience/client/type validation, then apply
their own durable revocation and authorization policy. It accepts caller-supplied
JWKS; retrieval/caching belongs to the broker caller.

No database migrations, UI framework, identity-provider admin credentials,
personnel models or private institution configuration are part of this library.
