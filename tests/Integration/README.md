# Real Keycloak integration harness with fake Broker

Run from package root: tests/Integration/run.sh.
Requires Docker daemon, PHP 8.4 + Composer, Node 24, Python 3, OpenSSL and curl.
Uses pinned Keycloak 26.8.2, browser-based login and two confidential clients on one.localhost / two.localhost with independent Laravel
application processes loading an SDK copy installed through Composer.
No Resource Owner Password Credentials grant is used or enabled.

The generated realm, test user password, CA key and sessions live in an ephemeral
temporary directory. Runtime cleanup removes the container and processes.
Ports 8080, 8443, 3000, 3001, 3002, 3443, 8000, 8001 and 8002 must be free.
Do not run concurrently with an infrastructure stack using these ports.

The browser accepts the ephemeral TLS fixture certificate. PHP verifies TLS using
that certificate as its explicit development CA; the SDK never disables TLS checks.

Playwright verifies:
- First consumer authorization code login requests S256 PKCE, state and nonce.
- Second consumer reaches account via the existing IdP session, no credential form.
- Local logout denies consumer one, preserves consumer two and the IdP SSO session.
- Keycloak rejects an unregistered redirect URI.
- Both web and native clients reject missing PKCE.
- Distinct host-only cookies are not received by the other consumer.

Fake Broker validates actual Keycloak access tokens using the SDK access validator,
then returns synthetic bootstrap/status data. It does not test production Broker
Persons, permission policies, gate UI, MFA enrollment or durable revocation.
Those require separate integration acceptance.

CI defines a real Keycloak job. Until the job or local harness actually passes,
these scenarios remain unverified; mocked tests do not count as P1 acceptance.

To adapt to an existing infrastructure realm, start consumer.php twice with
CONSUMER_RUNTIME, CONSUMER_APP_KEY, CONSUMER_CLIENT_ID, CONSUMER_CLIENT_SECRET,
CONSUMER_COOKIE, CONSUMER_ORIGIN and OIDC_ISSUER. Register exact callback paths
/auth/callback. Supply provider-specific scopes through consumer configuration,
and configure OIDC_AUDIENCE / OIDC_ALLOWED_PARTIES for the fake broker. The stock
runner deliberately provisions its own generic realm and never modifies existing
infrastructure.

Failed hosted runs upload sanitized-keycloak-diagnostics (three-day retention).
It includes sanitized service logs and query-free browser response/failure events.
Realm imports, keys, session files, token responses and network traces are excluded.
The native public client performs a separate browser authorization-code + S256
exchange without a client secret, using its own HTTPS callback listener.

The extended lifecycle test adds RP-initiated logout and a real signed provider
backchannel delivery to consumer two. It deliberately keeps the fake Broker's
status active: rejection must come from the provider-signed logout marker.
The Linux test container uses host networking with Keycloak bound to loopback,
so the confidential clients can receive direct HTTP loopback backchannels on
ports 8000/8001. Browser/SDK endpoints retain verified HTTPS. This is a development
fixture topology, not a production transport recommendation.
