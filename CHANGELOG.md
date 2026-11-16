# Changelog

## Unreleased — development branch

- Add opt-in rotating refresh credentials, encrypted in server-side JSON sessions.
- Add fresh-ID validation, identity/session binding and replay suppression.
- Rotate local session IDs on refresh; emit token-free refreshed/refresh_failed events.
- Recheck durable broker epoch/version and backchannel markers during refresh.
- Add actual-provider SDK refresh and native replay scenarios (CI pending).
- Extend PHP matrix to 8.5 and add secret/license/SBOM/container scan workflows.
- Add controller, routes, Blade and environment examples plus upgrade instructions.

## Accepted development baselines (not stable versions)

- c31509a / merged main 1a58b7d: typed JWKS refresh hint and preserved crypto causes.
- f4aa4cf / merged main 7aeff84: context guard, UniversityIdentity facade and
  registry lifecycle hooks. Hosted run 43782693712 passed all four browser tests,
  including actual provider RP logout and signed backchannel delivery.
- 765a7e2: hosted run 43781772392 passed three real-provider browser tests.

No stable tag, Packagist publication or comprehensive acceptance is claimed.
