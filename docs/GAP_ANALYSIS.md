# SDK gap analysis

Initial directory: absent. Public library scope supersedes the platform
monorepo topology. This package does not own broker migrations, Gate/Livewire UI,
Keycloak infrastructure or personnel/HR modules.

Implemented: package/provider/config, OIDC and broker clients, ID/access/logout
validation, DTO/contracts/facade, JSON sessions, revocation and permission guards,
local/RP/backchannel logout, independent consumer, Testbench matrix, static/style
checks, audits, dependency locks and CycloneDX inventory, actual-provider CI
harness with confidential host-separated consumers and a fake Broker.

Pending acceptance: successful hosted Keycloak browser run, production Broker
integration, security review closure and release process. Refresh-token renewal
remains unimplemented. The caller must restart authorization after token expiry.
No live university identity, real account or private realm data is included.
