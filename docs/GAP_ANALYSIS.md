# SDK gap analysis

Initial directory: absent. Public library scope supersedes the platform
monorepo topology. This package does not own broker migrations, Gate/Livewire UI,
Keycloak infrastructure or personnel/HR modules.

Implemented: package/provider/config, OIDC and broker clients, ID/access/logout
validation, DTO/contracts/facade, JSON sessions, revocation and permission guards,
local/RP/backchannel logout, independent consumer, Testbench matrix, static/style
checks, audits, dependency locks and CycloneDX inventory, actual-provider CI
harness with confidential host-separated consumers and a fake Broker.

Scoped actual-provider SSO/local/global logout/backchannel acceptance passed
hosted baselines. Current branch adds refresh rotation and broader security/PHP
matrix jobs, with provider refresh and security jobs pending CI. Production
Broker integration, independent security review and stable release acceptance
remain open. No real university accounts or private realm data is included.
