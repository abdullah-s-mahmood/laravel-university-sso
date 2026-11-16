# Laravel University SSO

Generic MIT Laravel SDK for OIDC authorization code + S256 PKCE and a separate
identity/context broker. PHP 8.4+, Laravel 12/13. No Livewire dependency.

## Local integration

Add a Composer path repository pointing to this directory and require
`university-sso/laravel-university-sso:dev-main`. Auto-discovery registers
`UniversitySso\SsoServiceProvider`. Publish config with
`php artisan vendor:publish --tag=university-sso-config`.

Configure SSO_ISSUER, SSO_CLIENT_ID, SSO_CLIENT_SECRET (confidential clients),
SSO_REDIRECT_URI and SSO_BROKER_URL. All endpoints require HTTPS. Register an
exact redirect URI with the provider; use RS256 signing. Configure scopes as
['openid', 'broker-api'] when your broker audience requires that optional scope.
The Composer vendor name is provisional; this is a development snapshot.

Consumer routes (under Laravel's web middleware):

```php
use UniversitySso\Sso;
use Illuminate\Http\Request;
Route::get('/login', fn (Request $request, Sso $sso) => redirect()->away($sso->authorizationUrl($request->session())));
Route::get('/callback', function (Illuminate\Http\Request $request, Sso $sso) {
    $sso->callback($request->session(), (string) $request->query('state'), (string) $request->query('code'));
    return redirect('/account');
});
Route::get('/account', fn (Illuminate\Http\Request $request) =>
    ['id' => $request->attributes->get('sso.context')->id])->middleware('sso');
Route::post('/logout', function (Request $request, Sso $sso) {
    $sso->logout($request->session());
    return redirect('/');
});
```

Catch ProtocolException in the application's exception handler and show a generic
login error without logging tokens. The SDK does not create a local User or set
Laravel Auth; map verified issuer/subject explicitly if needed, never by email.

The facade is `UniversitySso\Facades\Sso`. DTO permissions use
`$context->can('documents.read')`; this is a UI snapshot hint. For sensitive decisions, use Sso::hasPermission
with a resource-policy callback to recheck broker state. Apply
university.session-valid before university.permission or university.role.

See [integration contract](docs/INTEGRATION.md), [security](SECURITY.md),
[Arabic guide](README.ar.md), and [status](IMPLEMENTATION_STATUS.md).

## Development

`composer install && composer check && composer audit`.
Independent Composer consumer: `cd examples/consumer && composer install && php smoke.php`.
CI covers Laravel 12/Testbench 10 and Laravel 13/Testbench 11 with PHP 8.4.

Real-provider harness (with fake Broker): [instructions](tests/Integration/README.md).
Run php tools/sbom.php for a CycloneDX inventory of locked dependencies.

## Refresh, examples and development installation

Refresh stays disabled for existing consumers. See [upgrade guide](docs/UPGRADING.md)
before setting SSO_REFRESH_ENABLED=true: rotating provider policy, server-side
JSON sessions, shared atomic cache and route session blocking are required.
The API is Sso::refresh($request->session()): BootstrapContext. Resource decisions
still require authoritative state and consumer policy.

Copy [controller/routes/Blade examples](examples/laravel/) into an independent
Laravel app and adapt route names. [Environment example](.env.example) contains
no credentials. Never place tokens in frontend storage or application URLs.

Until a reviewed release and Packagist ownership exist, a Composer VCS repository
can point to https://github.com/abdullah-s-mahmood/laravel-university-sso and require
university-sso/laravel-university-sso at a reviewed dev-main commit. Keep the consumer
lockfile. No stable release has been published. See [changelog](CHANGELOG.md)
and [mandatory checklist](docs/SDK_CHECKLIST.md).
