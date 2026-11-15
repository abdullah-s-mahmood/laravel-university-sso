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
exact redirect URI with the provider; use RS256 signing.

Consumer routes (under Laravel's web middleware):

```php
use UniversitySso\Sso;
Route::get('/login', fn (Sso $sso) => redirect()->away($sso->authorizationUrl(session())));
Route::get('/callback', function (Illuminate\Http\Request $request, Sso $sso) {
    $sso->callback($request->session(), (string) $request->query('state'), (string) $request->query('code'));
    return redirect('/account');
});
Route::get('/account', fn (Illuminate\Http\Request $request) =>
    ['id' => $request->attributes->get('sso.context')->id])->middleware('sso');
Route::post('/logout', function (Sso $sso) {
    $sso->logout(session());
    return redirect('/');
});
```

Catch ProtocolException in the application's exception handler and show a generic
login error without logging tokens. The SDK does not create a local User or set
Laravel Auth; map verified issuer/subject explicitly if needed, never by email.

The facade is `UniversitySso\Facades\Sso`. DTO permissions use
`$context->can('documents.read')`; resource authorization remains the application's job.

See [integration contract](docs/INTEGRATION.md), [security](SECURITY.md),
[Arabic guide](README.ar.md), and [status](IMPLEMENTATION_STATUS.md).

## Development

`composer install && composer check && composer audit`.
Independent Composer consumer: `cd examples/consumer && composer install && php smoke.php`.
CI covers Laravel 12/Testbench 10 and Laravel 13/Testbench 11 with PHP 8.4.
