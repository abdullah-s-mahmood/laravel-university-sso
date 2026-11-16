<?php

declare(strict_types=1);
// Runnable independent application; executed against examples/consumer/vendor.
require __DIR__.'/../../examples/consumer/vendor/autoload.php';
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use UniversitySso\ProtocolException;
use UniversitySso\Sso;
use UniversitySso\SsoServiceProvider;

$runtime = getenv('CONSUMER_RUNTIME');
if (! $runtime) {
    throw new RuntimeException('CONSUMER_RUNTIME required');
}
$app = Application::configure(basePath: $runtime)
    ->withProviders([SsoServiceProvider::class])
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->render(function (ProtocolException $exception) {
            error_log('SDK protocol exception: '.get_class($exception).': '.$exception->getMessage());

            return response()->json(['message' => 'SSO failed.'], 401);
        });
    })
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->trustProxies(at: ['127.0.0.1', '::1']);
    })
    ->withRouting(using: function () {
        Route::middleware('web')->group(function () {
            Route::get('/', fn () => response('<a href="/login">Login</a>'));
            Route::get('/login', fn (Request $request, Sso $sso) => redirect()->away($sso->authorizationUrl($request->session())));
            Route::get('/auth/callback', function (Request $request, Sso $sso) {
                $sso->callback($request->session(), (string) $request->query('state'), (string) $request->query('code'));

                return redirect('/account');
            });
            Route::get('/account', fn (Request $request) => response()->json($request->attributes->get('sso.context')->toArray()))->middleware('university.auth');
            Route::get('/observed-cookies', fn (Request $request) => response()->json(array_map(static fn (string $cookie): string => trim(explode('=', $cookie, 2)[0]), explode(';', (string) $request->server('HTTP_COOKIE', '')))))->middleware('university.auth');
            Route::get('/logout-form', fn () => response('<form method="POST" action="/logout">'.csrf_field().'<button>Local logout</button></form>'));
            Route::post('/logout', function (Request $request, Sso $sso) {
                $sso->logout($request->session());

                return redirect('/');
            });
            Route::get('/global-logout-form', fn () => response('<form method="POST" action="/global-logout">'.csrf_field().'<button>Global logout</button></form>'));
            Route::post('/global-logout', fn (Request $request, Sso $sso) => redirect()->away($sso->logoutUrl($request->session())));
        });
    })->create();
$app->make(Kernel::class)->bootstrap();
config([
    'app.key' => getenv('CONSUMER_APP_KEY'),
    'app.debug' => false,
    'session.driver' => 'file', 'session.files' => $runtime.'/storage/framework/sessions',
    'session.cookie' => getenv('CONSUMER_COOKIE'), 'session.secure' => true,
    'session.http_only' => true, 'session.same_site' => 'lax', 'session.domain' => null,
    'session.serialization' => 'json',
    'cache.default' => 'file', 'cache.stores.file' => ['driver' => 'file', 'path' => $runtime.'/storage/framework/cache'],
    'university-sso.issuer' => getenv('OIDC_ISSUER'),
    'university-sso.client_id' => getenv('CONSUMER_CLIENT_ID'),
    'university-sso.client_secret' => getenv('CONSUMER_CLIENT_SECRET') ?: null,
    'university-sso.redirect_uri' => getenv('CONSUMER_ORIGIN').'/auth/callback',
    'university-sso.post_logout_redirect_uri' => getenv('CONSUMER_ORIGIN').'/',
    'university-sso.broker_url' => 'https://localhost:3443',
    'university-sso.require_identity_binding' => true,
]);
$app->handleRequest(Request::capture());
