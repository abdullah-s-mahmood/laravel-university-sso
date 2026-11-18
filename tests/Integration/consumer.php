<?php

declare(strict_types=1);
// Runnable independent application; executed against examples/consumer/vendor.
require __DIR__.'/../../examples/consumer/vendor/autoload.php';
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use UniversitySso\BackchannelLogout;
use UniversitySso\Events\SessionLifecycle;
use UniversitySso\ProtocolException;
use UniversitySso\Sso;
use UniversitySso\SsoServiceProvider;
use UniversitySso\UpstreamException;

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
        // Provider-to-server route has no web/session/CSRF middleware.
        Route::post('/auth/backchannel', function (Request $request) {
            $token = $request->input('logout_token');
            if (! is_string($token) || $token === '' || strlen($token) > 16384) {
                return response('', 400);
            }
            try {
                app(BackchannelLogout::class)->handle($token);
            } catch (UpstreamException) {
                return response('', 503);
            } catch (ProtocolException) {
                return response('', 400);
            }

            return response('', 200);
        });

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
            Route::get('/refresh-form', fn () => response('<form method="POST" action="/refresh">'.csrf_field().'<button>Refresh session</button></form>'));
            Route::post('/refresh', function (Request $request, Sso $sso) {
                $sso->refresh($request->session());

                return redirect('/account');
            })->block();
            Route::get('/lifecycle-operations', function () {
                $path = getenv('CONSUMER_RUNTIME').'/lifecycle.jsonl';
                $lines = is_file($path) ? file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];

                return response()->json(array_map(static fn ($line) => json_decode($line, true, 512, JSON_THROW_ON_ERROR)['operation'], $lines));
            })->middleware('university.session-valid');
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
    'university-sso.refresh.enabled' => true,
]);
// Test consumer registry adapter: persist only the already-token-free lifecycle payload.
Event::listen(SessionLifecycle::class, function ($event) use ($runtime): void {
    file_put_contents($runtime.'/lifecycle.jsonl', json_encode(['operation' => $event->operation, 'identity' => $event->identity], JSON_THROW_ON_ERROR)."\n", FILE_APPEND | LOCK_EX);
});
$app->handleRequest(Request::capture());
