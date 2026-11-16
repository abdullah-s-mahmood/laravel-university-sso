<?php

declare(strict_types=1);

namespace UniversitySso\Tests;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Illuminate\Contracts\Cache\Lock;
use Illuminate\Http\Client\Factory;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;
use UniversitySso\AccessTokenValidator;
use UniversitySso\AuthenticationException;
use UniversitySso\AuthorizationException;
use UniversitySso\BackchannelLogout;
use UniversitySso\BootstrapContext;
use UniversitySso\Events\SessionLifecycle;
use UniversitySso\ProtocolException;
use UniversitySso\Sso;
use UniversitySso\SsoServiceProvider;
use UniversitySso\TokenValidator;
use UniversitySso\UpstreamException;

final class ProtocolTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoServiceProvider::class];
    }

    protected function setUp(): void
    {
        parent::setUp();
        config(['app.key' => 'base64:'.base64_encode(str_repeat('x', 32))]);
        config(['university-sso.issuer' => 'https://id.example.invalid', 'university-sso.client_id' => 'demo', 'university-sso.redirect_uri' => 'https://app.example.invalid/callback', 'university-sso.broker_url' => 'https://broker.example.invalid']);
        Http::preventStrayRequests();
    }

    private function signing(): array
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $pem);
        $rsa = openssl_pkey_get_details($key)['rsa'];
        $b64 = static fn (string $v) => rtrim(strtr(base64_encode($v), '+/', '-_'), '=');

        return [$pem, ['keys' => [['kty' => 'RSA', 'alg' => 'RS256', 'kid' => 'test', 'n' => $b64($rsa['n']), 'e' => $b64($rsa['e'])]]]];
    }

    private function claims(): array
    {
        return ['iss' => 'https://id.example.invalid', 'sub' => 'synthetic-subject', 'aud' => 'demo', 'iat' => time() - 1, 'exp' => time() + 120, 'nonce' => 'nonce'];
    }

    private function discovery(array $extra = []): array
    {
        return array_merge(['issuer' => 'https://id.example.invalid', 'authorization_endpoint' => 'https://id.example.invalid/auth', 'token_endpoint' => 'https://id.example.invalid/token', 'jwks_uri' => 'https://id.example.invalid/keys'], $extra);
    }

    public function test_signed_token_and_rejection_matrix(): void
    {
        [$pem,$keys] = $this->signing();
        $validator = new TokenValidator;
        self::assertSame('synthetic-subject', $validator->validate(JWT::encode($this->claims(), $pem, 'RS256', 'test'), $keys, 'https://id.example.invalid', 'demo', 'nonce')['sub']);
        foreach ([['iss' => 'https://evil.invalid'], ['aud' => 'other'], ['exp' => time() - 10], ['iat' => time() + 30], ['nonce' => 'wrong'], ['azp' => 'other'], ['nbf' => time() + 60], ['sub' => '']] as $change) {
            try {
                $validator->validate(JWT::encode(array_merge($this->claims(), $change), $pem, 'RS256', 'test'), $keys, 'https://id.example.invalid', 'demo', 'nonce');
                self::fail('Invalid token accepted');
            } catch (ProtocolException) {
                self::assertTrue(true);
            }
        }
        try {
            $validator->validate(JWT::encode($this->claims(), 'synthetic-test-key-of-sufficient-length', 'HS256', 'test'), $keys, 'https://id.example.invalid', 'demo', 'nonce');
            self::fail('Algorithm confusion');
        } catch (ProtocolException) {
            self::assertTrue(true);
        }
    }

    public function test_pkce_state_consumption_and_successful_bootstrap(): void
    {
        [$pem,$keys] = $this->signing();
        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(['*/.well-known/*' => Http::response($this->discovery()), '*/keys' => Http::response($keys), '*/bootstrap' => Http::response($this->bootstrap())]);
        $sso = app(Sso::class);
        $session = app('session.store');
        parse_str(parse_url($sso->authorizationUrl($session), PHP_URL_QUERY), $query);
        $tx = $session->get('sso.transaction');
        self::assertSame('S256', $query['code_challenge_method']);
        self::assertSame(rtrim(strtr(base64_encode(hash('sha256', $tx['verifier'], true)), '+/', '-_'), '='), $query['code_challenge']);
        $claims = array_merge($this->claims(), ['nonce' => $tx['nonce']]);
        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(['*/.well-known/*' => Http::response($this->discovery()), '*/keys' => Http::response($keys), '*/token' => Http::response(['token_type' => 'Bearer', 'id_token' => JWT::encode($claims, $pem, 'RS256', 'test'), 'access_token' => 'synthetic-access']), '*/bootstrap' => Http::response($this->bootstrap())]);
        self::assertSame('person-demo', $sso->callback($session, $query['state'], 'code')->id);
        self::assertNull($session->get('sso.transaction'));
        $this->expectException(ProtocolException::class);
        $sso->callback($session, $query['state'], 'code');
    }

    private function bootstrap(): array
    {
        return ['authenticated' => true, 'user' => ['university_id' => 'person-demo'], 'application' => ['allowed' => true, 'client_id' => 'demo', 'permissions' => ['read']], 'security' => ['session_epoch' => 1, 'authorization_version' => 2]];
    }

    public function test_wrong_state_is_consumed_without_token_exchange(): void
    {
        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(['*' => Http::response($this->discovery())]);
        $sso = app(Sso::class);
        $session = app('session.store');
        $sso->authorizationUrl($session);
        try {
            $sso->callback($session, 'wrong', 'code');
            self::fail();
        } catch (ProtocolException) {
            self::assertNull($session->get('sso.transaction'));
        }
        Http::assertSentCount(1);
    }

    public function test_bootstrap_denies_wrong_client(): void
    {
        $this->expectException(ProtocolException::class);
        BootstrapContext::fromArray($this->bootstrap(), 'other');
    }

    public function test_http_redirect_is_rejected(): void
    {
        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(['*' => Http::response('', 302, ['Location' => 'https://evil.invalid'])]);
        $this->expectException(ProtocolException::class);
        app(Sso::class)->metadata();
    }

    public function test_middleware_fails_closed_on_changed_epoch(): void
    {
        $this->app['router']->get('/protected', fn () => response('ok'))->middleware(['web', 'sso']);
        $identity = ['issuer' => 'https://id.example.invalid', 'sub' => 'synthetic', 'iat' => time(), 'access_token' => 'synthetic', 'context' => BootstrapContext::fromArray($this->bootstrap(), 'demo')->toArray()];
        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(['*/status' => Http::response(['active' => true, 'university_id' => 'person-demo', 'session_epoch' => 2, 'authorization_version' => 2])]);
        $this->withSession(['sso.identity' => $identity])->getJson('/protected')->assertUnauthorized();
    }

    public function test_logout_token_nonce_is_rejected(): void
    {
        [$pem,$keys] = $this->signing();
        $claims = array_merge($this->claims(), ['jti' => 'logout-id', 'sid' => 'session', 'events' => ['http://schemas.openid.net/event/backchannel-logout' => (object) []]]);
        $this->expectException(ProtocolException::class);
        (new TokenValidator)->validate(JWT::encode($claims, $pem, 'RS256', 'test'), $keys, 'https://id.example.invalid', 'demo', logout: true);
    }

    public function test_logout_without_exp_and_malformed_events(): void
    {
        [$pem,$keys] = $this->signing();
        $claims = $this->claims();
        unset($claims['nonce'], $claims['exp']);
        $claims['jti'] = 'synthetic-logout';
        $claims['sid'] = 'sid';
        $claims['events'] = (object) ['http://schemas.openid.net/event/backchannel-logout' => (object) []];
        $validator = new TokenValidator;
        self::assertSame('sid', $validator->validate(JWT::encode($claims, $pem, 'RS256', 'test'), $keys, 'https://id.example.invalid', 'demo', logout: true)['sid']);
        foreach ([
            ['events' => ['http://schemas.openid.net/event/backchannel-logout' => []]],
            ['events' => ['http://schemas.openid.net/event/backchannel-logout' => 'bad']],
            ['sid' => ''], ['sub' => ''], ['jti' => ''], ['iat' => time() - 301], ['exp' => time() - 10],
        ] as $change) {
            try {
                $validator->validate(JWT::encode(array_merge($claims, $change), $pem, 'RS256', 'test'), $keys, 'https://id.example.invalid', 'demo', logout: true);
                self::fail('Invalid logout accepted');
            } catch (ProtocolException) {
                self::assertTrue(true);
            }
        }
    }

    public function test_access_token_validation_has_separate_audience_and_party(): void
    {
        [$pem,$keys] = $this->signing();
        $claims = array_merge($this->claims(), ['aud' => ['broker'], 'azp' => 'demo', 'typ' => 'Bearer']);
        unset($claims['nonce']);
        $validator = app(AccessTokenValidator::class);
        self::assertSame('demo', $validator->validateAccessToken(JWT::encode($claims, $pem, 'RS256', 'test'), $keys, 'https://id.example.invalid', 'broker', ['demo'])['azp']);
        foreach ([['typ' => 'ID'], ['aud' => 'demo'], ['azp' => 'evil'], ['iss' => 'https://evil.invalid']] as $change) {
            try {
                $validator->validateAccessToken(JWT::encode(array_merge($claims, $change), $pem, 'RS256', 'test'), $keys, 'https://id.example.invalid', 'broker', ['demo']);
                self::fail();
            } catch (AuthenticationException) {
                self::assertTrue(true);
            }
        }
    }

    public function test_json_reloaded_session_survives_and_outage_preserves_it(): void
    {
        $this->app['router']->get('/json-protected', fn () => response('ok'))->middleware(['web', 'university.auth']);
        $identity = ['issuer' => 'https://id.example.invalid', 'sub' => 'synthetic', 'iat' => time(), 'access_token' => 'synthetic', 'context' => BootstrapContext::fromArray($this->bootstrap(), 'demo')->toArray()];
        $identity = json_decode(json_encode($identity, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);
        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(['*/status' => Http::response(['active' => true, 'university_id' => 'person-demo', 'session_epoch' => 1, 'authorization_version' => 2])]);
        $this->withSession(['sso.identity' => $identity])->getJson('/json-protected')->assertOk();
        Http::swap(new Factory);
        Http::preventStrayRequests();
        Http::fake(['*/status' => Http::response([], 503)]);
        $this->getJson('/json-protected')->assertStatus(503);
        self::assertSame($identity, session('sso.identity'));
    }

    public function test_broker_http_statuses_remain_distinct(): void
    {
        foreach ([401 => AuthenticationException::class, 403 => AuthorizationException::class, 503 => UpstreamException::class] as $status => $class) {
            Http::swap(new Factory);
            Http::preventStrayRequests();
            Http::fake(['*' => Http::response([], $status)]);
            try {
                app(Sso::class)->status('synthetic');
                self::fail();
            } catch (ProtocolException $exception) {
                self::assertInstanceOf($class, $exception);
            }
        }
    }

    public function test_identity_binding_and_context_surface(): void
    {
        $data = $this->bootstrap();
        $data['identity'] = ['issuer' => 'https://id.example.invalid', 'subject' => 'synthetic'];
        $data['application']['roles'] = ['reader'];
        $data['active_context'] = ['context_id' => 'context-demo'];
        $data['applications'] = [['code' => 'demo']];
        $context = BootstrapContext::fromArray($data, 'demo', 'https://id.example.invalid', 'synthetic');
        self::assertSame('person-demo', $context->universityId());
        self::assertSame(['reader'], $context->roles());
        self::assertSame(['read'], $context->permissions());
        self::assertSame('person-demo', $context->person()['university_id']);
        self::assertSame('context-demo', $context->activeContext()['context_id']);
        self::assertCount(1, $context->applications());
        $this->expectException(AuthenticationException::class);
        BootstrapContext::fromArray($data, 'demo', 'https://id.example.invalid', 'other');
    }

    public function test_actual_json_session_handler_save_reload(): void
    {
        $handler = new ArraySessionHandler(120);
        $first = new Store('sdk-json', $handler, null, 'json');
        $first->start();
        $id = $first->getId();
        $first->put('sso.identity', ['issuer' => 'https://id.example.invalid', 'sub' => 'synthetic', 'context' => BootstrapContext::fromArray($this->bootstrap(), 'demo')->toArray()]);
        $first->save();
        $second = new Store('sdk-json', $handler, $id, 'json');
        $second->start();
        $context = app(Sso::class)->context($second);
        self::assertSame('person-demo', $context->universityId());
        self::assertTrue($context->can('read'));
    }

    public function test_backchannel_positive_delivery_and_replay_are_idempotent(): void
    {
        [$pem,$keys] = $this->signing();
        $claims = $this->claims();
        unset($claims['nonce'],$claims['exp']);
        $claims['jti'] = 'delivery-demo';
        $claims['sid'] = 'session-demo';
        $claims['events'] = (object) ['http://schemas.openid.net/event/backchannel-logout' => (object) []];
        Http::fake(['*/.well-known/*' => Http::response($this->discovery()), '*/keys' => Http::response($keys)]);
        $token = JWT::encode($claims, $pem, 'RS256', 'test');
        $handler = new BackchannelLogout;
        $handler->handle($token);
        $handler->handle($token);
        self::assertSame($claims['iat'], Cache::get(BackchannelLogout::key($claims['iss'], 'sid', 'session-demo')));
    }

    public function test_configurable_scopes_and_rp_logout(): void
    {
        config(['university-sso.scopes' => ['openid', 'broker-api'], 'university-sso.post_logout_redirect_uri' => 'https://app.example.invalid/']);
        Http::fake(['*' => Http::response($this->discovery(['end_session_endpoint' => 'https://id.example.invalid/logout']))]);
        $sso = app(Sso::class);
        $session = app('session.store');
        parse_str(parse_url($sso->authorizationUrl($session), PHP_URL_QUERY), $query);
        self::assertSame('openid broker-api', $query['scope']);
        $session->put('sso.identity', ['id_token' => 'synthetic-id']);
        parse_str(parse_url($sso->logoutUrl($session), PHP_URL_QUERY), $logout);
        self::assertSame('synthetic-id', $logout['id_token_hint']);
        self::assertNull($session->get('sso.identity'));
    }

    public function test_permission_middleware_alone_cannot_authorize(): void
    {
        $this->app['router']->get('/permission-alone', fn () => response('unsafe'))->middleware(['web', 'university.permission:read']);
        $this->getJson('/permission-alone')->assertUnauthorized();
    }

    public function test_changed_authorization_version_rejects_cached_permission(): void
    {
        $this->app['router']->get('/permission-protected', fn () => response('ok'))->middleware(['web', 'university.session-valid', 'university.permission:read']);
        $identity = ['issuer' => 'https://id.example.invalid', 'sub' => 'synthetic', 'iat' => time(), 'access_token' => 'synthetic', 'context' => BootstrapContext::fromArray($this->bootstrap(), 'demo')->toArray()];
        Http::fake(['*/status' => Http::response(['active' => true, 'university_id' => 'person-demo', 'session_epoch' => 1, 'authorization_version' => 3])]);
        $this->withSession(['sso.identity' => $identity])->getJson('/permission-protected')->assertUnauthorized();
    }

    public function test_fresh_permission_check_invokes_resource_policy(): void
    {
        $session = app('session.store');
        $session->put('sso.identity', ['issuer' => 'https://id.example.invalid', 'sub' => 'synthetic', 'iat' => time(), 'access_token' => 'synthetic', 'context' => BootstrapContext::fromArray($this->bootstrap(), 'demo')->toArray()]);
        Http::fake(['*/status' => Http::response(['active' => true, 'university_id' => 'person-demo', 'session_epoch' => 1, 'authorization_version' => 2])]);
        self::assertTrue(app(Sso::class)->hasPermission('read', fn (BootstrapContext $context) => $context->id === 'person-demo'));
        self::assertFalse(app(Sso::class)->hasPermission('read', fn () => false));
        Http::assertSentCount(2);
    }

    public function test_context_guard_requires_fresh_session_and_exact_active_context(): void
    {
        $this->app['router']->get('/context-alone', fn () => response('unsafe'))->middleware(['web', 'university.context:context-demo']);
        $this->getJson('/context-alone')->assertUnauthorized();
        $this->app['router']->get('/context-match', fn () => response('ok'))->middleware(['web', 'university.session-valid', 'university.context:context-demo']);
        $this->app['router']->get('/context-other', fn () => response('unsafe'))->middleware(['web', 'university.session-valid', 'university.context:other']);
        $data = $this->bootstrap();
        $data['active_context'] = ['context_id' => 'context-demo'];
        $identity = ['issuer' => 'https://id.example.invalid', 'sub' => 'synthetic', 'iat' => time(), 'access_token' => 'synthetic', 'context' => BootstrapContext::fromArray($data, 'demo')->toArray()];
        Http::fake(['*/status' => Http::response(['active' => true, 'university_id' => 'person-demo', 'session_epoch' => 1, 'authorization_version' => 2])]);
        $this->withSession(['sso.identity' => $identity])->getJson('/context-match')->assertOk();
        $this->getJson('/context-other')->assertForbidden();
    }

    public function test_registry_event_is_token_free_and_local_logout_clears_session(): void
    {
        Event::fake([SessionLifecycle::class]);
        $session = app('session.store');
        $session->start();
        $reference = hash('sha256', $session->getId());
        $session->put('sso.identity', ['issuer' => 'https://id.example.invalid', 'sub' => 'synthetic', 'access_token' => 'never-emit', 'id_token' => 'never-emit', 'context' => $this->bootstrap()]);
        app(Sso::class)->logout($session);
        self::assertNull($session->get('sso.identity'));
        Event::assertDispatched(SessionLifecycle::class, fn ($event) => $event->operation === 'local_logout' && $event->identity['session_reference'] === $reference && ! array_key_exists('access_token', $event->identity));
        $event = new SessionLifecycle('registered', ['issuer' => 'issuer', 'access_token' => 'secret', 'refresh_token' => 'secret']);
        self::assertSame(['issuer' => 'issuer'], $event->identity);
    }

    public function test_registry_listener_failure_cannot_prevent_local_logout(): void
    {
        Event::listen(SessionLifecycle::class, fn () => throw new \RuntimeException('unavailable'));
        $session = app('session.store');
        $session->put('sso.identity', ['issuer' => 'https://id.example.invalid', 'sub' => 'synthetic']);
        try {
            app(Sso::class)->logout($session);
            self::fail();
        } catch (UpstreamException) {
            self::assertNull($session->get('sso.identity'));
        }
    }

    public function test_access_failures_preserve_cause_and_scope_jwks_refresh(): void
    {
        [$pem,$keys] = $this->signing();
        [$rotatedPem] = $this->signing();
        $claims = array_merge($this->claims(), ['aud' => 'broker', 'azp' => 'demo', 'typ' => 'Bearer']);
        unset($claims['nonce']);
        $validator = new TokenValidator;
        foreach ([
            [JWT::encode($claims, $pem, 'RS256', 'rotated'), true, \UnexpectedValueException::class],
            [JWT::encode($claims, $rotatedPem, 'RS256', 'test'), true, SignatureInvalidException::class],
            [JWT::encode(array_merge($claims, ['iss' => 'https://wrong.invalid']), $pem, 'RS256', 'test'), false, null],
            [JWT::encode(array_merge($claims, ['exp' => time() - 10]), $pem, 'RS256', 'test'), false, ExpiredException::class],
            ['malformed', false, \UnexpectedValueException::class],
            [JWT::encode($claims, $pem, 'RS256'), false, \UnexpectedValueException::class],
        ] as [$token,$refresh,$cause]) {
            try {
                $validator->validateAccessToken($token, $keys, 'https://id.example.invalid', 'broker', ['demo']);
                self::fail();
            } catch (AuthenticationException $exception) {
                self::assertSame($refresh, $exception->shouldRefreshJwks());
                if ($cause !== null) {
                    self::assertInstanceOf($cause, $exception->getPrevious());
                } else {
                    self::assertNull($exception->getPrevious());
                }
            }
        }
    }

    private function refreshIdentity(string $token = 'refresh-old'): array
    {
        config(['university-sso.refresh.enabled' => true]);

        return [
            'issuer' => 'https://id.example.invalid', 'sub' => 'synthetic-subject', 'sid' => null,
            'iat' => time() - 60, 'nonce' => 'nonce', 'auth_time' => null, 'access_token' => 'access-old',
            'refresh_token' => Crypt::encryptString($token),
            'id_token' => 'original-id', 'context' => BootstrapContext::fromArray($this->bootstrap(), 'demo')->toArray(),
        ];
    }

    private function fakeRefresh(array $tokens, ?array $bootstrap = null, int $status = 200): void
    {
        Http::fake([
            '*/.well-known/*' => Http::response($this->discovery()),
            '*/token' => Http::response($tokens, $status),
            '*/bootstrap' => Http::response($bootstrap ?? $this->bootstrap()),
            '*/status' => Http::response(['active' => true, 'university_id' => 'person-demo', 'session_epoch' => 1, 'authorization_version' => 2]),
        ]);
    }

    public function test_refresh_rotates_encrypted_credentials_and_session_without_exposing_tokens(): void
    {
        Event::fake([SessionLifecycle::class]);
        $session = app('session.store');
        $session->start();
        $identity = $this->refreshIdentity();
        $session->put('sso.identity', $identity);
        $previousId = $session->getId();
        $this->fakeRefresh(['access_token' => 'access-new', 'refresh_token' => 'refresh-new', 'token_type' => 'Bearer', 'expires_in' => 120]);
        self::assertSame('person-demo', app(Sso::class)->refresh($session)->id);
        $renewed = json_decode(json_encode($session->get('sso.identity'), JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);
        self::assertNotSame($previousId, $session->getId());
        self::assertNotSame('refresh-new', $renewed['refresh_token']);
        self::assertSame('refresh-new', Crypt::decryptString($renewed['refresh_token']));
        self::assertSame($identity['iat'], $renewed['iat']);
        self::assertSame('original-id', $renewed['id_token']);
        Event::assertDispatched(SessionLifecycle::class,
            fn ($event) => $event->operation === 'refreshed' && $event->identity['previous_session_reference'] === hash('sha256', $previousId) && ! isset($event->identity['refresh_token']));
        // A stale session snapshot cannot submit the retired refresh credential again.
        $session->put('sso.identity', $identity);
        try {
            app(Sso::class)->refresh($session);
            self::fail();
        } catch (AuthenticationException) {
            self::assertNull($session->get('sso.identity'));
        }
        self::assertCount(1, Http::recorded(fn ($request) => str_ends_with($request->url(), '/token')));
    }

    public function test_refreshed_id_token_allows_absent_nonce_but_binds_identity_and_present_nonce(): void
    {
        [$pem,$keys] = $this->signing();
        $validator = new TokenValidator;
        $claims = $this->claims();
        unset($claims['nonce']);
        self::assertSame('synthetic-subject', $validator->validateRefreshedIdToken(JWT::encode($claims, $pem, 'RS256', 'test'), $keys, 'https://id.example.invalid', 'demo', 'synthetic-subject', 'nonce')['sub']);
        foreach ([['sub' => 'other'], ['iss' => 'https://wrong.invalid'], ['aud' => 'other'], ['nonce' => 'wrong'], ['exp' => time() - 10]] as $change) {
            try {
                $validator->validateRefreshedIdToken(JWT::encode(array_merge($claims, $change), $pem, 'RS256', 'test'), $keys, 'https://id.example.invalid', 'demo', 'synthetic-subject', 'nonce');
                self::fail();
            } catch (ProtocolException) {
                self::assertTrue(true);
            }
        }
    }

    public function test_nonrotating_refresh_response_ends_session(): void
    {
        $session = app('session.store');
        $session->put('sso.identity', $this->refreshIdentity());
        $this->fakeRefresh(['access_token' => 'new', 'refresh_token' => 'refresh-old', 'token_type' => 'Bearer']);
        try {
            app(Sso::class)->refresh($session);
            self::fail();
        } catch (AuthenticationException) {
            self::assertNull($session->get('sso.identity'));
        }
    }

    public function test_refresh_cannot_accept_changed_broker_authorization(): void
    {
        $session = app('session.store');
        $session->put('sso.identity', $this->refreshIdentity());
        $data = $this->bootstrap();
        $data['security']['session_epoch'] = 2;
        $this->fakeRefresh(['access_token' => 'new', 'refresh_token' => 'new', 'token_type' => 'Bearer'], $data);
        try {
            app(Sso::class)->refresh($session);
            self::fail();
        } catch (AuthenticationException) {
            self::assertNull($session->get('sso.identity'));
        }
    }

    public function test_ambiguous_refresh_failure_is_503_class_and_cannot_retry_old_credential(): void
    {
        $session = app('session.store');
        $session->put('sso.identity', $this->refreshIdentity());
        $this->fakeRefresh([], status: 503);
        try {
            app(Sso::class)->refresh($session);
            self::fail();
        } catch (UpstreamException) {
            self::assertNull($session->get('sso.identity'));
        }
        self::assertCount(1, Http::recorded(fn ($request) => str_ends_with($request->url(), '/token')));
    }

    public function test_outage_before_refresh_grant_preserves_unconsumed_session(): void
    {
        $session = app('session.store');
        $identity = $this->refreshIdentity();
        $session->put('sso.identity', $identity);
        Http::fake(['*' => Http::response([], 503)]);
        try {
            app(Sso::class)->refresh($session);
            self::fail();
        } catch (UpstreamException) {
            self::assertSame($identity, $session->get('sso.identity'));
        }
        self::assertCount(0, Http::recorded(fn ($request) => str_ends_with($request->url(), '/token')));
    }

    public function test_concurrent_refresh_snapshots_issue_only_one_provider_grant(): void
    {
        $first = app('session.store');
        $first->start();
        $identity = $this->refreshIdentity();
        $first->put('sso.identity', $identity);
        $second = new Store('parallel', new ArraySessionHandler(120), null, 'json');
        $second->start();
        $second->put('sso.identity', $identity);
        $rejected = false;
        Http::fake([
            '*/.well-known/*' => Http::response($this->discovery()),
            '*/token' => function () use ($second, &$rejected) {
                try {
                    app(Sso::class)->refresh($second);
                    self::fail('Concurrent credential accepted');
                } catch (AuthenticationException) {
                    $rejected = true;
                }

                return Http::response(['access_token' => 'new', 'refresh_token' => 'new', 'token_type' => 'Bearer']);
            },
            '*/bootstrap' => Http::response($this->bootstrap()),
        ]);
        app(Sso::class)->refresh($first);
        self::assertTrue($rejected);
        self::assertNotNull($first->get('sso.identity'));
        self::assertNull($second->get('sso.identity'));
        self::assertCount(1, Http::recorded(fn ($request) => str_ends_with($request->url(), '/token')));
    }

    public function test_session_guard_refreshes_before_access_token_expiry(): void
    {
        $this->app['router']->get('/auto-refresh', fn () => response('ok'))->middleware(['web', 'university.session-valid']);
        $identity = $this->refreshIdentity();
        $identity['access_expires_at'] = time();
        $this->fakeRefresh(['access_token' => 'new', 'refresh_token' => 'new', 'token_type' => 'Bearer', 'expires_in' => 120]);
        $this->withSession(['sso.identity' => $identity])->getJson('/auto-refresh')->assertOk();
        self::assertSame('new', session('sso.identity.access_token'));
    }

    public function test_logout_arriving_during_refresh_cannot_revive_session(): void
    {
        $session = app('session.store');
        $identity = $this->refreshIdentity();
        $session->put('sso.identity', $identity);
        Http::fake([
            '*/.well-known/*' => Http::response($this->discovery()),
            '*/token' => Http::response(['access_token' => 'new', 'refresh_token' => 'new', 'token_type' => 'Bearer']),
            '*/bootstrap' => function () use ($identity) {
                Cache::put(BackchannelLogout::key($identity['issuer'], 'sub', $identity['sub']), time(), 600);

                return Http::response($this->bootstrap());
            },
        ]);
        try {
            app(Sso::class)->refresh($session);
            self::fail();
        } catch (AuthenticationException) {
            self::assertNull($session->get('sso.identity'));
        }
    }

    public function test_backchannel_out_of_order_and_duplicate_events_never_regress_marker(): void
    {
        Event::fake([SessionLifecycle::class]);
        [$pem,$keys] = $this->signing();
        $claims = $this->claims();
        unset($claims['nonce']);
        $claims['sid'] = 'monotonic-session';
        $claims['jti'] = 'new-event';
        $claims['iat'] = time() - 1;
        $claims['events'] = (object) ['http://schemas.openid.net/event/backchannel-logout' => (object) []];
        Http::fake(['*/.well-known/*' => Http::response($this->discovery()), '*/keys' => Http::response($keys)]);
        $handler = new BackchannelLogout;
        $handler->handle(JWT::encode($claims, $pem, 'RS256', 'test'));
        $latest = $claims['iat'];
        $claims['iat'] -= 10;
        $claims['jti'] = 'old-event';
        $old = JWT::encode($claims, $pem, 'RS256', 'test');
        $handler->handle($old);
        $handler->handle($old);
        self::assertSame($latest, Cache::get(BackchannelLogout::key($claims['iss'], 'sid', $claims['sid'])));
        Event::assertDispatchedTimes(SessionLifecycle::class, 2);
    }

    public function test_refreshed_signed_id_token_is_verified_and_retained_for_rp_logout(): void
    {
        [$pem,$keys] = $this->signing();
        $claims = $this->claims();
        unset($claims['nonce']);
        $session = app('session.store');
        $session->put('sso.identity', $this->refreshIdentity());
        $jwt = JWT::encode($claims, $pem, 'RS256', 'test');
        Http::fake([
            '*/.well-known/*' => Http::response($this->discovery()),
            '*/token' => Http::response(['access_token' => 'new', 'refresh_token' => 'new', 'token_type' => 'Bearer', 'id_token' => $jwt]),
            '*/keys' => Http::response($keys),
            '*/bootstrap' => Http::response($this->bootstrap()),
        ]);
        app(Sso::class)->refresh($session);
        self::assertSame($jwt, $session->get('sso.identity.id_token'));
    }

    public function test_refresh_never_sends_credentials_after_provider_configuration_changes(): void
    {
        $session = app('session.store');
        $session->put('sso.identity', $this->refreshIdentity());
        config(['university-sso.issuer' => 'https://replacement.example.invalid']);
        Http::fake();
        try {
            app(Sso::class)->refresh($session);
            self::fail();
        } catch (AuthenticationException) {
            self::assertNull($session->get('sso.identity'));
        }
        Http::assertNothingSent();
    }

    public function test_refreshed_identity_rejects_logout_and_access_token_profiles(): void
    {
        [$pem,$keys] = $this->signing();
        $claims = $this->claims();
        unset($claims['nonce']);
        foreach ([
            ['jti' => 'logout', 'sid' => 'sid', 'events' => (object) ['http://schemas.openid.net/event/backchannel-logout' => (object) []]],
            ['typ' => 'Bearer'], ['typ' => 'Refresh'],
        ] as $profile) {
            try {
                (new TokenValidator)->validateRefreshedIdToken(JWT::encode(array_merge($claims, $profile), $pem, 'RS256', 'test'), $keys, 'https://id.example.invalid', 'demo', 'synthetic-subject', 'nonce');
                self::fail('Wrong profile accepted');
            } catch (ProtocolException) {
                self::assertTrue(true);
            }
        }
    }

    public function test_future_not_before_is_rejected_despite_ambient_library_leeway(): void
    {
        [$pem,$keys] = $this->signing();
        $claims = array_merge($this->claims(), ['aud' => 'broker', 'azp' => 'demo', 'typ' => 'Bearer', 'nbf' => time() + 60]);
        $previousLeeway = JWT::$leeway;
        JWT::$leeway = 300;
        try {
            try {
                (new TokenValidator)->validateAccessToken(JWT::encode($claims, $pem, 'RS256', 'test'), $keys, 'https://id.example.invalid', 'broker', ['demo']);
                self::fail();
            } catch (AuthenticationException $exception) {
                self::assertFalse($exception->shouldRefreshJwks());
            }
        } finally {
            JWT::$leeway = $previousLeeway;
        }
    }

    private function logoutFixture(): array
    {
        [$pem,$keys] = $this->signing();
        $claims = $this->claims();
        unset($claims['nonce']);
        $claims['jti'] = 'retryable-event';
        $claims['sid'] = 'retryable-session';
        $claims['events'] = (object) ['http://schemas.openid.net/event/backchannel-logout' => (object) []];
        Http::fake(['*/.well-known/*' => Http::response($this->discovery()), '*/keys' => Http::response($keys)]);

        return [$pem, $claims];
    }

    public function test_backchannel_listener_failure_preserves_marker_and_allows_idempotent_retry(): void
    {
        [$pem,$claims] = $this->logoutFixture();
        $references = [];
        Event::listen(SessionLifecycle::class, function ($event) use (&$references): void {
            $references[] = $event->identity['event_reference'];
            if (count($references) === 1) {
                throw new \RuntimeException('Registry unavailable');
            }
        });
        $handler = new BackchannelLogout;
        $token = JWT::encode($claims, $pem, 'RS256', 'test');
        try {
            $handler->handle($token);
            self::fail();
        } catch (UpstreamException) {
            self::assertSame($claims['iat'], Cache::get(BackchannelLogout::key($claims['iss'], 'sid', $claims['sid'])));
        }
        $handler->handle($token);
        $handler->handle($token);
        self::assertCount(2, $references);
        self::assertSame($references[0], $references[1]);
    }

    public function test_backchannel_failed_marker_write_is_service_unavailable_and_emits_no_registry_event(): void
    {
        [$pem,$claims] = $this->logoutFixture();
        Event::fake([SessionLifecycle::class]);
        $lock = \Mockery::mock(Lock::class);
        $lock->shouldReceive('block')->once()->andReturnUsing(fn ($seconds, $callback) => $callback());
        Cache::shouldReceive('lock')->once()->andReturn($lock);
        Cache::shouldReceive('has')->once()->andReturn(false);
        Cache::shouldReceive('get')->once()->andReturn(0);
        Cache::shouldReceive('put')->once()->andReturn(false);
        try {
            (new BackchannelLogout)->handle(JWT::encode($claims, $pem, 'RS256', 'test'));
            self::fail();
        } catch (UpstreamException) {
            Event::assertNothingDispatched();
        }
    }

    public function test_shared_cache_replay_deduplication_is_scoped_to_the_receiving_client(): void
    {
        [$pem,$claims] = $this->logoutFixture();
        Event::fake([SessionLifecycle::class]);
        $claims['aud'] = ['demo', 'other-client'];
        $token = JWT::encode($claims, $pem, 'RS256', 'test');
        $handler = new BackchannelLogout;
        $handler->handle($token);
        config(['university-sso.client_id' => 'other-client']);
        $handler->handle($token);
        Event::assertDispatchedTimes(SessionLifecycle::class, 2);
        Event::assertDispatched(SessionLifecycle::class, fn ($event) => $event->identity['client_id'] === 'other-client');
    }

    private function expiredContextIdentity(): array
    {
        $identity = $this->refreshIdentity();
        config(['university-sso.refresh.enabled' => false]);
        $data = $this->bootstrap();
        $data['security']['context_expires_at'] = gmdate('Y-m-d\TH:i:s\Z', time() - 60);
        $identity['context'] = BootstrapContext::fromArray($data, 'demo')->toArray();

        return $identity;
    }

    public function test_context_expiry_survives_json_round_trip_and_has_a_precise_boundary(): void
    {
        $data = $this->bootstrap();
        $data['security']['context_expires_at'] = '2030-01-01T00:00:00Z';
        $context = BootstrapContext::fromArray(json_decode(json_encode($data, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR), 'demo');
        self::assertSame($data['security']['context_expires_at'], $context->toArray()['security']['context_expires_at']);
        self::assertFalse($context->isExpired($context->expiresAt() - 1));
        self::assertTrue($context->isExpired($context->expiresAt()));
    }

    public function test_malformed_context_expiry_and_negative_version_are_rejected(): void
    {
        foreach (['not-a-date', '2026-02-31T00:00:00Z', true, null] as $expiry) {
            $data = $this->bootstrap();
            $data['security']['context_expires_at'] = $expiry;
            try {
                BootstrapContext::fromArray($data, 'demo');
                self::fail();
            } catch (UpstreamException) {
                self::assertTrue(true);
            }
        }
        $data = $this->bootstrap();
        $data['security']['authorization_version'] = -1;
        $this->expectException(UpstreamException::class);
        BootstrapContext::fromArray($data, 'demo');
    }

    public function test_expired_context_is_replaced_once_without_a_provider_token_grant(): void
    {
        $this->app['router']->get('/expiring-context', fn () => response('ok'))->middleware(['web', 'university.session-valid']);
        $identity = $this->expiredContextIdentity();
        $fresh = $this->bootstrap();
        $fresh['security']['context_expires_at'] = gmdate('Y-m-d\TH:i:s\Z', time() + 300);
        Http::fake([
            '*/bootstrap' => Http::response($fresh),
            '*/status' => Http::response(['active' => true, 'university_id' => 'person-demo', 'session_epoch' => 1, 'authorization_version' => 2]),
        ]);
        $this->withSession(['sso.identity' => $identity])->getJson('/expiring-context')->assertOk();
        $this->getJson('/expiring-context')->assertOk();
        self::assertCount(1, Http::recorded(fn ($request) => str_ends_with($request->url(), '/bootstrap')));
        self::assertCount(0, Http::recorded(fn ($request) => str_ends_with($request->url(), '/token')));
        self::assertSame($identity['access_token'], session('sso.identity.access_token'));
    }

    public function test_context_renewal_outage_preserves_expired_snapshot_but_executes_no_protected_action(): void
    {
        $this->app['router']->get('/expired-outage', fn () => response('unsafe'))->middleware(['web', 'university.session-valid']);
        $identity = $this->expiredContextIdentity();
        Http::fake(['*/bootstrap' => Http::response([], 503)]);
        $this->withSession(['sso.identity' => $identity])->getJson('/expired-outage')->assertStatus(503);
        self::assertSame($identity, session('sso.identity'));
    }

    public function test_context_renewal_cannot_drop_expiry_or_change_authorization_version(): void
    {
        $session = app('session.store');
        $identity = $this->expiredContextIdentity();
        $session->put('sso.identity', $identity);
        Http::fake(['*/bootstrap' => Http::response($this->bootstrap())]);
        try {
            app(Sso::class)->refreshContext($session);
            self::fail();
        } catch (UpstreamException) {
            self::assertSame($identity, $session->get('sso.identity'));
        }
        Http::swap(new Factory);
        Http::preventStrayRequests();
        $changed = $this->bootstrap();
        $changed['security']['authorization_version'] = 3;
        $changed['security']['context_expires_at'] = gmdate('Y-m-d\TH:i:s\Z', time() + 300);
        Http::fake(['*/bootstrap' => Http::response($changed)]);
        try {
            app(Sso::class)->refreshContext($session);
            self::fail();
        } catch (AuthenticationException) {
            self::assertNull($session->get('sso.identity'));
        }
    }
}
