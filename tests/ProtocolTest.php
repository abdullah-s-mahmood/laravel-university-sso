<?php

declare(strict_types=1);

namespace UniversitySso\Tests;

use Firebase\JWT\JWT;
use Illuminate\Http\Client\Factory;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;
use UniversitySso\AccessTokenValidator;
use UniversitySso\AuthenticationException;
use UniversitySso\AuthorizationException;
use UniversitySso\BackchannelLogout;
use UniversitySso\BootstrapContext;
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
}
