<?php

declare(strict_types=1);

namespace UniversitySso;

use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Http as Client;

final class Sso implements Contracts\BrokerClient
{
    private function setting(string $key): string
    {
        $value = config('university-sso.'.$key);
        if (! is_string($value) || $value === '') {
            throw new ProtocolException('Missing SSO configuration: '.$key);
        }

        return $value;
    }

    public function metadata(): array
    {
        $issuer = Http::url($this->setting('issuer'));
        $data = Http::get(rtrim($issuer, '/').'/.well-known/openid-configuration');
        if (($data['issuer'] ?? null) !== $issuer) {
            throw new ProtocolException('Discovery issuer mismatch.');
        }
        foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $key) {
            if (! is_string($data[$key] ?? null)) {
                throw new ProtocolException('Missing discovery endpoint.');
            }
            Http::url($data[$key]);
        }

        return $data;
    }

    public function authorizationUrl(Session $session): string
    {
        $data = $this->metadata();
        $state = bin2hex(random_bytes(32));
        $nonce = bin2hex(random_bytes(32));
        $verifier = bin2hex(random_bytes(32));
        $session->put('sso.transaction', ['state' => $state, 'nonce' => $nonce, 'verifier' => $verifier, 'time' => time()]);

        return $data['authorization_endpoint'].(str_contains($data['authorization_endpoint'], '?') ? '&' : '?').http_build_query([
            'client_id' => $this->setting('client_id'), 'redirect_uri' => Http::url($this->setting('redirect_uri')),
            'response_type' => 'code', 'scope' => implode(' ', array_unique(array_merge(['openid'], config('university-sso.scopes', ['openid'])))), 'state' => $state, 'nonce' => $nonce,
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
        ], '', '&', PHP_QUERY_RFC3986);
    }

    public function callback(Session $session, string $state, string $code): BootstrapContext
    {
        $transaction = $session->pull('sso.transaction');
        if (! is_array($transaction) || ! hash_equals($transaction['state'], $state) || $code === '' || time() - $transaction['time'] > (int) config('university-sso.transaction_ttl', 300)) {
            throw new ProtocolException('Invalid or expired authorization transaction.');
        }
        $metadata = $this->metadata();
        $tokens = $this->requestTokens($metadata['token_endpoint'], [
            'grant_type' => 'authorization_code', 'code' => $code,
            'redirect_uri' => $this->setting('redirect_uri'), 'code_verifier' => $transaction['verifier'],
        ]);
        if (! is_string($tokens['id_token'] ?? null) || $tokens['id_token'] === '') {
            throw new AuthenticationException('Missing ID token.');
        }
        $claims = (new TokenValidator)->validate($tokens['id_token'], Http::get($metadata['jwks_uri']), $this->setting('issuer'), $this->setting('client_id'), $transaction['nonce']);
        $this->validateAccessHash($claims, $tokens['access_token']);
        $context = $this->bootstrap($tokens['access_token'], $claims['iss'], $claims['sub']);
        $encryptedRefresh = $this->encryptRefreshToken($tokens);
        $session->regenerate(true);
        $this->notifySession('registered', $session, [
            'issuer' => $claims['iss'], 'sub' => $claims['sub'], 'sid' => $claims['sid'] ?? null,
        ], $context);
        $session->put('sso.identity', ['issuer' => $claims['iss'], 'sub' => $claims['sub'], 'sid' => $claims['sid'] ?? null, 'iat' => $claims['iat'], 'access_token' => $tokens['access_token'], 'id_token' => $tokens['id_token'], 'context' => $context->toArray(),
            'nonce' => $transaction['nonce'], 'auth_time' => $claims['auth_time'] ?? null,
            'access_expires_at' => isset($tokens['expires_in']) ? time() + $tokens['expires_in'] : null,
            'refresh_token' => $encryptedRefresh,
        ]);

        return $context;
    }

    private function requestTokens(string $endpoint, array $grant): array
    {
        try {
            $request = Client::asForm()->acceptJson()->timeout((int) config('university-sso.timeout', 5))
                ->connectTimeout(3)->withOptions(['allow_redirects' => false]);
            $secret = config('university-sso.client_secret');
            if (is_string($secret) && $secret !== '') {
                $request = $request->withBasicAuth($this->setting('client_id'), $secret);
            }
            $response = $request->post(Http::url($endpoint), array_merge($grant, ['client_id' => $this->setting('client_id')]));
            if ($response->status() === 400 || $response->status() === 401) {
                throw new AuthenticationException('Token grant rejected.');
            }
            if ($response->status() === 403) {
                throw new AuthorizationException('Token grant denied.');
            }
            $tokens = $response->json();
            if (! $response->successful() || ! is_array($tokens) || ! is_string($tokens['access_token'] ?? null)
                || $tokens['access_token'] === '' || ! is_string($tokens['token_type'] ?? null)
                || strtolower($tokens['token_type']) !== 'bearer'
                || (array_key_exists('expires_in', $tokens) && (! is_int($tokens['expires_in']) || $tokens['expires_in'] <= 0))) {
                throw new UpstreamException('Token endpoint unavailable or malformed.');
            }

            return $tokens;
        } catch (ProtocolException $exception) {
            throw $exception;
        } catch (\Throwable) {
            throw new UpstreamException('Token endpoint unavailable or malformed.');
        }
    }

    private function validateAccessHash(array $claims, string $accessToken): void
    {
        if (array_key_exists('at_hash', $claims)) {
            $expected = rtrim(strtr(base64_encode(substr(hash('sha256', $accessToken, true), 0, 16)), '+/', '-_'), '=');
            if (! is_string($claims['at_hash']) || ! hash_equals($expected, $claims['at_hash'])) {
                throw new AuthenticationException('Access token hash mismatch.');
            }
        }
    }

    private function encryptRefreshToken(array $tokens): ?string
    {
        if (! config('university-sso.refresh.enabled', false)) {
            return null;
        }
        if (! is_string($tokens['refresh_token'] ?? null) || $tokens['refresh_token'] === '') {
            throw new AuthenticationException('Provider did not return a rotating refresh token.');
        }

        return Crypt::encryptString($tokens['refresh_token']);
    }

    private function assertConfiguredIdentity(array $identity): void
    {
        if (($identity['issuer'] ?? null) !== $this->setting('issuer')
            || ($identity['context']['application']['client_id'] ?? null) !== $this->setting('client_id')
            || ! is_string($identity['sub'] ?? null) || $identity['sub'] === '') {
            throw new AuthenticationException('Session identity configuration changed.');
        }
    }

    private function assertNotLoggedOut(array $identity): void
    {
        foreach (['sid', 'sub'] as $kind) {
            if (is_string($identity[$kind] ?? null)) {
                try {
                    $marker = Cache::get(BackchannelLogout::key($identity['issuer'], $kind, $identity[$kind]));
                } catch (\Throwable) {
                    throw new UpstreamException('Session revocation store unavailable.');
                }
                if ($marker !== null && ($kind === 'sid' || $identity['iat'] <= $marker)) {
                    throw new AuthenticationException('Session logged out.');
                }
            }
        }
    }

    public function refresh(Session $session): BootstrapContext
    {
        if (! config('university-sso.refresh.enabled', false)) {
            throw new ProtocolException('Refresh is disabled.');
        }
        $identity = $session->get('sso.identity');
        if (! is_array($identity) || ! is_string($identity['refresh_token'] ?? null)) {
            throw new AuthenticationException('No refreshable session.');
        }
        $claimed = false;
        try {
            $this->assertConfiguredIdentity($identity);
            $old = BootstrapContext::fromArray($identity['context'], $this->setting('client_id'), $identity['issuer'], $identity['sub']);
            $this->assertNotLoggedOut($identity);
            $metadata = $this->metadata();
            try {
                $refreshToken = Crypt::decryptString($identity['refresh_token']);
            } catch (\Throwable) {
                throw new AuthenticationException('Invalid refresh credential.');
            }
            $key = 'sso:refresh:'.hash('sha256', $identity['issuer']."\0".$this->setting('client_id')."\0".$refreshToken);
            try {
                $unused = Cache::add($key, true, (int) config('university-sso.refresh.replay_retention', 86400));
            } catch (\Throwable) {
                throw new UpstreamException('Refresh replay store unavailable.');
            }
            if (! $unused) {
                throw new AuthenticationException('Refresh credential already consumed.');
            }
            $claimed = true;
            $tokens = $this->requestTokens($metadata['token_endpoint'], ['grant_type' => 'refresh_token', 'refresh_token' => $refreshToken]);
            if (! is_string($tokens['refresh_token'] ?? null) || $tokens['refresh_token'] === ''
                || hash_equals($refreshToken, $tokens['refresh_token'])) {
                throw new AuthenticationException('Refresh token was not rotated.');
            }
            if (array_key_exists('id_token', $tokens)) {
                if (! is_string($tokens['id_token']) || $tokens['id_token'] === '') {
                    throw new AuthenticationException('Invalid refreshed ID token.');
                }
                $claims = (new TokenValidator)->validateRefreshedIdToken($tokens['id_token'], Http::get($metadata['jwks_uri']),
                    $identity['issuer'], $this->setting('client_id'), $identity['sub'], $identity['nonce'] ?? null);
                if ((isset($claims['auth_time']) && $claims['auth_time'] !== ($identity['auth_time'] ?? null))
                    || (isset($claims['sid']) && $claims['sid'] !== ($identity['sid'] ?? null))) {
                    throw new AuthenticationException('Refreshed authentication session mismatch.');
                }
                $this->validateAccessHash($claims, $tokens['access_token']);
                $identity['id_token'] = $tokens['id_token'];
            }
            $context = $this->bootstrap($tokens['access_token'], $identity['issuer'], $identity['sub']);
            $this->assertSameSecurityContext($old, $context);
            $this->assertNotLoggedOut($identity);
            $identity['access_token'] = $tokens['access_token'];
            $identity['refresh_token'] = $this->encryptRefreshToken($tokens);
            $identity['access_expires_at'] = isset($tokens['expires_in']) ? time() + $tokens['expires_in'] : null;
            $identity['context'] = $context->toArray();
            $identity['previous_session_reference'] = hash('sha256', $session->getId());
            $session->regenerate(true);
            $this->notifySession('refreshed', $session, $identity, $context);
            unset($identity['previous_session_reference']);
            $session->put('sso.identity', $identity);

            return $context;
        } catch (\Throwable $exception) {
            if ($claimed || $exception instanceof AuthenticationException) {
                try {
                    $this->logout($session, 'refresh_failed');
                } catch (\Throwable) {
                }
            }
            if ($exception instanceof ProtocolException) {
                throw $exception;
            }
            throw new UpstreamException('Refresh operation unavailable.');
        }
    }

    public function bootstrap(string $accessToken, ?string $issuer = null, ?string $subject = null): BootstrapContext
    {
        $context = BootstrapContext::fromArray(Http::get(rtrim(Http::url($this->setting('broker_url')), '/').'/api/v1/me/bootstrap', $accessToken), $this->setting('client_id'), $issuer, $subject, (bool) config('university-sso.require_identity_binding', false));
        if ($context->isExpired()) {
            throw new UpstreamException('Broker returned expired context.');
        }

        return $context;
    }

    private function assertSameSecurityContext(BootstrapContext $old, BootstrapContext $context): void
    {
        if ($context->id !== $old->id || $context->epoch !== $old->epoch || $context->authorizationVersion !== $old->authorizationVersion) {
            throw new AuthenticationException('Session authorization changed; authenticate again.');
        }
        $this->assertContextFingerprint($old, $context->fingerprint());
        if ($old->expiresAt() !== null && $context->expiresAt() === null) {
            throw new UpstreamException('Broker omitted the required context expiry.');
        }
    }

    private function assertContextFingerprint(BootstrapContext $context, mixed $fingerprint): void
    {
        if ($context->fingerprint() === null) {
            return;
        }
        if (! is_string($fingerprint) || ! preg_match('/^[a-f0-9]{64}$/D', $fingerprint)) {
            throw new UpstreamException('Broker omitted the required context fingerprint.');
        }
        if (! hash_equals($context->fingerprint(), $fingerprint)) {
            throw new AuthenticationException('Session authorization context changed.');
        }
    }

    public function refreshContext(Session $session): BootstrapContext
    {
        $identity = $session->get('sso.identity');
        if (! is_array($identity) || ! is_array($identity['context'] ?? null)) {
            throw new AuthenticationException('No authenticated context.');
        }
        try {
            $this->assertConfiguredIdentity($identity);
            $this->assertNotLoggedOut($identity);
            $old = BootstrapContext::fromArray($identity['context'], $this->setting('client_id'), $identity['issuer'], $identity['sub']);
            $context = $this->bootstrap($identity['access_token'], $identity['issuer'], $identity['sub']);
            $this->assertSameSecurityContext($old, $context);
            $this->assertNotLoggedOut($identity);
            $identity['context'] = $context->toArray();
            $session->put('sso.identity', $identity);

            return $context;
        } catch (AuthenticationException $exception) {
            try {
                $this->logout($session);
            } catch (\Throwable) {
            }
            throw $exception;
        }
    }

    public function status(string $accessToken): array
    {
        return Http::get(rtrim(Http::url($this->setting('broker_url')), '/').'/api/v1/session/status', $accessToken);
    }

    public function validatedContext(Session $session): BootstrapContext
    {
        $identity = $session->get('sso.identity');
        if (! is_array($identity) || ! is_array($identity['context'] ?? null)) {
            throw new ProtocolException('No SSO session.');
        }
        $this->assertConfiguredIdentity($identity);
        if (config('university-sso.refresh.enabled', false) && is_int($identity['access_expires_at'] ?? null)
            && $identity['access_expires_at'] <= time() + (int) config('university-sso.refresh.before_expiry', 30)) {
            $this->refresh($session);
            $identity = $session->get('sso.identity');
        }
        $this->assertNotLoggedOut($identity);
        $context = BootstrapContext::fromArray($identity['context'], config('university-sso.client_id'), $identity['issuer'], $identity['sub']);
        if ($context->isExpired()) {
            $context = $this->refreshContext($session);
            $identity = $session->get('sso.identity');
        }
        $status = $this->status($identity['access_token']);
        if (! is_bool($status['active'] ?? null) || ! is_string($status['university_id'] ?? null) || ! is_int($status['session_epoch'] ?? null) || ! is_int($status['authorization_version'] ?? null)) {
            throw new UpstreamException('Malformed status response.');
        }
        if ($status['active'] !== true || $status['university_id'] !== $context->id || $status['session_epoch'] !== $context->epoch || $status['authorization_version'] !== $context->authorizationVersion) {
            throw new ProtocolException('Session revoked.');
        }

        $this->assertContextFingerprint($context, $status['context_fingerprint'] ?? null);

        return $context;
    }

    public function hasPermission(string $permission, ?callable $resourcePolicy = null, ?Session $session = null): bool
    {
        $context = $this->validatedContext($session ?? app('session.store'));
        if (! $context->can($permission)) {
            return false;
        }

        return $resourcePolicy === null || $resourcePolicy($context) === true;
    }

    public function context(?Session $session = null): BootstrapContext
    {
        $session ??= app('session.store');
        $identity = $session->get('sso.identity');
        if (! is_array($identity) || ! is_array($identity['context'] ?? null)) {
            throw new AuthenticationException('No authenticated context.');
        }

        return BootstrapContext::fromArray($identity['context'], $this->setting('client_id'), $identity['issuer'], $identity['sub']);
    }

    public function person(): array
    {
        return $this->context()->person();
    }

    public function activeContext(): ?array
    {
        return $this->context()->activeContext();
    }

    public function roles(): array
    {
        return $this->context()->roles();
    }

    public function permissions(): array
    {
        return $this->context()->permissions();
    }

    public function applications(): array
    {
        return $this->context()->applications();
    }

    public function universityId(): string
    {
        return $this->context()->universityId();
    }

    public function logoutUrl(Session $session): string
    {
        $metadata = $this->metadata();
        if (! is_string($metadata['end_session_endpoint'] ?? null)) {
            throw new ProtocolException('Provider does not support RP logout.');
        }
        $identity = $session->get('sso.identity');
        $url = Http::url($metadata['end_session_endpoint']).'?'.http_build_query([
            'id_token_hint' => is_array($identity) ? ($identity['id_token'] ?? null) : null,
            'client_id' => $this->setting('client_id'),
            'post_logout_redirect_uri' => Http::url($this->setting('post_logout_redirect_uri')),
        ], '', '&', PHP_QUERY_RFC3986);
        $this->logout($session, 'provider_logout');

        return $url;
    }

    private function notifySession(string $operation, Session $session, array $identity, ?BootstrapContext $context = null): void
    {
        try {
            event(new Events\SessionLifecycle($operation, [
                'issuer' => $identity['issuer'], 'client_id' => $this->setting('client_id'),
                'subject' => $identity['sub'], 'sid' => $identity['sid'] ?? null,
                'session_reference' => hash('sha256', $session->getId()),
                'previous_session_reference' => $identity['previous_session_reference'] ?? null,
                'university_id' => $context->id ?? ($identity['context']['user']['university_id'] ?? null),
                'session_epoch' => $context->epoch ?? ($identity['context']['security']['session_epoch'] ?? null),
                'authorization_version' => $context->authorizationVersion ?? ($identity['context']['security']['authorization_version'] ?? null),
                'expires_at' => time() + (int) config('session.lifetime', 120) * 60,
            ]));
        } catch (\Throwable) {
            throw new UpstreamException('Session lifecycle listener unavailable.');
        }
    }

    public function logout(Session $session, string $operation = 'local_logout'): void
    {
        try {
            $identity = $session->get('sso.identity');
            if (is_array($identity) && isset($identity['issuer'], $identity['sub'])) {
                $this->notifySession($operation, $session, $identity);
            }
        } finally {
            $session->invalidate();
            $session->regenerateToken();
        }
    }
}
