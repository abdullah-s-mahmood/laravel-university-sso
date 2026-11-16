<?php

declare(strict_types=1);

namespace UniversitySso;

use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\Cache;
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
        try {
            $request = Client::asForm()->acceptJson()->timeout((int) config('university-sso.timeout', 5))->connectTimeout(3)->withOptions(['allow_redirects' => false]);
            $secret = config('university-sso.client_secret');
            if (is_string($secret) && $secret !== '') {
                $request = $request->withBasicAuth($this->setting('client_id'), $secret);
            }
            $response = $request->post($metadata['token_endpoint'], [
                'grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => $this->setting('redirect_uri'),
                'client_id' => $this->setting('client_id'), 'code_verifier' => $transaction['verifier'],
            ]);
            $tokens = $response->json();
            if ($response->status() === 401) {
                throw new AuthenticationException('Token exchange rejected.');
            }
            if ($response->status() === 403) {
                throw new AuthorizationException('Token exchange forbidden.');
            }
            if ($response->status() >= 500) {
                throw new UpstreamException('Token endpoint unavailable.');
            }
            if (! $response->successful() || ! is_array($tokens) || ! is_string($tokens['id_token'] ?? null) || ! is_string($tokens['access_token'] ?? null) || strtolower($tokens['token_type'] ?? '') !== 'bearer') {
                throw new AuthenticationException('Invalid token response.');
            }
        } catch (ProtocolException $exception) {
            throw $exception;
        } catch (\Throwable) {
            throw new UpstreamException('Token endpoint unavailable or malformed.');
        }
        $claims = (new TokenValidator)->validate($tokens['id_token'], Http::get($metadata['jwks_uri']), $this->setting('issuer'), $this->setting('client_id'), $transaction['nonce']);
        if (array_key_exists('at_hash', $claims)) {
            $expected = rtrim(strtr(base64_encode(substr(hash('sha256', $tokens['access_token'], true), 0, 16)), '+/', '-_'), '=');
            if (! is_string($claims['at_hash']) || ! hash_equals($expected, $claims['at_hash'])) {
                throw new AuthenticationException('Access token hash mismatch.');
            }
        }
        $context = $this->bootstrap($tokens['access_token'], $claims['iss'], $claims['sub']);
        $session->regenerate(true);
        $this->notifySession('registered', $session, [
            'issuer' => $claims['iss'], 'sub' => $claims['sub'], 'sid' => $claims['sid'] ?? null,
        ], $context);
        $session->put('sso.identity', ['issuer' => $claims['iss'], 'sub' => $claims['sub'], 'sid' => $claims['sid'] ?? null, 'iat' => $claims['iat'], 'access_token' => $tokens['access_token'], 'id_token' => $tokens['id_token'], 'context' => $context->toArray()]);

        return $context;
    }

    public function bootstrap(string $accessToken, ?string $issuer = null, ?string $subject = null): BootstrapContext
    {
        return BootstrapContext::fromArray(Http::get(rtrim(Http::url($this->setting('broker_url')), '/').'/api/v1/me/bootstrap', $accessToken), $this->setting('client_id'), $issuer, $subject, (bool) config('university-sso.require_identity_binding', false));
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
        foreach (['sid', 'sub'] as $kind) {
            if (is_string($identity[$kind] ?? null)) {
                try {
                    $marker = Cache::get(BackchannelLogout::key($identity['issuer'], $kind, $identity[$kind]));
                } catch (\Throwable) {
                    throw new UpstreamException('Session revocation store unavailable.');
                }
                if ($marker !== null && ($kind === 'sid' || $identity['iat'] <= $marker)) {
                    throw new ProtocolException('Session logged out.');
                }
            }
        }
        $context = BootstrapContext::fromArray($identity['context'], config('university-sso.client_id'), $identity['issuer'], $identity['sub']);
        $status = $this->status($identity['access_token']);
        if (! is_bool($status['active'] ?? null) || ! is_string($status['university_id'] ?? null) || ! is_int($status['session_epoch'] ?? null) || ! is_int($status['authorization_version'] ?? null)) {
            throw new UpstreamException('Malformed status response.');
        }
        if ($status['active'] !== true || $status['university_id'] !== $context->id || $status['session_epoch'] !== $context->epoch || $status['authorization_version'] !== $context->authorizationVersion) {
            throw new ProtocolException('Session revoked.');
        }

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
