<?php

declare(strict_types=1);

namespace UniversitySso;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

final class TokenValidator implements AccessTokenValidator
{
    public function validate(string $jwt, array $keys, string $issuer, string $client, ?string $nonce = null, bool $logout = false): array
    {
        try {
            $claims = $this->decode($jwt, $keys);
            $aud = $claims['aud'] ?? [];
            $aud = is_string($aud) ? [$aud] : $aud;
            if (($claims['iss'] ?? null) !== $issuer || ! is_array($aud) || ! in_array($client, $aud, true) || (! $logout && ! is_int($claims['exp'] ?? null)) || (array_key_exists('exp', $claims) && (! is_int($claims['exp']) || $claims['exp'] <= time())) || ! is_int($claims['iat'] ?? null) || $claims['iat'] > time()) {
                throw new ProtocolException('Invalid claims.');
            }
            if (! $logout && count($aud) > 1 && ($claims['azp'] ?? null) !== $client) {
                throw new ProtocolException('Invalid authorized party.');
            }
            if (isset($claims['azp']) && $claims['azp'] !== $client) {
                throw new ProtocolException('Invalid authorized party.');
            }
            if ($logout) {
                $events = (array) ($claims['events'] ?? []);
                if (! is_object($claims['events'] ?? null) || ! is_object($events['http://schemas.openid.net/event/backchannel-logout'] ?? null) || array_key_exists('nonce', $claims) || ! is_string($claims['jti'] ?? null) || $claims['jti'] === '' || (array_key_exists('sid', $claims) && (! is_string($claims['sid']) || $claims['sid'] === '')) || (array_key_exists('sub', $claims) && (! is_string($claims['sub']) || $claims['sub'] === '')) || ((! is_string($claims['sid'] ?? null) || $claims['sid'] === '') && (! is_string($claims['sub'] ?? null) || $claims['sub'] === '')) || $claims['iat'] < time() - 300) {
                    throw new ProtocolException('Invalid logout token.');
                }
            } elseif (! is_string($claims['sub'] ?? null) || $claims['sub'] === '' || $nonce === null || ! is_string($claims['nonce'] ?? null) || ! hash_equals($nonce, $claims['nonce'])) {
                throw new ProtocolException('Invalid identity or nonce.');
            }

            return $claims;
        } catch (\Throwable) {
            throw new ProtocolException('Token validation failed.');
        }
    }

    private function decode(string $jwt, array $keys): array
    {
        // Only RSA SHA-256 keys are accepted; never infer an algorithm from a token.
        $filtered = array_values(array_filter($keys['keys'] ?? [], static fn ($key) => is_array($key) && ($key['kty'] ?? '') === 'RSA' && ($key['alg'] ?? 'RS256') === 'RS256' && ($key['use'] ?? 'sig') === 'sig'));
        $claims = (array) JWT::decode($jwt, JWK::parseKeySet(['keys' => $filtered], 'RS256'));

        return $claims;
    }

    public function validateAccessToken(string $jwt, array $keys, string $issuer, string $audience, array $allowedParties, string $tokenType = 'Bearer'): array
    {
        try {
            $claims = $this->decode($jwt, $keys);
            $aud = $claims['aud'] ?? [];
            $aud = is_string($aud) ? [$aud] : $aud;
            if ($allowedParties === [] || ($claims['iss'] ?? null) !== $issuer || ! is_array($aud) || ! in_array($audience, $aud, true) || ! is_string($claims['azp'] ?? null) || ! in_array($claims['azp'], $allowedParties, true) || ($claims['typ'] ?? null) !== $tokenType || ! is_string($claims['sub'] ?? null) || $claims['sub'] === '' || ! is_int($claims['exp'] ?? null) || $claims['exp'] <= time() || ! is_int($claims['iat'] ?? null) || $claims['iat'] > time()) {
                throw new AuthenticationException('Invalid access token.');
            }

            return $claims;
        } catch (\Throwable) {
            throw new AuthenticationException('Access token validation failed.');
        }
    }
}
