<?php

declare(strict_types=1);

namespace UniversitySso;

use Illuminate\Support\Facades\Http as Client;

final class Http
{
    public static function url(string $url): string
    {
        $parts = parse_url($url);
        if (! is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host']) || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])) {
            throw new ProtocolException('An absolute HTTPS endpoint is required.');
        }

        $allowed = config('university-sso.allowed_hosts', []);
        if ($allowed !== [] && ! in_array($parts['host'], $allowed, true)) {
            throw new ProtocolException('Endpoint host is not allowed.');
        }

        return $url;
    }

    public static function get(string $url, ?string $token = null): array
    {
        try {
            $request = Client::acceptJson()->timeout((int) config('university-sso.timeout', 5))->connectTimeout(3)->withOptions(['allow_redirects' => false]);
            if ($token !== null) {
                $request = $request->withToken($token);
            }
            $response = $request->retry(2, 100, throw: false)->get(self::url($url));
            if ($response->status() === 401) {
                throw new AuthenticationException('Authentication rejected.');
            }
            if ($response->status() === 403) {
                throw new AuthorizationException('Access denied.');
            }
            if (! $response->successful() || ! is_array($response->json())) {
                throw new UpstreamException('Remote service unavailable or malformed.');
            }

            return $response->json();
        } catch (ProtocolException $exception) {
            throw $exception;
        } catch (\Throwable) {
            throw new UpstreamException('Remote service unavailable or invalid.');
        }
    }
}
