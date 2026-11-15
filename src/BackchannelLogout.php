<?php

declare(strict_types=1);

namespace UniversitySso;

use Illuminate\Support\Facades\Cache;

final class BackchannelLogout
{
    public static function key(string $issuer, string $kind, string $value): string
    {
        return 'sso:logout:'.hash('sha256', $issuer.'|'.$kind.'|'.$value);
    }

    public function handle(string $token): void
    {
        $sso = app(Sso::class);
        $metadata = $sso->metadata();
        $claims = (new TokenValidator)->validate($token, Http::get($metadata['jwks_uri']), config('university-sso.issuer'), config('university-sso.client_id'), logout: true);
        $replay = self::key($claims['iss'], 'jti', $claims['jti']);
        $kind = isset($claims['sid']) ? 'sid' : 'sub';
        $key = self::key($claims['iss'], $kind, $claims[$kind]);
        Cache::lock($key.':lock', 10)->block(3, function () use ($key, $claims, $replay): void {
            if (Cache::has($replay)) {
                return;
            }
            Cache::put($key, max((int) Cache::get($key, 0), $claims['iat']), (int) config('university-sso.logout_retention', 86400));
            Cache::put($replay, true, 600);
        });
    }
}
