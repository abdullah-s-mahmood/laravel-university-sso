<?php

declare(strict_types=1);

namespace UniversitySso;

interface AccessTokenValidator
{
    public function validateAccessToken(string $jwt, array $keys, string $issuer, string $audience, array $allowedParties, string $tokenType = 'Bearer'): array;
}
