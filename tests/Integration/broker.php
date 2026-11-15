<?php

declare(strict_types=1);
use UniversitySso\TokenValidator;

// Test-only broker double: cryptographically validates REAL provider access tokens.
// This is not the production broker and does not test its authorization logic.
require __DIR__.'/../../examples/consumer/vendor/autoload.php';
try {
    $issuer = getenv('OIDC_ISSUER');
    $metadata = json_decode(file_get_contents($issuer.'/.well-known/openid-configuration'), true, 512, JSON_THROW_ON_ERROR);
    $keys = json_decode(file_get_contents($metadata['jwks_uri']), true, 512, JSON_THROW_ON_ERROR);
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (! str_starts_with($header, 'Bearer ')) {
        throw new RuntimeException('Missing bearer');
    }
    $claims = (new TokenValidator)->validateAccessToken(substr($header, 7), $keys, $issuer, getenv('OIDC_AUDIENCE') ?: 'sdk-broker', explode(',', getenv('OIDC_ALLOWED_PARTIES') ?: 'sdk-one,sdk-two'));
    $status = ['active' => true, 'university_id' => 'synthetic-person', 'session_epoch' => 1, 'authorization_version' => 1];
    header('Content-Type: application/json');
    if (str_ends_with($_SERVER['REQUEST_URI'], '/status')) {
        echo json_encode($status, JSON_THROW_ON_ERROR);
    } else {
        echo json_encode(['authenticated' => true, 'identity' => ['issuer' => $claims['iss'], 'subject' => $claims['sub']], 'user' => ['university_id' => 'synthetic-person'], 'application' => ['client_id' => $claims['azp'], 'allowed' => true, 'roles' => ['reader'], 'permissions' => ['read']], 'security' => ['session_epoch' => 1, 'authorization_version' => 1]], JSON_THROW_ON_ERROR);
    }
} catch (Throwable) {
    http_response_code(401);
    echo '{"message":"Invalid access token"}';
}
