<?php

declare(strict_types=1);

return [
    'issuer' => env('SSO_ISSUER'),
    'client_id' => env('SSO_CLIENT_ID'),
    'client_secret' => env('SSO_CLIENT_SECRET'),
    'redirect_uri' => env('SSO_REDIRECT_URI'),
    'broker_url' => env('SSO_BROKER_URL'),
    'scopes' => ['openid'],
    'allowed_hosts' => [],
    'require_identity_binding' => false,
    'logout_retention' => 86400,
    'post_logout_redirect_uri' => env('SSO_POST_LOGOUT_REDIRECT_URI'),
    'timeout' => 5,
    'transaction_ttl' => 300,
];
