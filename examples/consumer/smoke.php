<?php

declare(strict_types=1);
use UniversitySso\BootstrapContext;

require __DIR__.'/vendor/autoload.php';
$context = BootstrapContext::fromArray([
    'authenticated' => true, 'user' => ['university_id' => 'synthetic-person'],
    'application' => ['allowed' => true, 'client_id' => 'demo', 'permissions' => ['read']],
    'security' => ['session_epoch' => 1, 'authorization_version' => 1],
], 'demo');
if (! $context->can('read') || $context->can('write')) {
    throw new RuntimeException('Consumer DTO failed');
}
echo "Independent Composer consumer passed.\n";
