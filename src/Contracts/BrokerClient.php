<?php

declare(strict_types=1);

namespace UniversitySso\Contracts;

use UniversitySso\BootstrapContext;

interface BrokerClient
{
    public function bootstrap(string $accessToken, ?string $issuer = null, ?string $subject = null): BootstrapContext;

    public function status(string $accessToken): array;
}
