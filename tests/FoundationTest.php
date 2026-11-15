<?php

declare(strict_types=1);

namespace UniversitySso\Tests;

use Orchestra\Testbench\TestCase;
use UniversitySso\SsoServiceProvider;

final class FoundationTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [SsoServiceProvider::class];
    }

    public function test_configuration_and_middleware_are_registered(): void
    {
        self::assertSame(5, config('university-sso.timeout'));
        self::assertArrayHasKey('sso', app('router')->getMiddleware());
    }
}
