<?php

declare(strict_types=1);

namespace UniversitySso;

use Illuminate\Support\ServiceProvider;

final class SsoServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/university-sso.php', 'university-sso');
        $this->app->singleton(Sso::class);
        $this->app->bind(Contracts\BrokerClient::class, fn () => $this->app->make(Sso::class));
        $this->app->bind(AccessTokenValidator::class, TokenValidator::class);
    }

    public function boot(): void
    {
        $this->publishes([__DIR__.'/../config/university-sso.php' => config_path('university-sso.php')], 'university-sso-config');
        $this->app['router']->aliasMiddleware('sso', Middleware\EnsureSso::class);
        $this->app['router']->aliasMiddleware('university.auth', Middleware\EnsureSso::class);
        $this->app['router']->aliasMiddleware('university.session-valid', Middleware\EnsureSso::class);
        $this->app['router']->aliasMiddleware('university.permission', Middleware\RequirePermission::class);
        $this->app['router']->aliasMiddleware('university.role', Middleware\RequireRole::class);
        $this->app['router']->aliasMiddleware('university.context', Middleware\RequireContext::class);
    }
}
