<?php

declare(strict_types=1);

namespace UniversitySso\Facades;

use Illuminate\Support\Facades\Facade;

/** @mixin \UniversitySso\Sso */
final class Sso extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \UniversitySso\Sso::class;
    }
}
