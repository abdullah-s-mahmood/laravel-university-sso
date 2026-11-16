<?php

declare(strict_types=1);

namespace UniversitySso\Facades;

use Illuminate\Support\Facades\Facade;
use UniversitySso\Sso;

/** @mixin Sso */
final class UniversityIdentity extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return Sso::class;
    }
}
