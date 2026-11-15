<?php

declare(strict_types=1);

namespace UniversitySso\Contracts;

interface IdentityContext
{
    public function universityId(): string;

    public function person(): array;

    public function activeContext(): ?array;

    public function roles(): array;

    public function permissions(): array;

    public function applications(): array;

    public function can(string $permission): bool;

    public function toArray(): array;
}
