<?php

declare(strict_types=1);

namespace UniversitySso;

final readonly class BootstrapContext implements Contracts\IdentityContext
{
    public function __construct(public string $id, public int $epoch, public int $authorizationVersion, public array $permissions, private array $data = [], private ?int $expiry = null) {}

    public static function fromArray(array $data, string $client, ?string $issuer = null, ?string $subject = null, bool $requireIdentityBinding = false): self
    {
        if (($data['authenticated'] ?? null) === false) {
            throw new AuthenticationException('Unauthenticated context.');
        }
        if (($data['application']['allowed'] ?? null) === false) {
            throw new AuthorizationException('Application access denied.');
        }
        if (($data['authenticated'] ?? null) !== true || ($data['application']['allowed'] ?? null) !== true || ($data['application']['client_id'] ?? null) !== $client || ! is_string($data['user']['university_id'] ?? null) || $data['user']['university_id'] === '' || ! is_int($data['security']['session_epoch'] ?? null) || $data['security']['session_epoch'] < 0 || ! is_int($data['security']['authorization_version'] ?? null) || $data['security']['authorization_version'] < 0 || ! is_array($data['application']['permissions'] ?? null)) {
            throw new UpstreamException('Invalid bootstrap context.');
        }
        if (isset($data['identity'])) {
            if (! is_array($data['identity']) || ($issuer !== null && ($data['identity']['issuer'] ?? null) !== $issuer) || ($subject !== null && ($data['identity']['subject'] ?? null) !== $subject)) {
                throw new AuthenticationException('Bootstrap identity mismatch.');
            }
        } elseif ($requireIdentityBinding && $subject !== null) {
            throw new UpstreamException('Missing bootstrap identity binding.');
        }
        foreach (['permissions', 'roles'] as $key) {
            $values = $data['application'][$key] ?? [];
            if (! is_array($values) || ! array_is_list($values)) {
                throw new UpstreamException('Invalid grants.');
            }
            foreach ($values as $value) {
                if (! is_string($value) || $value === '') {
                    throw new UpstreamException('Invalid grant.');
                }
            }
        }
        foreach (['active_context', 'applications'] as $key) {
            if (isset($data[$key]) && ! is_array($data[$key])) {
                throw new UpstreamException('Invalid context.');
            }
        }
        $expiry = null;
        if (array_key_exists('context_expires_at', $data['security'])) {
            $value = $data['security']['context_expires_at'];
            if (! is_string($value) || ! preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/D', $value)) {
                throw new UpstreamException('Invalid context expiry.');
            }
            try {
                $expiry = (new \DateTimeImmutable($value))->getTimestamp();
            } catch (\Throwable) {
                throw new UpstreamException('Invalid context expiry.');
            }
            $errors = \DateTimeImmutable::getLastErrors();
            if (is_array($errors) && ($errors['warning_count'] > 0 || $errors['error_count'] > 0)) {
                throw new UpstreamException('Invalid context expiry.');
            }
        }
        // Keep a documented non-sensitive person summary; broker must filter nested context/catalog fields.
        $safe = [
            'authenticated' => true,
            'user' => array_intersect_key($data['user'], array_flip(['university_id', 'type', 'status', 'full_name'])),
            'application' => array_intersect_key($data['application'], array_flip(['client_id', 'allowed', 'roles', 'permissions'])),
            'security' => array_intersect_key($data['security'], array_flip(['session_epoch', 'authorization_version', 'context_expires_at'])),
            'active_context' => $data['active_context'] ?? null,
            'applications' => $data['applications'] ?? [],
        ];
        if (isset($data['identity'])) {
            $safe['identity'] = $data['identity'];
        }

        return new self($data['user']['university_id'], $data['security']['session_epoch'], $data['security']['authorization_version'], $data['application']['permissions'], $safe, $expiry);
    }

    public function expiresAt(): ?int
    {
        return $this->expiry;
    }

    public function isExpired(?int $now = null): bool
    {
        return $this->expiry !== null && $this->expiry <= ($now ?? time());
    }

    public function toArray(): array
    {
        return $this->data;
    }

    public function universityId(): string
    {
        return $this->id;
    }

    public function person(): array
    {
        return $this->data['user'] ?? [];
    }

    public function activeContext(): ?array
    {
        return $this->data['active_context'] ?? null;
    }

    public function roles(): array
    {
        return $this->data['application']['roles'] ?? [];
    }

    public function permissions(): array
    {
        return $this->permissions;
    }

    public function applications(): array
    {
        return $this->data['applications'] ?? [];
    }

    public function can(string $permission): bool
    {
        return in_array($permission, $this->permissions, true);
    }
}
