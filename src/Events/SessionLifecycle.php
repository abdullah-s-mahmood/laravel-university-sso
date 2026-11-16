<?php

declare(strict_types=1);

namespace UniversitySso\Events;

/** Token-free notification for consumer-owned registry/audit listeners. */
final readonly class SessionLifecycle
{
    public array $identity;

    public function __construct(public string $operation, array $identity)
    {
        $this->identity = array_intersect_key($identity, array_flip([
            'issuer', 'client_id', 'subject', 'sid', 'session_reference',
            'previous_session_reference', 'university_id', 'session_epoch', 'authorization_version', 'expires_at',
        ]));
    }
}
