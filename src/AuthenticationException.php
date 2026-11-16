<?php

declare(strict_types=1);

namespace UniversitySso;

use Firebase\JWT\SignatureInvalidException;

final class AuthenticationException extends ProtocolException
{
    /** A bounded JWKS refetch may help; this never permits skipping validation. */
    public function shouldRefreshJwks(): bool
    {
        $cause = $this->getPrevious();

        return $cause instanceof SignatureInvalidException
            || ($cause instanceof \UnexpectedValueException
                && $cause->getMessage() === '"kid" invalid, unable to lookup correct key');
    }
}
