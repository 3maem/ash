<?php

declare(strict_types=1);

namespace Ash\Core\Exceptions;

use Ash\Core\AshErrorCode;

/**
 * Proof verification failed - payload may have been tampered.
 */
class IntegrityFailedException extends AshException
{
    public function __construct(string $message = 'Proof verification failed - payload may have been tampered')
    {
        parent::__construct(AshErrorCode::ProofInvalid, $message);
    }
}
