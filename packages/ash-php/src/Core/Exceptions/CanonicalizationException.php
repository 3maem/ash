<?php

declare(strict_types=1);

namespace Ash\Core\Exceptions;

use Ash\Core\AshErrorCode;

/**
 * Failed to canonicalize payload.
 */
class CanonicalizationException extends AshException
{
    public function __construct(string $message = 'Failed to canonicalize payload')
    {
        parent::__construct(AshErrorCode::CanonicalizationFailed, 400, $message);
    }
}
