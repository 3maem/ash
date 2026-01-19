<?php

declare(strict_types=1);

namespace Ash\Core\Exceptions;

use Ash\Core\AshErrorCode;

/**
 * Context not found or invalid.
 */
class InvalidContextException extends AshException
{
    public function __construct(string $message = 'Context not found or invalid')
    {
        parent::__construct(AshErrorCode::InvalidContext, 401, $message);
    }
}
