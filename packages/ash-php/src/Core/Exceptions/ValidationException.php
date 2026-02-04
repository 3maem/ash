<?php

declare(strict_types=1);

namespace Ash\Core\Exceptions;

use Ash\Core\AshErrorCode;

/**
 * Input validation failed.
 */
class ValidationException extends AshException
{
    public function __construct(string $message = 'Input validation failed')
    {
        parent::__construct(AshErrorCode::ValidationError, $message);
    }
}
