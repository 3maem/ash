<?php

declare(strict_types=1);

namespace Ash\Core\Exceptions;

use Ash\Core\AshErrorCode;
use Exception;

/**
 * Base class for all ASH errors.
 */
class AshException extends Exception
{
    public function __construct(
        public readonly AshErrorCode $code,
        public readonly int $httpStatus,
        string $message = 'ASH error',
    ) {
        parent::__construct($message);
    }
}
