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
    public readonly AshErrorCode $errorCode;
    public readonly int $httpStatus;

    public function __construct(
        AshErrorCode $errorCode,
        string $message = 'ASH error',
    ) {
        parent::__construct($message);
        $this->errorCode = $errorCode;
        $this->httpStatus = $errorCode->httpStatus();
    }
}
