<?php

declare(strict_types=1);

namespace Ash\Core\Exceptions;

use Ash\Core\AshErrorCode;

/**
 * Request replay detected - context already consumed.
 */
class ReplayDetectedException extends AshException
{
    public function __construct(string $message = 'Request replay detected - context already consumed')
    {
        parent::__construct(AshErrorCode::CtxAlreadyUsed, $message);
    }
}
