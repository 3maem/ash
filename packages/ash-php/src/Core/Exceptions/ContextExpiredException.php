<?php

declare(strict_types=1);

namespace Ash\Core\Exceptions;

use Ash\Core\AshErrorCode;

/**
 * Context has expired.
 */
class ContextExpiredException extends AshException
{
    public function __construct(string $message = 'Context has expired')
    {
        parent::__construct(AshErrorCode::CtxExpired, $message);
    }
}
