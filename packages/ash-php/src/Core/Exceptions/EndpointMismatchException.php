<?php

declare(strict_types=1);

namespace Ash\Core\Exceptions;

use Ash\Core\AshErrorCode;

/**
 * Context binding does not match requested endpoint.
 */
class EndpointMismatchException extends AshException
{
    public function __construct(string $message = 'Context binding does not match requested endpoint')
    {
        parent::__construct(AshErrorCode::BindingMismatch, $message);
    }
}
