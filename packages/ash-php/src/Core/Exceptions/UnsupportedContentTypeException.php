<?php

declare(strict_types=1);

namespace Ash\Core\Exceptions;

use Ash\Core\AshErrorCode;

/**
 * Content type not supported by ASH protocol.
 */
class UnsupportedContentTypeException extends AshException
{
    public function __construct(string $message = 'Content type not supported by ASH protocol')
    {
        parent::__construct(AshErrorCode::UnsupportedContentType, 415, $message);
    }
}
