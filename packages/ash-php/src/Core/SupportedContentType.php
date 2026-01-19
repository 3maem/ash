<?php

declare(strict_types=1);

namespace Ash\Core;

/**
 * Supported content types for ASH protocol.
 */
enum SupportedContentType: string
{
    case Json = 'application/json';
    case UrlEncoded = 'application/x-www-form-urlencoded';
}
