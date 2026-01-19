<?php

declare(strict_types=1);

namespace Ash\Core;

/**
 * Security modes for ASH protocol.
 */
enum AshMode: string
{
    case Minimal = 'minimal';
    case Balanced = 'balanced';
    case Strict = 'strict';
}
