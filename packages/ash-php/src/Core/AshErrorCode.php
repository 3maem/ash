<?php

declare(strict_types=1);

namespace Ash\Core;

/**
 * Error codes returned by ASH verification.
 */
enum AshErrorCode: string
{
    case InvalidContext = 'ASH_INVALID_CONTEXT';
    case ContextExpired = 'ASH_CONTEXT_EXPIRED';
    case ReplayDetected = 'ASH_REPLAY_DETECTED';
    case IntegrityFailed = 'ASH_INTEGRITY_FAILED';
    case EndpointMismatch = 'ASH_ENDPOINT_MISMATCH';
    case ModeViolation = 'ASH_MODE_VIOLATION';
    case UnsupportedContentType = 'ASH_UNSUPPORTED_CONTENT_TYPE';
    case MalformedRequest = 'ASH_MALFORMED_REQUEST';
    case CanonicalizationFailed = 'ASH_CANONICALIZATION_FAILED';
}
