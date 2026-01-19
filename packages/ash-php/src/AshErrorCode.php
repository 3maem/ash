<?php

declare(strict_types=1);

namespace Ash;

/**
 * ASH error codes.
 */
enum AshErrorCode: string
{
    case InvalidContext = 'INVALID_CONTEXT';
    case ContextExpired = 'CONTEXT_EXPIRED';
    case ReplayDetected = 'REPLAY_DETECTED';
    case IntegrityFailed = 'INTEGRITY_FAILED';
    case EndpointMismatch = 'ENDPOINT_MISMATCH';
    case ModeViolation = 'MODE_VIOLATION';
    case UnsupportedContentType = 'UNSUPPORTED_CONTENT_TYPE';
    case MalformedRequest = 'MALFORMED_REQUEST';
    case CanonicalizationFailed = 'CANONICALIZATION_FAILED';
}
