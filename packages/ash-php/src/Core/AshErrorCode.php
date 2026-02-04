<?php

declare(strict_types=1);

namespace Ash\Core;

/**
 * Error codes returned by ASH verification.
 *
 * v2.3.4: Uses unique HTTP status codes in the 450-499 range for ASH-specific errors.
 * This enables precise error identification, better monitoring, and targeted retry logic.
 *
 * Error Categories:
 * - 450-459: Context errors
 * - 460-469: Seal/Proof errors
 * - 461, 473-479: Binding/Verification errors
 * - 480-489: Format/Protocol errors
 */
enum AshErrorCode: string
{
    // Context errors (450-459)
    case CtxNotFound = 'ASH_CTX_NOT_FOUND';
    case CtxExpired = 'ASH_CTX_EXPIRED';
    case CtxUsed = 'ASH_CTX_USED';
    case CtxAlreadyUsed = 'ASH_CTX_ALREADY_USED';

    // Seal/Proof errors (460-469)
    case ProofInvalid = 'ASH_PROOF_INVALID';

    // Binding/Verification errors (461, 473-479)
    case BindingMismatch = 'ASH_BINDING_MISMATCH';
    case ScopeMismatch = 'ASH_SCOPE_MISMATCH';
    case ChainBroken = 'ASH_CHAIN_BROKEN';

    // Format/Protocol errors (480-489)
    case TimestampInvalid = 'ASH_TIMESTAMP_INVALID';
    case ProofMissing = 'ASH_PROOF_MISSING';

    // Standard HTTP codes (preserved for semantic clarity)
    case CanonicalizationError = 'ASH_CANONICALIZATION_ERROR';
    case ModeViolation = 'ASH_MODE_VIOLATION';
    case UnsupportedContentType = 'ASH_UNSUPPORTED_CONTENT_TYPE';
    case ValidationError = 'ASH_VALIDATION_ERROR';
    case InternalError = 'ASH_INTERNAL_ERROR';

    /**
     * Get the recommended HTTP status code for this error.
     *
     * v2.3.4: Uses unique HTTP status codes for ASH-specific errors.
     */
    public function httpStatus(): int
    {
        return match ($this) {
            // Context errors (450-459)
            self::CtxNotFound => 450,
            self::CtxExpired => 451,
            self::CtxUsed => 452,
            self::CtxAlreadyUsed => 452,
            // Seal/Proof errors (460-469)
            self::ProofInvalid => 460,
            // Verification errors (461, 473-479)
            self::BindingMismatch => 461,
            self::ScopeMismatch => 473,
            self::ChainBroken => 474,
            // Format/Protocol errors (480-489)
            self::TimestampInvalid => 482,
            self::ProofMissing => 483,
            // Standard HTTP codes (preserved for semantic clarity)
            self::CanonicalizationError => 422,
            self::ModeViolation => 400,
            self::UnsupportedContentType => 415,
            self::ValidationError => 400,
            self::InternalError => 500,
        };
    }
}
