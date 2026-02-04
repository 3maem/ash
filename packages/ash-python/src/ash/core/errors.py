"""ASH Protocol Errors.

v2.3.4: Uses unique HTTP status codes in the 450-499 range for ASH-specific errors.
This enables precise error identification, better monitoring, and targeted retry logic.

Error Categories:
- 450-459: Context errors
- 460-469: Seal/Proof errors
- 461, 473-479: Binding/Verification errors
- 480-489: Format/Protocol errors
"""

from typing import Optional

from ash.core.types import AshErrorCode


class AshError(Exception):
    """Base class for all ASH errors."""

    code: AshErrorCode
    http_status: int

    def __init__(self, message: Optional[str] = None):
        self.message = message or self.__class__.__doc__ or "ASH error"
        super().__init__(self.message)


# Context errors (450-459)

class InvalidContextError(AshError):
    """Context not found or invalid."""

    code: AshErrorCode = "ASH_CTX_NOT_FOUND"
    http_status = 450


class ContextExpiredError(AshError):
    """Context has expired."""

    code: AshErrorCode = "ASH_CTX_EXPIRED"
    http_status = 451


class ReplayDetectedError(AshError):
    """Request replay detected - context already consumed."""

    code: AshErrorCode = "ASH_CTX_ALREADY_USED"
    http_status = 452


# Seal/Proof errors (460-469)

class IntegrityFailedError(AshError):
    """Proof verification failed - payload may have been tampered."""

    code: AshErrorCode = "ASH_PROOF_INVALID"
    http_status = 460


# Verification errors (461, 473-479)

class BindingMismatchError(AshError):
    """IP/User binding mismatch - context stolen or session hijacked."""

    code: AshErrorCode = "ASH_BINDING_MISMATCH"
    http_status = 461


# Alias for backward compatibility
EndpointMismatchError = BindingMismatchError


class ScopeMismatchError(AshError):
    """Scope hash mismatch."""

    code: AshErrorCode = "ASH_SCOPE_MISMATCH"
    http_status = 473


class ChainBrokenError(AshError):
    """Chain verification failed."""

    code: AshErrorCode = "ASH_CHAIN_BROKEN"
    http_status = 474


# Format/Protocol errors (480-489)

class TimestampInvalidError(AshError):
    """Timestamp validation failed."""

    code: AshErrorCode = "ASH_TIMESTAMP_INVALID"
    http_status = 482


class ProofMissingError(AshError):
    """Required proof not provided."""

    code: AshErrorCode = "ASH_PROOF_MISSING"
    http_status = 483


# Standard HTTP codes (preserved for semantic clarity)

class CanonicalizationError(AshError):
    """Failed to canonicalize payload."""

    code: AshErrorCode = "ASH_CANONICALIZATION_ERROR"
    http_status = 422


class UnsupportedContentTypeError(AshError):
    """Content type not supported by ASH protocol."""

    code: AshErrorCode = "ASH_UNSUPPORTED_CONTENT_TYPE"
    http_status = 415


class ValidationError(AshError):
    """Input validation failed."""

    code: AshErrorCode = "ASH_VALIDATION_ERROR"
    http_status = 400
