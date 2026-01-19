"""ASH Protocol Errors."""

from typing import Optional

from ash.core.types import AshErrorCode


class AshError(Exception):
    """Base class for all ASH errors."""

    code: AshErrorCode
    http_status: int

    def __init__(self, message: Optional[str] = None):
        self.message = message or self.__class__.__doc__ or "ASH error"
        super().__init__(self.message)


class InvalidContextError(AshError):
    """Context not found or invalid."""

    code: AshErrorCode = "ASH_INVALID_CONTEXT"
    http_status = 401


class ContextExpiredError(AshError):
    """Context has expired."""

    code: AshErrorCode = "ASH_CONTEXT_EXPIRED"
    http_status = 401


class ReplayDetectedError(AshError):
    """Request replay detected - context already consumed."""

    code: AshErrorCode = "ASH_REPLAY_DETECTED"
    http_status = 409


class IntegrityFailedError(AshError):
    """Proof verification failed - payload may have been tampered."""

    code: AshErrorCode = "ASH_INTEGRITY_FAILED"
    http_status = 400


class EndpointMismatchError(AshError):
    """Context binding does not match requested endpoint."""

    code: AshErrorCode = "ASH_ENDPOINT_MISMATCH"
    http_status = 400


class CanonicalizationError(AshError):
    """Failed to canonicalize payload."""

    code: AshErrorCode = "ASH_CANONICALIZATION_FAILED"
    http_status = 400


class UnsupportedContentTypeError(AshError):
    """Content type not supported by ASH protocol."""

    code: AshErrorCode = "ASH_UNSUPPORTED_CONTENT_TYPE"
    http_status = 415
