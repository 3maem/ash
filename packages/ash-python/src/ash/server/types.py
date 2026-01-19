"""ASH Server Types."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, Literal, Optional

from ash.core.types import StoredContext, AshMode, SupportedContentType

# Result of consuming a context
ConsumeResult = Literal["consumed", "already_consumed", "missing"]


class ContextStore(ABC):
    """Abstract base class for context stores."""

    @abstractmethod
    async def put(self, ctx: StoredContext) -> None:
        """Store a context."""
        ...

    @abstractmethod
    async def get(self, context_id: str) -> Optional[StoredContext]:
        """Get a context by ID. Returns None if not found."""
        ...

    @abstractmethod
    async def consume(self, context_id: str, now_ms: int) -> ConsumeResult:
        """
        Atomically consume a context.

        Returns:
            - "consumed": Successfully consumed
            - "already_consumed": Context was already consumed
            - "missing": Context not found
        """
        ...

    async def cleanup(self) -> int:
        """
        Remove expired and consumed contexts.

        Returns:
            Number of contexts removed
        """
        return 0


@dataclass
class VerifyOptions:
    """Options for request verification."""

    expected_binding: str
    """Expected binding: 'METHOD /path'."""

    content_type: SupportedContentType = "application/json"
    """Content type of the request body."""

    extract_context_id: Optional[Callable[[Any], str]] = None
    """Function to extract context ID from request."""

    extract_proof: Optional[Callable[[Any], str]] = None
    """Function to extract proof from request."""

    extract_payload: Optional[Callable[[Any], Any]] = None
    """Function to extract payload from request."""


@dataclass
class CreateContextOptions:
    """Options for creating a context."""

    binding: str
    """Binding: 'METHOD /path'."""

    ttl_ms: int
    """Time-to-live in milliseconds."""

    mode: AshMode = "balanced"
    """Security mode."""

    issue_nonce: bool = False
    """Whether to issue a server nonce."""
