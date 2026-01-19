"""
Base context store interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..core import AshContext, AshMode


class ContextStore(ABC):
    """
    Abstract base class for context stores.

    Implement this interface to use different storage backends
    (Redis, SQL, etc.)
    """

    @abstractmethod
    def create(
        self,
        binding: str,
        ttl_ms: int,
        mode: "AshMode",
        metadata: dict[str, Any],
    ) -> "AshContext":
        """
        Create a new context.

        Args:
            binding: Endpoint binding
            ttl_ms: Time-to-live in milliseconds
            mode: Security mode
            metadata: Optional metadata

        Returns:
            Created context
        """
        ...

    @abstractmethod
    def get(self, context_id: str) -> "AshContext | None":
        """
        Get a context by ID.

        Args:
            context_id: Context ID

        Returns:
            Context or None if not found/expired
        """
        ...

    @abstractmethod
    def consume(self, context_id: str) -> bool:
        """
        Consume a context (mark as used).

        Args:
            context_id: Context ID

        Returns:
            True if consumed, False if not found or already used
        """
        ...

    @abstractmethod
    def cleanup(self) -> int:
        """
        Clean up expired contexts.

        Returns:
            Number of contexts removed
        """
        ...
