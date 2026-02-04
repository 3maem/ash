"""
ASH Secure Memory Module

Provides secure handling of sensitive data with automatic memory clearing.
Prevents secrets from lingering in memory after use.

Security Properties:
- Zeros memory on deletion/context exit
- Prevents accidental string conversion
- Works with context managers for guaranteed cleanup
"""

import ctypes
import secrets
from typing import Union


def secure_zero_memory(data: Union[bytearray, memoryview]) -> None:
    """
    Securely zero out memory containing sensitive data.

    Uses ctypes.memset to ensure the compiler doesn't optimize away
    the memory clearing operation.

    Args:
        data: Mutable bytes-like object to clear
    """
    if isinstance(data, memoryview):
        # Get the underlying buffer
        buf = data.obj
        if isinstance(buf, bytearray):
            addr = ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))
            ctypes.memset(addr, 0, len(buf))
    elif isinstance(data, bytearray):
        addr = ctypes.addressof((ctypes.c_char * len(data)).from_buffer(data))
        ctypes.memset(addr, 0, len(data))


class SecureBytes:
    """
    A secure container for sensitive byte data that automatically
    clears memory when deleted or when exiting a context manager.

    Example:
        with SecureBytes(secret_key) as key:
            result = hmac.new(key.get(), message, 'sha256')
        # Memory is automatically cleared here

    Example without context manager:
        key = SecureBytes(secret_data)
        try:
            use_key(key.get())
        finally:
            key.clear()
    """

    __slots__ = ('_data', '_cleared')

    def __init__(self, data: Union[bytes, bytearray, str, None] = None, length: int = 32):
        """
        Initialize secure bytes container.

        Args:
            data: Initial data (bytes, bytearray, or hex string)
            length: Length for random generation if data is None
        """
        self._cleared = False

        if data is None:
            # Generate random secure bytes
            self._data = bytearray(secrets.token_bytes(length))
        elif isinstance(data, str):
            # Assume hex string
            self._data = bytearray(bytes.fromhex(data))
        elif isinstance(data, bytes):
            self._data = bytearray(data)
        elif isinstance(data, bytearray):
            self._data = bytearray(data)  # Make a copy
        else:
            raise TypeError(f"Unsupported data type: {type(data)}")

    def get(self) -> bytes:
        """Get the data as bytes. Raises if already cleared."""
        if self._cleared:
            raise ValueError("SecureBytes has been cleared")
        return bytes(self._data)

    def get_bytearray(self) -> bytearray:
        """Get a reference to the internal bytearray. Use with caution."""
        if self._cleared:
            raise ValueError("SecureBytes has been cleared")
        return self._data

    def to_hex(self) -> str:
        """Get the data as a hex string. Raises if already cleared."""
        if self._cleared:
            raise ValueError("SecureBytes has been cleared")
        return self._data.hex()

    def clear(self) -> None:
        """Securely clear the memory."""
        if not self._cleared:
            secure_zero_memory(self._data)
            self._cleared = True

    def __enter__(self) -> 'SecureBytes':
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - always clears memory."""
        self.clear()

    def __del__(self) -> None:
        """Destructor - clears memory if not already cleared."""
        self.clear()

    def __len__(self) -> int:
        """Return length of data."""
        if self._cleared:
            return 0
        return len(self._data)

    def __repr__(self) -> str:
        """Safe representation that doesn't expose data."""
        if self._cleared:
            return "SecureBytes(<cleared>)"
        return f"SecureBytes(<{len(self._data)} bytes>)"

    def __str__(self) -> str:
        """Prevent accidental string conversion."""
        return repr(self)

    # Prevent pickling which would expose data
    def __getstate__(self):
        raise TypeError("SecureBytes cannot be pickled")

    def __setstate__(self, state):
        raise TypeError("SecureBytes cannot be unpickled")


class SecureString:
    """
    A secure container for sensitive string data (like client secrets)
    that automatically clears memory when deleted.

    Example:
        with SecureString(client_secret) as secret:
            proof = build_proof(secret.get(), timestamp, binding, body_hash)
        # Memory is automatically cleared here
    """

    __slots__ = ('_data', '_cleared')

    def __init__(self, data: str):
        """
        Initialize secure string container.

        Args:
            data: String data to protect
        """
        self._cleared = False
        # Store as bytearray for secure clearing
        self._data = bytearray(data.encode('utf-8'))

    def get(self) -> str:
        """Get the string. Raises if already cleared."""
        if self._cleared:
            raise ValueError("SecureString has been cleared")
        return self._data.decode('utf-8')

    def clear(self) -> None:
        """Securely clear the memory."""
        if not self._cleared:
            secure_zero_memory(self._data)
            self._cleared = True

    def __enter__(self) -> 'SecureString':
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - always clears memory."""
        self.clear()

    def __del__(self) -> None:
        """Destructor - clears memory if not already cleared."""
        self.clear()

    def __len__(self) -> int:
        """Return length of string."""
        if self._cleared:
            return 0
        return len(self._data)

    def __repr__(self) -> str:
        """Safe representation that doesn't expose data."""
        if self._cleared:
            return "SecureString(<cleared>)"
        return f"SecureString(<{len(self._data)} bytes>)"

    def __str__(self) -> str:
        """Prevent accidental string conversion."""
        return repr(self)


def secure_derive_client_secret(nonce: Union[str, SecureBytes],
                                 context_id: str,
                                 binding: str) -> SecureString:
    """
    Derive client secret with secure memory handling.

    Returns a SecureString that will automatically clear memory when done.

    Example:
        with secure_derive_client_secret(nonce, ctx_id, binding) as secret:
            proof = build_proof_v21(secret.get(), timestamp, binding, body_hash)
        # Secret is automatically cleared

    Args:
        nonce: Server nonce (hex string or SecureBytes)
        context_id: Context identifier
        binding: Request binding

    Returns:
        SecureString containing the derived client secret
    """
    import hashlib
    import hmac

    # Get nonce bytes
    if isinstance(nonce, SecureBytes):
        nonce_bytes = nonce.get()
    elif isinstance(nonce, str):
        nonce_bytes = bytes.fromhex(nonce)
    else:
        nonce_bytes = nonce

    # Derive secret
    message = f"{context_id}|{binding}".encode('utf-8')
    secret = hmac.new(nonce_bytes, message, hashlib.sha256).hexdigest()

    return SecureString(secret)


__all__ = [
    'secure_zero_memory',
    'SecureBytes',
    'SecureString',
    'secure_derive_client_secret',
]
