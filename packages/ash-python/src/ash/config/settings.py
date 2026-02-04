"""
ASH Configuration Module (v2.3.4)

Environment-based configuration for deployment flexibility.
"""

import os
from typing import List, Optional


class AshConfig:
    """ASH configuration loaded from environment variables."""
    
    # Default values
    DEFAULT_RATE_LIMIT_WINDOW = 60
    DEFAULT_RATE_LIMIT_MAX = 10
    DEFAULT_TIMESTAMP_TOLERANCE = 30
    
    def __init__(self):
        """Initialize configuration from environment variables."""
        self._trust_proxy = self._parse_bool(
            os.environ.get('ASH_TRUST_PROXY', 'false')
        )
        self._trusted_proxies = self._parse_proxy_list(
            os.environ.get('ASH_TRUSTED_PROXIES', '')
        )
        self._rate_limit_window = int(
            os.environ.get('ASH_RATE_LIMIT_WINDOW', self.DEFAULT_RATE_LIMIT_WINDOW)
        )
        self._rate_limit_max = int(
            os.environ.get('ASH_RATE_LIMIT_MAX', self.DEFAULT_RATE_LIMIT_MAX)
        )
        self._timestamp_tolerance = int(
            os.environ.get('ASH_TIMESTAMP_TOLERANCE', self.DEFAULT_TIMESTAMP_TOLERANCE)
        )
    
    @staticmethod
    def _parse_bool(value: str) -> bool:
        """Parse boolean from string."""
        return value.lower() in ('true', '1', 'yes', 'on')
    
    @staticmethod
    def _parse_proxy_list(value: str) -> List[str]:
        """Parse comma-separated proxy list."""
        if not value:
            return []
        return [ip.strip() for ip in value.split(',') if ip.strip()]
    
    @property
    def trust_proxy(self) -> bool:
        """Whether to trust X-Forwarded-For headers."""
        return self._trust_proxy
    
    @property
    def trusted_proxies(self) -> List[str]:
        """List of trusted proxy IP addresses."""
        return self._trusted_proxies
    
    @property
    def rate_limit_window(self) -> int:
        """Rate limit window in seconds."""
        return self._rate_limit_window
    
    @property
    def rate_limit_max(self) -> int:
        """Maximum contexts per rate limit window."""
        return self._rate_limit_max
    
    @property
    def timestamp_tolerance(self) -> int:
        """Timestamp tolerance in seconds."""
        return self._timestamp_tolerance


# Global config instance (lazy-loaded)
_config: Optional[AshConfig] = None


def get_config() -> AshConfig:
    """Get the global ASH configuration instance."""
    global _config
    if _config is None:
        _config = AshConfig()
    return _config


def reset_config() -> None:
    """Reset the configuration (useful for testing)."""
    global _config
    _config = None


def get_client_ip(request_headers: Optional[dict] = None, 
                  remote_addr: Optional[str] = None) -> str:
    """
    Get client IP address with proxy support.
    
    v2.3.4: Added X-Forwarded-For handling for deployments behind proxies/CDNs.
    
    Args:
        request_headers: Dictionary of HTTP headers (case-insensitive keys)
        remote_addr: Direct remote address (fallback)
        
    Returns:
        Client IP address string
    """
    config = get_config()
    
    # If not trusting proxies, use direct connection IP
    if not config.trust_proxy:
        return remote_addr or 'unknown'
    
    if request_headers is None:
        return remote_addr or 'unknown'
    
    # Normalize header keys to lowercase for case-insensitive lookup
    headers = {k.lower(): v for k, v in request_headers.items()}
    
    # Check for X-Forwarded-For header
    forwarded_for = headers.get('x-forwarded-for')
    if forwarded_for:
        # Take the first IP in the chain
        if isinstance(forwarded_for, str):
            ips = [ip.strip() for ip in forwarded_for.split(',')]
            client_ip = ips[0]
            # Basic IP validation
            if _is_valid_ip(client_ip):
                return client_ip
    
    # Check for X-Real-IP header
    real_ip = headers.get('x-real-ip')
    if real_ip and isinstance(real_ip, str):
        if _is_valid_ip(real_ip):
            return real_ip
    
    # Fall back to direct connection IP
    return remote_addr or 'unknown'


def _is_valid_ip(ip: str) -> bool:
    """Basic IP address validation (IPv4 or IPv6)."""
    import re
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # IPv6 pattern (simplified)
    ipv6_pattern = r'^[0-9a-fA-F:]+$'
    return bool(re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip))
