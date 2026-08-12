"""
AgentShield Security Package (SSRF Protection, API Key Auth, Rate Limiting)
"""

from app.security.auth import (
    APIKeyAuthenticator,
    extract_api_key,
    get_api_key_authenticator,
    require_api_key,
    set_api_key_authenticator,
)
from app.security.rate_limit import (
    InMemoryRateLimiter,
    get_rate_limiter,
    require_rate_limit,
    set_rate_limiter,
)
from app.security.ssrf import SSRFPolicy, SSRFValidator, default_dns_resolver

__all__ = [
    "SSRFPolicy",
    "SSRFValidator",
    "default_dns_resolver",
    "APIKeyAuthenticator",
    "extract_api_key",
    "get_api_key_authenticator",
    "require_api_key",
    "set_api_key_authenticator",
    "InMemoryRateLimiter",
    "require_rate_limit",
    "set_rate_limiter",
    "get_rate_limiter",
]
