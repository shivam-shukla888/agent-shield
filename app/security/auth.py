"""
API Key Authentication Infrastructure (STEP 12A)

This module defines:
1. APIKeyAuthenticator: Security component performing constant-time credential comparison.
2. set_api_key_authenticator / get_api_key_authenticator: Global dependency providers.
3. require_api_key: FastAPI dependency enforcing API key authentication on protected routes.

SECURITY INVARIANTS:
1. Uses `secrets.compare_digest` for constant-time comparison to prevent timing attacks.
2. Returns safe HTTP 401 Unauthorized errors without exposing expected credentials or internal tracebacks.
3. Allows disabling authentication when no API key is configured (for local dev / test suites).
"""

import secrets
from typing import Optional

from fastapi import HTTPException, Request, status


class APIKeyAuthenticator:
    """
    Constant-time API Key Authenticator.
    """

    def __init__(self, api_key: Optional[str] = None) -> None:
        """
        Initialize APIKeyAuthenticator with an optional configured master API key.

        Args:
            api_key (Optional[str]): The configured expected master API key string.
                If None or empty/whitespace, authentication is disabled.
        """
        clean_key = api_key.strip() if api_key else None
        self._api_key = clean_key if clean_key else None

    @property
    def is_enabled(self) -> bool:
        """
        Return True if authentication is active (master API key configured), False otherwise.
        """
        return self._api_key is not None

    def verify_key(self, provided_key: Optional[str]) -> bool:
        """
        Verify a provided API key against configured key using constant-time comparison.

        Args:
            provided_key (Optional[str]): Raw API key string provided by client request.

        Returns:
            bool: True if key is valid or authentication is disabled, False otherwise.
        """
        if not self.is_enabled:
            return True

        if not provided_key:
            return False

        clean_provided = provided_key.strip()
        if not clean_provided:
            return False

        return secrets.compare_digest(
            clean_provided.encode("utf-8"),
            self._api_key.encode("utf-8"),  # type: ignore
        )


# Global authenticator holder for FastAPI dependency injection
_authenticator_instance: Optional[APIKeyAuthenticator] = None


def set_api_key_authenticator(authenticator: APIKeyAuthenticator) -> None:
    """
    Set global APIKeyAuthenticator instance in composition root.
    """
    global _authenticator_instance
    _authenticator_instance = authenticator


def get_api_key_authenticator() -> APIKeyAuthenticator:
    """
    Dependency provider returning the configured APIKeyAuthenticator instance.
    """
    if _authenticator_instance is None:
        return APIKeyAuthenticator(api_key=None)
    return _authenticator_instance


def extract_api_key(request: Request) -> Optional[str]:
    """
    Extract API key from X-API-Key header or Authorization: Bearer <key> header.

    Args:
        request (Request): Incoming FastAPI HTTP Request.

    Returns:
        Optional[str]: Extracted API key string if present, else None.
    """
    # 1. Check X-API-Key header
    api_key_header = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
    if api_key_header and api_key_header.strip():
        return api_key_header.strip()

    # 2. Check Authorization: Bearer <token> header
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    if auth_header and auth_header.strip():
        parts = auth_header.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()

    return None


def require_api_key(request: Request) -> None:
    """
    FastAPI route dependency enforcing API key authentication.

    Raises:
        HTTPException(401): If authentication fails or key is missing.
    """
    authenticator = get_api_key_authenticator()
    if not authenticator.is_enabled:
        return

    provided_key = extract_api_key(request)
    if not authenticator.verify_key(provided_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )
