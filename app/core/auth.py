import secrets
from typing import Optional
from fastapi import Header, Query, Request, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from app.config import settings
from app.core.errors import UnauthorizedException

api_key_header_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)
http_bearer_scheme = HTTPBearer(auto_error=False)


def extract_api_key(
    authorization: Optional[HTTPAuthorizationCredentials] = Security(http_bearer_scheme),
    x_api_key: Optional[str] = Security(api_key_header_scheme),
    api_key_query: Optional[str] = Query(None, alias="api_key"),
) -> Optional[str]:
    """Extract API key from Bearer token, X-API-Key header, or query param."""
    if authorization and authorization.credentials:
        return authorization.credentials.strip()
    if x_api_key:
        return x_api_key.strip()
    if api_key_query:
        return api_key_query.strip()
    return None


async def verify_client_api_key(
    authorization: Optional[HTTPAuthorizationCredentials] = Security(http_bearer_scheme),
    x_api_key: Optional[str] = Security(api_key_header_scheme),
    api_key_query: Optional[str] = Query(None, alias="api_key"),
) -> str:
    """Verify that incoming request provides a valid Gateway API key."""
    key = extract_api_key(authorization, x_api_key, api_key_query)
    if not key:
        raise UnauthorizedException("Missing Gateway API key. Provide via 'Authorization: Bearer <key>' or 'X-API-Key'.")

    valid_keys = settings.valid_api_keys
    # Constant-time comparison against each key to prevent timing attacks
    match = any(secrets.compare_digest(key, vk) for vk in valid_keys)
    if not match:
        raise UnauthorizedException("Invalid Gateway API key provided.")

    return key


async def verify_admin_api_key(
    authorization: Optional[HTTPAuthorizationCredentials] = Security(http_bearer_scheme),
    x_api_key: Optional[str] = Security(api_key_header_scheme),
    api_key_query: Optional[str] = Query(None, alias="api_key"),
) -> str:
    """Verify administrator permissions for sensitive admin and policy endpoints."""
    key = extract_api_key(authorization, x_api_key, api_key_query)
    if not key:
        raise UnauthorizedException("Admin authentication required.")

    admin_key = settings.ARGUS_ADMIN_API_KEY
    if not secrets.compare_digest(key, admin_key):
        raise UnauthorizedException("Invalid Admin API key.")

    return key
