import pytest
from app.core.auth import verify_client_api_key, verify_admin_api_key
from app.core.errors import UnauthorizedException
from fastapi.security import HTTPAuthorizationCredentials


@pytest.mark.asyncio
async def test_auth_valid_bearer_token():
    auth_cred = HTTPAuthorizationCredentials(scheme="Bearer", credentials="sk-argus-test-client-key-1")
    key = await verify_client_api_key(authorization=auth_cred, x_api_key=None, api_key_query=None)
    assert key == "sk-argus-test-client-key-1"


@pytest.mark.asyncio
async def test_auth_valid_x_api_key_header():
    key = await verify_client_api_key(authorization=None, x_api_key="sk-argus-admin-master-key", api_key_query=None)
    assert key == "sk-argus-admin-master-key"


@pytest.mark.asyncio
async def test_auth_missing_key_raises():
    with pytest.raises(UnauthorizedException):
        await verify_client_api_key(authorization=None, x_api_key=None, api_key_query=None)


@pytest.mark.asyncio
async def test_auth_invalid_key_raises():
    with pytest.raises(UnauthorizedException):
        await verify_client_api_key(authorization=None, x_api_key="invalid-bogus-key", api_key_query=None)


@pytest.mark.asyncio
async def test_admin_auth_success_and_failure():
    admin_key = await verify_admin_api_key(authorization=None, x_api_key="sk-argus-admin-master-key", api_key_query=None)
    assert admin_key == "sk-argus-admin-master-key"

    with pytest.raises(UnauthorizedException):
        await verify_admin_api_key(authorization=None, x_api_key="sk-argus-test-client-key-1", api_key_query=None)
