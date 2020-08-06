"""Test issued JWT content."""
import jwt

import pytest

from app.main.api.user.models import User
from app.main.api.user.enum import Role
from app.test.util import authenticate_user, API_URL_BASE

AUTH_ENDPOINT = f"{API_URL_BASE}/auth/token"


@pytest.mark.parametrize("role", [Role.USER, Role.OPERATOR])
def test_role_claim(db, client, role):
    """JWT role claim should match user's role."""
    # create user
    User.create(
        username="foo",
        email="foo@bar.com",
        password="password",
        role=role,
        active=True,
    )
    # authenticate
    access_token, _ = authenticate_user(client, "foo@bar.com", "password")
    claims = jwt.decode(access_token, verify=False)
    assert claims["user_claims"]["role"] == role.value
