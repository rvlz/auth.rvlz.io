"""Test refresh token."""
import json

import pytest

from app.main.api.user.models import User
from app.test.util import authenticate_user, API_URL_BASE

REFRESH_ENDPOINT = f"{API_URL_BASE}/auth/refresh"


def test_refresh_token(db, client):
    """Client can refresh access token."""
    User.create(
        username="foo", email="foo@bar.com", password="password", active=True,
    )
    access_token, refresh_token = authenticate_user(
        client, "foo@bar.com", "password",
    )
    response = client.post(
        REFRESH_ENDPOINT, headers={"Authorization": f"Bearer {refresh_token}"},
    )
    refreshed_access_token = json.loads(response.data).get("access_token")
    assert response.status_code == 200
    assert refreshed_access_token is not None
    assert refreshed_access_token != access_token


@pytest.mark.parametrize("role", ["user", "operator"])
@pytest.mark.parametrize("token_type", ["refresh"])
def test_expired_token(db, client, expired_token):
    """Client cannot access endpoint with expired token."""
    response = client.post(
        REFRESH_ENDPOINT, headers={"Authorization": f"Bearer {expired_token}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 401
    assert data.get("message") == "Action unauthorized"
    assert data.get("description") == "Token has expired."


@pytest.mark.parametrize("headers", [{"Authorization": ""}, {}])
def test_missing_token(db, client, headers):
    """Client must provide endpoint a token."""
    response = client.post(REFRESH_ENDPOINT, headers=headers)
    data = json.loads(response.data)
    assert response.status_code == 401
    assert data.get("message") == "Action unauthorized"
    assert data.get("description") == "Missing Authorization Header."


def test_wrong_token(db, client):
    """Client cannot use access token as refresh token."""
    User.create(
        username="foo", email="foo@bar.com", password="password", active=True,
    )
    access_token, refresh_token = authenticate_user(
        client, "foo@bar.com", "password",
    )
    response = client.post(
        REFRESH_ENDPOINT, headers={"Authorization": f"Bearer {access_token}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Action unauthorized"
    assert data.get("description") == "Only refresh tokens are allowed."


@pytest.mark.parametrize("bad_jwt", ["", "random string!"])
def test_invalid_jwt(db, client, bad_jwt):
    """Client must provide endpoint a valid JWT."""
    response = client.post(
        REFRESH_ENDPOINT, headers={"Authorization": f"Bearer {bad_jwt}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Action unauthorized"
    assert (
        data.get("description")
        == "Bad Authorization header. Expected value 'Bearer <JWT>'."
    )
