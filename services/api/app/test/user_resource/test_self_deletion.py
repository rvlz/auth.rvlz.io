"""Test DELETE /users/self endpoint."""
import json
import pytest

from app.main.api.user.models import User
from app.test.util import authenticate_user, API_URL_BASE

USERS_ENDPOINT = f"{API_URL_BASE}/users/self"
REVOKE_ENDPOINT = f"{API_URL_BASE}/auth/revoke"


def test_deletion(db, client):
    """Client can delete current user."""
    # create user
    User.create(
        username="foo", email="foo@bar.com", password="password", active=True,
    )
    # authenticate
    access_token, _ = authenticate_user(client, "foo@bar.com", "password")
    # deletion
    response = client.delete(
        USERS_ENDPOINT, headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 204


@pytest.mark.parametrize("role,token_type", [("user", "access")])
def test_expired_token(db, client, expired_token):
    """Client cannot access endpoint with expired token."""
    # attempt deletion
    response = client.delete(
        USERS_ENDPOINT, headers={"Authorization": f"Bearer {expired_token}"}
    )
    data = json.loads(response.data)
    assert response.status_code == 401
    assert data.get("message") == "Action unauthorized"
    assert data.get("description") == "Token has expired."


@pytest.mark.parametrize("headers", [{"Authorization": ""}, {}])
def test_missing_token(db, client, headers):
    """Client must provide endpoint a token."""
    # attempt deletion
    response = client.delete(USERS_ENDPOINT, headers=headers)
    data = json.loads(response.data)
    assert response.status_code == 401
    assert data.get("message") == "Action unauthorized"
    assert data.get("description") == "Missing Authorization Header."


def test_user_not_found(db, client):
    """Client must provide token associated with existing user."""
    # create user
    user = User.create(
        username="foo", email="foo@bar.com", password="password", active=True,
    )
    user_id = user.id
    # authenticate
    access_token, _ = authenticate_user(client, "foo@bar.com", "password")
    # delete user
    user.delete()
    # attempt deletion
    response = client.delete(
        USERS_ENDPOINT, headers={"Authorization": f"Bearer {access_token}"}
    )
    data = json.loads(response.data)
    assert response.status_code == 404
    assert data.get("message") == "Resource not found"
    assert data.get("description") == f'User with id "{user_id}" not found.'


@pytest.mark.parametrize("bad_jwt", ["", "random string!"])
def test_invalid_jwt(db, client, bad_jwt):
    """Client must provide endpoint a valid JWT."""
    # attempt retrieval
    response = client.delete(
        USERS_ENDPOINT, headers={"Authorization": f"Bearer {bad_jwt}"}
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Action unauthorized"
    assert (
        data.get("description")
        == "Bad Authorization header. Expected value 'Bearer <JWT>'."
    )
