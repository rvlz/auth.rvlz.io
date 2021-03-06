"""Test GET /users/<id> endpoint."""
import json
import uuid

import pytest
from freezegun import freeze_time

from app.main.api.user.models import User
from app.main.api.user.enum import Role
from app.test.util import (
    is_iso_format,
    authenticate_user,
    create_operator,
    days_from_now,
    API_URL_BASE,
)

USERS_ENDPOINT = f"{API_URL_BASE}/users"
REVOKE_ENDPOINT = f"{API_URL_BASE}/auth/revoke"


def test_retrieval(db, client):
    """Client with operator permissions can get user information."""
    # create operator
    access_token, _ = create_operator(client, "foo", "foo@bar.com", "password")
    # create user
    user = User.create(
        username="foo1", email="foo1@bar.com", password="password",
    )
    user_id = user.id
    # retrieval
    response = client.get(
        f"{USERS_ENDPOINT}/{user_id}",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 200
    assert data.get("id") == user_id
    assert data.get("username") == "foo1"
    assert data.get("email") == "foo1@bar.com"
    assert data.get("active") is False
    assert data.get("role") == Role.USER.value
    assert is_iso_format(data.get("created_at")) is True


def test_expired_token(db, client):
    """Client cannot access endpoint with expired token."""
    # authenticate
    access_token, _ = create_operator(client, "foo", "foo@bar.com", "password")
    # create user
    user = User.create(
        username="foo_user", email="foo_user@bar.com", password="password",
    )
    user_id = user.id
    with freeze_time(days_from_now):
        # attempt retrieval
        response = client.get(
            f"{USERS_ENDPOINT}/{user_id}",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        data = json.loads(response.data)
        assert response.status_code == 401
        assert data.get("message") == "Action unauthorized"
        assert data.get("description") == "Token has expired."


@pytest.mark.parametrize("headers", [{"Authorization": ""}, {}])
def test_missing_token(db, client, headers):
    """Client must provide endpoint a token."""
    # create user
    user = User.create(
        username="foo_user", email="foo_user@bar.com", password="password",
    )
    user_id = user.id
    # attempt retrieval
    response = client.get(f"{USERS_ENDPOINT}/{user_id}", headers=headers)
    data = json.loads(response.data)
    assert response.status_code == 401
    assert data.get("message") == "Action unauthorized"
    assert data.get("description") == "Missing Authorization Header."


def test_permissions(db, client):
    """Client must have proper permissions to get user information."""
    # create non-operator user
    User.create(
        username="foo",
        email="foo@bar.com",
        password="password",
        role=Role.USER,
        active=True,
    )
    # create user
    user = User.create(
        username="foo_user", email="foo_user@bar.com", password="password"
    )
    user_id = user.id
    # authenticate
    access_token, _ = authenticate_user(client, "foo@bar.com", "password")
    # attempt retrieval
    response = client.get(
        f"{USERS_ENDPOINT}/{user_id}",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 403
    assert data.get("message") == "Action unauthorized"
    assert data.get("description") == "Missing required permissions."


def test_user_not_found(db, client):
    """Client must provide the id of an existing user."""
    # create operator
    access_token, _ = create_operator(client, "foo", "foo@bar.com", "password")
    # generate random id
    user_id = str(uuid.uuid4())
    # attempt retrieval
    response = client.get(
        f"{USERS_ENDPOINT}/{user_id}",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 404
    assert data.get("message") == "Resource not found"
    assert data.get("description") == f'User with id "{user_id}" not found.'


@pytest.mark.parametrize("bad_jwt", ["", "random string!"])
def test_invalid_jwt(db, client, bad_jwt):
    """Client must provide endpoint a valid JWT."""
    # create user
    user = User.create(
        username="foo_user", email="foo_user@bar.com", password="password"
    )
    user_id = user.id
    # attempt retrieval
    response = client.get(
        f"{USERS_ENDPOINT}/{user_id}",
        headers={"Authorization": f"Bearer {bad_jwt}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Action unauthorized"
    assert (
        data.get("description")
        == "Bad Authorization header. Expected value 'Bearer <JWT>'."
    )
