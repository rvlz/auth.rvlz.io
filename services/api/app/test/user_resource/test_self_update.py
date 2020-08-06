"""Test PATCH /users/self endpoint."""
import json

import pytest

from app.main.api.user.models import User
from app.test.util import (
    authenticate_user,
    is_iso_format,
    API_URL_BASE,
)

USERS_ENDPOINT = f"{API_URL_BASE}/users/self"
REVOKE_ENDPOINT = f"{API_URL_BASE}/auth/revoke"


@pytest.mark.parametrize("username", [{}, {"username": "foo_user"}])
@pytest.mark.parametrize("email", [{}, {"email": "foo_bar@bar.com"}])
@pytest.mark.parametrize("password", [{}, {"password": "password1!"}])
def test_update(db, client, username, email, password):
    """Client can update current user."""
    updates = {**username, **email, **password}
    # if not updates skip test
    if updates == {}:
        pytest.skip()
    # create user
    user = User.create(
        username="foo", email="foo@bar.com", password="password", active=True,
    )
    user_id = user.id
    # authenticate
    access_token, _ = authenticate_user(client, "foo@bar.com", "password")
    # update
    response = client.patch(
        USERS_ENDPOINT,
        data=json.dumps(updates),
        content_type="application/json",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 200
    assert data.get("id") == user_id
    assert data.get("username") == updates.get("username", "foo")
    assert data.get("email") == updates.get("email", "foo@bar.com")
    assert data.get("active") is user.active
    assert data.get("role") == user.role.value
    assert is_iso_format(data.get("created_at")) is True


@pytest.mark.parametrize("role,token_type", [("user", "access")])
def test_expired_token(db, client, expired_token):
    """Client cannot access endpoint with expired token."""
    # attempt update
    response = client.patch(
        USERS_ENDPOINT, headers={"Authorization": f"Bearer {expired_token}"}
    )
    data = json.loads(response.data)
    assert response.status_code == 401
    assert data.get("message") == "Action unauthorized"
    assert data.get("description") == "Token has expired."


@pytest.mark.parametrize("headers", [{"Authorization": ""}, {}])
def test_missing_token(db, client, headers):
    """Client must provide endpoint a token."""
    # attempt update
    response = client.patch(
        USERS_ENDPOINT,
        data=json.dumps({"username": "foo_bar"}),
        content_type="application/json",
        headers=headers,
    )
    data = json.loads(response.data)
    assert response.status_code == 401
    assert data.get("message") == "Action unauthorized"
    assert data.get("description") == "Missing Authorization Header."


def test_username_taken(db, client):
    """Client cannot use a taken username to update a user."""
    # create user
    User.create(
        username="foo", email="foo@bar.com", password="password", active=True,
    )
    # create another user
    User.create(
        username="foo_user", email="foo_user@bar.com", password="password"
    )
    # authenticate first user
    access_token, _ = authenticate_user(client, "foo@bar.com", "password")
    # attempt update
    response = client.patch(
        USERS_ENDPOINT,
        data=json.dumps({"username": "foo_user"}),
        content_type="application/json",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 403
    assert data.get("message") == "Action aborted"
    assert (
        data.get("description")
        == '"foo_user" already exists. Please choose another username.'
    )


def test_email_taken(db, client):
    """Client cannot use a taken email address to update a user."""
    # create user
    User.create(
        username="foo", email="foo@bar.com", password="password", active=True,
    )
    # create another user
    User.create(
        username="foo_user", email="foo_user@bar.com", password="password"
    )
    # authenticate first user
    access_token, _ = authenticate_user(client, "foo@bar.com", "password")
    # attempt update
    response = client.patch(
        USERS_ENDPOINT,
        data=json.dumps({"email": "foo_user@bar.com"}),
        content_type="application/json",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 403
    assert data.get("message") == "Action aborted"
    assert data.get("description") == (
        '"foo_user@bar.com" already exists.'
        " Please choose another email address."
    )


def test_user_not_found(db, client):
    """Client must provide a token associated with an existing user."""
    # create user
    user = User.create(
        username="foo", email="foo@bar.com", password="password", active=True,
    )
    user_id = user.id
    # authenticate
    access_token, _ = authenticate_user(client, "foo@bar.com", "password")
    # delete user
    user.delete()
    # attempt update
    response = client.patch(
        USERS_ENDPOINT,
        data=json.dumps({"username": "foo_1"}),
        content_type="application/json",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 404
    assert data.get("message") == "Resource not found"
    assert data.get("description") == f'User with id "{user_id}" not found.'


@pytest.mark.parametrize("bad_jwt", ["", "random string!"])
def test_invalid_jwt(db, client, bad_jwt):
    """Client must provide endpoint a valid JWT."""
    # attempt retrieval
    response = client.patch(
        USERS_ENDPOINT, headers={"Authorization": f"Bearer {bad_jwt}"}
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Action unauthorized"
    assert (
        data.get("description")
        == "Bad Authorization header. Expected value 'Bearer <JWT>'."
    )


def test_invalid_json(db, client):
    """Client must provide valid JSON."""
    # create user
    User.create(
        username="foo", email="foo@bar.com", password="password", active=True,
    )
    # authenticate
    access_token, _ = authenticate_user(client, "foo@bar.com", "password")
    # attempt update
    response = client.patch(
        USERS_ENDPOINT,
        data="username=foo_1",
        content_type="application/json",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Validation failure"
    assert "Payload must be valid JSON." in data["errors"][0]["description"]


def test_unknown_field(db, client):
    """Client must not provide unknown fields."""
    # create user
    User.create(
        username="foo", email="foo@bar.com", password="password", active=True,
    )
    # authenticate
    access_token, _ = authenticate_user(client, "foo@bar.com", "password")
    # attempt update
    response = client.patch(
        USERS_ENDPOINT,
        data=json.dumps({"random_field": "random_value"}),
        content_type="application/json",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Validation failure"
    assert data["errors"][0]["field"] == "random_field"
    assert "Unknown field." in data["errors"][0]["description"]


def test_invalid_email_address(db, client):
    """Client must provide valid email address."""
    # create user
    User.create(
        username="foo", email="foo@bar.com", password="password", active=True,
    )
    # authenticate
    access_token, _ = authenticate_user(client, "foo@bar.com", "password")
    # attempt update
    response = client.patch(
        USERS_ENDPOINT,
        data=json.dumps({"email": "foobar.com"}),
        content_type="application/json",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Validation failure"
    assert data["errors"][0]["field"] == "email"
    assert "Not a valid email address." in data["errors"][0]["description"]


@pytest.mark.parametrize("username", ["f", "foo" * 11])
def test_invalid_username_length(db, client, username):
    """Client must provide valid username length."""
    # create user
    User.create(
        username="foo", email="foo@bar.com", password="password", active=True,
    )
    # authenticate
    access_token, _ = authenticate_user(client, "foo@bar.com", "password")
    # attempt update
    response = client.patch(
        USERS_ENDPOINT,
        data=json.dumps({"username": username}),
        content_type="application/json",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Validation failure"
    assert data["errors"][0]["field"] == "username"
    assert (
        "Usernames must be between 2 and 30 characters."
        in data["errors"][0]["description"]
    )


@pytest.mark.parametrize("username", ["foobar#", "*#$foobar", "foo*(#$BAR"])
def test_invalid_username_characters(db, client, username):
    """
    Client must use letters, numbers, and/or underscores for username.
    """
    # create user
    User.create(
        username="foo", email="foo@bar.com", password="password", active=True,
    )
    # authenticate
    access_token, _ = authenticate_user(client, "foo@bar.com", "password")
    # attempt update
    response = client.patch(
        USERS_ENDPOINT,
        data=json.dumps({"username": username}),
        content_type="application/json",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Validation failure"
    assert data["errors"][0]["field"] == "username"
    assert (
        "Usernames must only have letters, numbers, and underscores."
        in data["errors"][0]["description"]
    )


@pytest.mark.parametrize("password", ["pass", "password" * 3])
def test_invalid_password_length(db, client, password):
    """Client must provide valid password length."""
    # create user
    User.create(
        username="foo", email="foo@bar.com", password="password", active=True,
    )
    # authenticate
    access_token, _ = authenticate_user(client, "foo@bar.com", "password")
    # attempt update
    response = client.patch(
        USERS_ENDPOINT,
        data=json.dumps({"password": password}),
        content_type="application/json",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Validation failure"
    assert data["errors"][0]["field"] == "password"
    assert (
        "Passwords must be between 8 and 15 characters."
        in data["errors"][0]["description"]
    )


@pytest.mark.parametrize(
    "password",
    [
        "password#$",  # no number
        "password1",  # no special character
        "12345678!",  # no letter
        "",
    ],
)
def test_invalid_password_characters(db, client, password):
    """
    Client must provide a password that has at least one letter,
    one number, and one special character.
    """
    # create user
    User.create(
        username="foo", email="foo@bar.com", password="password", active=True,
    )
    # authenticate
    access_token, _ = authenticate_user(client, "foo@bar.com", "password")
    # attempt update
    response = client.patch(
        USERS_ENDPOINT,
        data=json.dumps({"password": password}),
        content_type="application/json",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Validation failure"
    assert data["errors"][0]["field"] == "password"
    assert (
        "Passwords must have at least one letter, one number, "
        "and one special character."
    ) in data["errors"][0]["description"]


def test_empty_payload(db, client):
    """
    Client cannot provide empty payload.
    """
    # create user
    User.create(
        username="foo", email="foo@bar.com", password="password", active=True,
    )
    # authenticate
    access_token, _ = authenticate_user(client, "foo@bar.com", "password")
    # attempt update
    response = client.patch(
        USERS_ENDPOINT,
        data=json.dumps({}),
        content_type="application/json",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Validation failure"
    assert data.get("description") == "Payload cannot be empty."
