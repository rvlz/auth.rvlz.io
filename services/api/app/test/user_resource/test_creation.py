"""Test POST /users endpoint."""
import json

import pytest

from app.main.api.user.models import User
from app.test.util import is_iso_format, API_URL_BASE

USERS_ENDPOINT = f"{API_URL_BASE}/users"


def test_creation(db, client):
    """Client can create users."""
    # create user
    response = client.post(
        USERS_ENDPOINT,
        data=json.dumps(
            {
                "username": "foo",
                "email": "foo@bar.com",
                "password": "password1!",
            }
        ),
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 201
    assert data.get("id") is not None
    assert data.get("username") == "foo"
    assert data.get("email") == "foo@bar.com"
    assert data.get("active") is False
    assert data.get("role") == "user"
    assert is_iso_format(data.get("created_at"))


def test_username_taken(db, client):
    """Client cannot use a taken username to create a user."""
    # create user
    User.create(username="foo", email="foo@bar.com", password="password1!")
    # creation attempt
    response = client.post(
        USERS_ENDPOINT,
        data=json.dumps(
            {
                "username": "foo",
                "email": "foo1@bar.com",
                "password": "password1!",
            }
        ),
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 403
    assert data.get("message") == "Action aborted"
    assert (
        data.get("description")
        == '"foo" already exists. Please choose another username.'
    )


def test_email_taken(db, client):
    """Client cannot use a taken email address to update a user."""
    # create user
    User.create(username="foo", email="foo@bar.com", password="password1!")
    # creation attempt
    response = client.post(
        USERS_ENDPOINT,
        data=json.dumps(
            {
                "username": "foo1",
                "email": "foo@bar.com",
                "password": "password1!",
            }
        ),
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 403
    assert data.get("message") == "Action aborted"
    assert data.get("description") == (
        '"foo@bar.com" already exists. ' "Please choose another email address."
    )


def test_invalid_json(db, client):
    """Client must provide valid JSON."""
    # creation attempt
    response = client.post(
        USERS_ENDPOINT,
        data="username=foo email=foo@bar.com password=password1!",
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Validation failure"
    assert "Payload must be valid JSON." in data["errors"][0]["description"]


def test_unknown_fields(db, client):
    """Client must not provide unknown fields."""
    response = client.post(
        USERS_ENDPOINT,
        data=json.dumps(
            {
                "username": "foo",
                "email": "foo@bar.com",
                "password": "password1!",
                "random_field": "random_value",
            }
        ),
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Validation failure"
    assert data["errors"][0]["field"] == "random_field"
    assert "Unknown field." in data["errors"][0]["description"]


def test_missing_email_address(db, client):
    """Client must provide email address."""
    response = client.post(
        USERS_ENDPOINT,
        data=json.dumps({"username": "foo", "password": "password1!"}),
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Validation failure"
    assert data["errors"][0]["field"] == "email"
    assert (
        "Missing data for required field." in data["errors"][0]["description"]
    )


def test_invalid_email_address(db, client):
    """Client must provide valid email address."""
    response = client.post(
        USERS_ENDPOINT,
        data=json.dumps(
            {
                "username": "foo",
                "email": "foobar.com",
                "password": "password1!",
            }
        ),
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Validation failure"
    assert data["errors"][0]["field"] == "email"
    assert "Not a valid email address." in data["errors"][0]["description"]


def test_missing_username(db, client):
    """Client must provide username."""
    response = client.post(
        USERS_ENDPOINT,
        data=json.dumps({"email": "foo@bar.com", "password": "password1!"}),
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Validation failure"
    assert data["errors"][0]["field"] == "username"
    assert (
        "Missing data for required field." in data["errors"][0]["description"]
    )


@pytest.mark.parametrize("username", ["f", "foo" * 11])
def test_invalid_username_length(db, client, username):
    """Client must provide valid username length."""
    response = client.post(
        USERS_ENDPOINT,
        data=json.dumps(
            {
                "username": username,
                "email": "foo@bar.com",
                "password": "password1!",
            }
        ),
        content_type="application/json",
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
    response = client.post(
        USERS_ENDPOINT,
        data=json.dumps(
            {
                "username": username,
                "email": "foo@gar.com",
                "password": "password1!",
            }
        ),
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Validation failure"
    assert data["errors"][0]["field"] == "username"
    assert (
        "Usernames must only have letters, numbers, and underscores."
        in data["errors"][0]["description"]
    )


def test_missing_password(client, db):
    """Client must provide password."""
    response = client.post(
        USERS_ENDPOINT,
        data=json.dumps({"username": "foo", "email": "foo@bar.com"}),
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Validation failure"
    assert data["errors"][0]["field"] == "password"
    assert (
        "Missing data for required field." in data["errors"][0]["description"]
    )


@pytest.mark.parametrize("password", ["pass", "password" * 3])
def test_invalid_password_length(client, db, password):
    """Client must provide valid password length."""
    response = client.post(
        USERS_ENDPOINT,
        data=json.dumps(
            {"username": "foo", "email": "foo@bar.com", "password": password}
        ),
        content_type="application/json",
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
def test_invalid_password_characters(client, db, password):
    """
    Client must provide a password that has at least one letter,
    one number, and one special character.
    """
    response = client.post(
        USERS_ENDPOINT,
        data=json.dumps(
            {"username": "foo", "email": "foo@bar.com", "password": password}
        ),
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data.get("message") == "Validation failure"
    assert data["errors"][0]["field"] == "password"
    assert (
        "Passwords must have at least one letter, one number, "
        "and one special character."
    ) in data["errors"][0]["description"]
