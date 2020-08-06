"""Test token authentication."""
import json

import pytest

from app.main.api.user.models import User
from app.test.util import API_URL_BASE

AUTH_ENDPOINT = f"{API_URL_BASE}/auth/token"


def test_authentication(db, client):
    """Client can authenticate user."""
    # create user
    User.create(
        username="foo", email="foo@bar.com", password="password", active=True,
    )
    # authenticate
    response = client.post(
        AUTH_ENDPOINT,
        data=json.dumps({"email": "foo@bar.com", "password": "password"}),
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 200
    assert data["access_token"] is not None
    assert data["refresh_token"] is not None


def test_wrong_password(db, client):
    """Client must provide correct password."""
    # create user
    User.create(
        username="foo", email="foo@bar.com", password="password", active=True,
    )
    # attempt authentication
    response = client.post(
        AUTH_ENDPOINT,
        data=json.dumps({"email": "foo@bar.com", "password": "passwords"}),
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 401
    assert data["message"] == "Invalid credentials"
    assert data["description"] == "Incorrect password."


def test_user_missing(db, client):
    """Client must provide email address belonging to existing user."""
    # create user
    User.create(
        username="foo", email="foo@bar.com", password="password", active=True,
    )
    # attempt authentication
    response = client.post(
        AUTH_ENDPOINT,
        data=json.dumps({"email": "foo1@bar.com", "password": "password"}),
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 404
    assert data["message"] == "Resource not found"
    assert data["description"] == 'User with email "foo1@bar.com" not found.'


def test_inactive_user(db, client):
    """Client must authenticate active user."""
    # create user
    User.create(
        username="foo", email="foo@bar.com", password="password", active=False,
    )
    # attempt authentication
    response = client.post(
        AUTH_ENDPOINT,
        data=json.dumps({"email": "foo@bar.com", "password": "password"}),
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 403
    assert data["message"] == "Action on resource unauthorized"
    assert data["description"] == "User must be active to authenticate."


def test_invalid_json(db, client):
    """Client must provide valid JSON."""
    response = client.post(
        AUTH_ENDPOINT,
        data="email=foo password=password",
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data["message"] == "Validation failure"
    assert "Payload must be valid JSON." in data["errors"][0]["description"]


@pytest.mark.parametrize("payload", ["", "{}"])
def test_empty_payload(db, client, payload):
    """Client cannot provide empty payload."""
    response = client.post(
        AUTH_ENDPOINT,
        data=json.dumps(payload),
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data["message"] == "Validation failure"
    assert "Invalid input type." in data["errors"][0]["description"]


def test_invalid_email(db, client):
    """Client must provide valid email."""
    response = client.post(
        AUTH_ENDPOINT,
        data=json.dumps({"email": "foobar.com", "password": "password"}),
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data["message"] == "Validation failure"
    assert data["errors"][0]["field"] == "email"
    assert "Not a valid email address." in data["errors"][0]["description"]


def test_missing_email(db, client):
    """Client must provide email."""
    response = client.post(
        AUTH_ENDPOINT,
        data=json.dumps({"password": "password"}),
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data["message"] == "Validation failure"
    assert data["errors"][0]["field"] == "email"
    assert (
        "Missing data for required field." in data["errors"][0]["description"]
    )


def test_missing_password(db, client):
    """Client must provide password."""
    response = client.post(
        AUTH_ENDPOINT,
        data=json.dumps({"email": "foo@bar.com"}),
        content_type="application/json",
    )
    data = json.loads(response.data)
    assert response.status_code == 422
    assert data["message"] == "Validation failure"
    assert data["errors"][0]["field"] == "password"
    assert (
        "Missing data for required field." in data["errors"][0]["description"]
    )
