"""Utilities module for tests."""
import os
import json
import datetime as dt
from datetime import datetime

from app.main.api.user.models import User
from app.main.api.user.enum import Role

API_URL_BASE = f'/api/{os.getenv("VERSION")}'
days_from_now = dt.timedelta(days=365)


def is_iso_format(dt):
    """Check date string is ISO 8601."""
    try:
        datetime.fromisoformat(dt)
    except Exception:
        return False
    return True


def authenticate_user(client, email, password):
    """Convenience method for authentication."""
    AUTH_ENDPOINT = f"{API_URL_BASE}/auth/token"
    response = client.post(
        AUTH_ENDPOINT,
        data=json.dumps({"email": email, "password": password}),
        content_type="application/json",
    )
    data = json.loads(response.data)
    return data["access_token"], data["refresh_token"]


def create_operator(client, username, email, password):
    """Create operator and authenticate operator."""
    # create operator
    User.create(
        username=username,
        email=email,
        password=password,
        role=Role.OPERATOR,
        active=True,
    )
    # return access token
    return authenticate_user(client, email, password)
