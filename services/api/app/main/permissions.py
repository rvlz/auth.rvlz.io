"""Application permissions module."""
import functools

from flask import jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_claims

from app.main.api.user.enum import Role


def authorization_required(f):
    """Checks JWT has proper permssions."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt_claims()
        if claims["role"] != Role.OPERATOR.value:
            payload = {
                "message": "Action unauthorized",
                "description": "Missing required permissions.",
            }
            return jsonify(payload), 403
        return f(*args, **kwargs)

    return wrapper
