"""Authentication views."""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_refresh_token_required,
    get_jwt_identity,
    get_jwt_claims,
)

from app.main.extensions import jwt
from app.main.validation import validate_schema
from app.main.api.user.models import User

bp = Blueprint("auth", __name__)


@jwt.unauthorized_loader
def unauthorized(description):
    payload = {
        "message": "Action unauthorized",
        "description": f"{description}.",
    }
    return jsonify(payload), 401


@jwt.expired_token_loader
def expired(token):
    payload = {
        "message": "Action unauthorized",
        "description": "Token has expired.",
    }
    return jsonify(payload), 401


@jwt.invalid_token_loader
def invalid(description):
    payload = {
        "message": "Action unauthorized",
        "description": f"{description}.",
    }
    return jsonify(payload), 422


@bp.route("/token", methods=["POST"])
@validate_schema("user_auth")
def token():
    """Authenticate user and issue token."""
    email = request.json.get("email")
    password = request.json.get("password")
    user = User.get_by_email(email)
    if user is None:
        payload = {
            "message": "Resource not found",
            "description": f'User with email "{email}" not found.',
        }
        return jsonify(payload), 404
    if not user.active:
        payload = {
            "message": "Action on resource unauthorized",
            "description": "User must be active to authenticate.",
        }
        return jsonify(payload), 403
    if user.check_password(password):
        claims = {
            "identity": user.id,
            "user_claims": {"role": user.role.value},
        }
        access_token = create_access_token(**claims)
        refresh_token = create_refresh_token(**claims)
        payload = {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }
        return jsonify(payload), 200
    payload = {
        "message": "Invalid credentials",
        "description": "Incorrect password.",
    }
    return jsonify(payload), 401


@bp.route("/refresh", methods=["POST"])
@jwt_refresh_token_required
def refresh_token():
    """Refresh access token."""
    identity = get_jwt_identity()
    claims = get_jwt_claims()
    payload = {
        "access_token": create_access_token(
            identity=identity, user_claims=claims,
        ),
    }
    return jsonify(payload), 200
