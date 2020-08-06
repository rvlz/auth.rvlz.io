"""User views."""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import exc

from app.main.api.user.models import User
from app.main.api.user.schema import UserPatchSchema
from app.main.validation import validate_schema
from app.main.permissions import authorization_required
from app.main.api.user.util import get_unique_col_error_message


bp = Blueprint("user", __name__)


@bp.route("", methods=["POST"])
@validate_schema("user_post")
def create_user():
    """Create user."""
    updates = {**request.json}
    try:
        user = User.create(**updates)
    except exc.IntegrityError as error:
        payload = {"message": "Action aborted"}
        description = get_unique_col_error_message(error, updates)
        if description:
            payload["description"] = description
        return jsonify(payload), 403
    return jsonify(user.to_dict()), 201


@bp.route("/<uuid:user_id>", methods=["GET"])
@authorization_required
def get_user(user_id):
    """Get user."""
    user = User.get_by_id(str(user_id))
    if user is None:
        payload = {
            "message": "Resource not found",
            "description": f'User with id "{user_id}" not found.',
        }
        return jsonify(payload), 404
    return jsonify(user.to_dict()), 200


@bp.route("/<uuid:user_id>", methods=["DELETE"])
@authorization_required
def delete_user(user_id):
    """Delete user."""
    user = User.get_by_id(str(user_id))
    if user is None:
        payload = {
            "message": "Resource not found",
            "description": f'User with id "{user_id}" not found.',
        }
        return jsonify(payload), 404
    user.delete()
    return "", 204


@bp.route("/<uuid:user_id>", methods=["PATCH"])
@authorization_required
@validate_schema("user_patch")
def update_user(user_id):
    """Update user."""
    schema = UserPatchSchema()
    updates = schema.load(request.json)
    user = User.get_by_id(str(user_id))
    if user is None:
        payload = {
            "message": "Resource not found",
            "description": f'User with id "{user_id}" not found.',
        }
        return jsonify(payload), 404
    try:
        user.update(**updates)
    except exc.IntegrityError as error:
        payload = {"message": "Action aborted"}
        description = get_unique_col_error_message(error, updates)
        if description:
            payload["description"] = description
        return jsonify(payload), 403
    return jsonify(user.to_dict()), 200


@bp.route("/self", methods=["GET"])
@jwt_required
def get_current_user():
    """Get user associated with JWT."""
    user_id = get_jwt_identity()
    user = User.get_by_id(user_id)
    if user is None:
        payload = {
            "message": "Resource not found",
            "description": f'User with id "{user_id}" not found.',
        }
        return jsonify(payload), 404
    return jsonify(user.to_dict()), 200


@bp.route("/self", methods=["DELETE"])
@jwt_required
def delete_current_user():
    """Delete user associated with JWT."""
    user_id = get_jwt_identity()
    user = User.get_by_id(user_id)
    if user is None:
        payload = {
            "message": "Resource not found",
            "description": f'User with id "{user_id}" not found.',
        }
        return jsonify(payload), 404
    user.delete()
    return "", 204


@bp.route("/self", methods=["PATCH"])
@jwt_required
@validate_schema("user_self_patch")
def update_current_user():
    """Update user associated with JWT."""
    user_id = get_jwt_identity()
    user = User.get_by_id(user_id)
    if user is None:
        payload = {
            "message": "Resource not found",
            "description": f'User with id "{user_id}" not found.',
        }
        return jsonify(payload), 404
    updates = request.json
    try:
        user.update(**updates)
    except exc.IntegrityError as error:
        payload = {"message": "Action aborted"}
        description = get_unique_col_error_message(error, updates)
        if description:
            payload["description"] = description
        return jsonify(payload), 403
    return jsonify(user.to_dict()), 200
