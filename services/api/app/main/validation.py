"""Application validation module."""
import functools

from werkzeug.exceptions import BadRequest
from flask import request, jsonify
from marshmallow import ValidationError

from app.main.api.user.schema import (
    UserAuthSchema,
    UserPostSchema,
    UserPatchSchema,
    UserSelfPatchSchema,
)


class ValidationSchemaProvider:
    """Validation schemas."""

    def __init__(self):
        """Initialize dictionary for holding schemas."""
        self._schemas = {}

    def register(self, name, Schema):
        """Add a schema."""
        self._schemas[name] = Schema()

    def get(self, name):
        """Retrieve schema."""
        return self._schemas[name]


# register schemas
schemas = ValidationSchemaProvider()
# user resource schemas
schemas.register("user_auth", UserAuthSchema)
schemas.register("user_post", UserPostSchema)
schemas.register("user_patch", UserPatchSchema)
schemas.register("user_self_patch", UserSelfPatchSchema)


def validate_schema(schema_name):
    """Checks request data against specified schema."""

    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            failure_payload = {"message": "Validation failure"}
            try:
                schema = schemas.get(schema_name)
                schema.load(request.json)
                if request.json == {}:
                    raise ValueError("Payload cannot be empty.")
            except ValidationError as error:
                errors = [
                    {"field": field, "description": error.messages[field]}
                    for field in error.messages
                ]
                failure_payload["errors"] = errors
                return jsonify(failure_payload), 422
            except BadRequest:
                failure_payload["errors"] = [
                    {"description": "Payload must be valid JSON."}
                ]
                return jsonify(failure_payload), 422
            except ValueError as error:
                failure_payload["description"] = str(error)
                return jsonify(failure_payload), 422
            return f(*args, **kwargs)

        return wrapper

    return decorator
