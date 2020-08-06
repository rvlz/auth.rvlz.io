"""User schema modules."""
import re

from marshmallow import Schema, fields, ValidationError, validate

from .enum import Role

fields.Field.default_error_messages[
    "required"
] = "Missing data for required field."
username_re = r"^\w*$"
password_re = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$"


class RoleField(fields.Field):
    """Field for serializing and deserialize Role enums."""

    def _serialize(self, enum, attr, obj, **kwargs):
        if enum is None:
            return ""
        if isinstance(enum, str):
            return enum
        return enum.value

    def _deserialize(self, value, attr, data, **kwargs):
        try:
            return Role(value)
        except ValueError as error:
            error_msg = 'Roles must be either "user" or "operator".'
            raise ValidationError(error_msg) from error


class UserSchema(Schema):
    """General user schema."""

    id = fields.Str()
    username = fields.Str()
    email = fields.Email()
    active = fields.Bool()
    role = RoleField()
    created_at = fields.DateTime()


class UserAuthSchema(Schema):
    """Authentication user schema."""

    email = fields.Email(
        required=True, error_messages={"invalid": "Not a valid email address."}
    )
    password = fields.Str(required=True,)


class UserPostSchema(Schema):
    """User POST /users."""

    username = fields.Str(
        required=True,
        validate=[
            validate.Length(
                min=2,
                max=30,
                error="Usernames must be between {min} and {max} characters.",
            ),
            validate.Regexp(
                username_re,
                flags=re.ASCII,
                error=(
                    "Usernames must only have letters, "
                    "numbers, and underscores."
                ),
            ),
        ],
    )
    email = fields.Email(required=True)
    password = fields.Str(
        required=True,
        validate=[
            validate.Length(
                min=8,
                max=15,
                error="Passwords must be between 8 and 15 characters.",
            ),
            validate.Regexp(
                password_re,
                error=(
                    "Passwords must have at least one letter, one number, "
                    "and one special character."
                ),
            ),
        ],
    )


class UserPatchSchema(Schema):
    """User PATCH /users/<id>."""

    username = fields.Str(
        validate=[
            validate.Length(
                min=2,
                max=30,
                error="Usernames must be between {min} and {max} characters.",
            ),
            validate.Regexp(
                username_re,
                flags=re.ASCII,
                error=(
                    "Usernames must only have letters, "
                    "numbers, and underscores."
                ),
            ),
        ]
    )
    email = fields.Email()
    active = fields.Bool(
        error_messages={"invalid": "Active state must be a boolean value."}
    )
    role = RoleField()
    password = fields.Str(
        validate=[
            validate.Length(
                min=8,
                max=15,
                error="Passwords must be between 8 and 15 characters.",
            ),
            validate.Regexp(
                password_re,
                error=(
                    "Passwords must have at least one letter, one number, "
                    "and one special character."
                ),
            ),
        ]
    )


class UserSelfPatchSchema(Schema):
    """User PATCH /users/self."""

    username = fields.Str(
        validate=[
            validate.Length(
                min=2,
                max=30,
                error="Usernames must be between {min} and {max} characters.",
            ),
            validate.Regexp(
                username_re,
                flags=re.ASCII,
                error=(
                    "Usernames must only have letters, "
                    "numbers, and underscores."
                ),
            ),
        ]
    )
    email = fields.Email()
    password = fields.Str(
        validate=[
            validate.Length(
                min=8,
                max=15,
                error="Passwords must be between 8 and 15 characters.",
            ),
            validate.Regexp(
                password_re,
                error=(
                    "Passwords must have at least one letter, one number, "
                    "and one special character."
                ),
            ),
        ]
    )
