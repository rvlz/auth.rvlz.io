"""User model tests."""
import datetime as dt

import pytest

from app.main.api.user.models import User, Role
from app.test.util import is_iso_format


def test_get_by_id(db):
    """Get user by id."""
    user = User("foo", "foo@bar.com")
    user.save()
    retrieved_user = User.get_by_id(user.id)
    assert user == retrieved_user


def test_get_by_email(db):
    """Get user by email."""
    user = User("foo", "foo@bar.com")
    user.save()
    retrieved_user = User.get_by_email("foo@bar.com")
    assert user == retrieved_user


def test_get_by_email_missing_user(db):
    """None is returned when user doesn't exist."""
    user = User("foo", "foo@bar.com")
    user.save()
    retrieved_user = User.get_by_email("foo1@bar.com")
    assert retrieved_user is None


def test_password_hash_is_nullable(db):
    """Test null password."""
    user = User("foo", "foo@bar.com")
    user.save()
    assert user.password_hash is None


def test_check_password(db):
    """Check hashed password."""
    user = User(username="foo", email="foo@bar.com", password="password")
    user.save()
    assert user.password_hash
    assert str(user.password_hash) != "password"
    assert user.check_password("password") is True
    assert user.check_password("password1") is False


def test_password_attribute_write_only(db):
    """Test password attribute is write-only."""
    user = User(username="foo", email="foo@bar.com", password="password")
    user.save()
    with pytest.raises(AttributeError) as excinfo:
        user.password
    assert str(excinfo.value) == "password: write-only attribute"


def test_role_defaults_to_user(db):
    """
    User role field defaults to user, a role with minimum authorization.
    """
    user = User("foo", "foo@bar.com")
    user.save()
    assert user.role == Role.USER


def test_active_defaults_to_true(db):
    """User active field defaults to False."""
    user = User("foo", "foo@bar.com")
    user.save()
    assert user.active is False


def test_created_at_defaults_to_datetime(db):
    """Test creation date."""
    user = User("foo", "foo@bar.com")
    user.save()
    assert bool(user.created_at)
    assert isinstance(user.created_at, dt.datetime)


def test_to_dict(db):
    """Tesst user instance representation as a dictionary."""
    user = User.create(username="foo", email="foo@bar.com")
    user_dict = user.to_dict()
    assert user_dict["id"]
    assert user_dict["username"] == "foo"
    assert user_dict["email"] == "foo@bar.com"
    assert user_dict["active"] is False
    assert user_dict["role"] == "user"
    assert is_iso_format(user_dict["created_at"])
    assert "password" not in user_dict and "password_hash" not in user_dict
