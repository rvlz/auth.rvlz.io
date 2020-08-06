"""Model factories module."""
from factory import Sequence, LazyAttribute
from factory.alchemy import SQLAlchemyModelFactory

from app.main.api.user.models import User


class BaseFactory(SQLAlchemyModelFactory):
    """Base factory for all models."""

    class Meta:
        """Factory configuration."""

        abstract = True


class UserFactory(BaseFactory):
    """User model factory."""

    username = Sequence(lambda n: "foo_%d" % n)
    email = LazyAttribute(lambda obj: "%s@bar.com" % obj.username)
    password = "password"
    active = True

    class Meta:
        """Factory configuration."""

        model = User
