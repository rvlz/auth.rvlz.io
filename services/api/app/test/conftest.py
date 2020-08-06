"""Defines fixtures available to all tests."""
import pytest
import jwt
from flask import current_app

from app.main.database import db as _db
from app.main import create_app
from app.test.factories import UserFactory
from app.main.api.user.models import User


@pytest.fixture
def config(env, monkeypatch):
    monkeypatch.setenv(
        "APP_CONFIG", f"app.main.config.{env.capitalize()}Config"
    )


@pytest.fixture
def app(monkeypatch):
    """Create web application for tests."""
    monkeypatch.setenv("APP_CONFIG", "app.main.config.TestingConfig")
    _app = create_app()
    with _app.test_request_context():
        yield _app


@pytest.fixture
def db(app):
    """Create database for tests."""
    _db.app = app
    with app.app_context():
        _db.create_all()

    yield _db

    _db.session.close()
    _db.drop_all()


@pytest.fixture
def client(monkeypatch):
    """Create test client."""
    monkeypatch.setenv("APP_CONFIG", "app.main.config.TestingConfig")
    app = create_app()
    _client = app.test_client()

    with app.app_context():
        yield _client


@pytest.fixture
def request_ctx(monkeypatch):
    """Create request context."""
    monkeypatch.setenv("APP_CONFIG", "app.main.config.TestingConfig")
    app = create_app()
    with app.test_request_context():
        yield


@pytest.fixture
def expired_token(role, token_type):
    """Issue expired tokens."""
    secret = current_app.config["JWT_SECRET_KEY"]
    claims = {
        "exp": 0,
        "identity": "1",
        "type": token_type,
        "user_claims": {"role": role},
    }
    _expired_operator_token = jwt.encode(claims, secret)
    yield _expired_operator_token.decode()


@pytest.fixture
def users(db, resource_count):
    """Generate users."""
    UserFactory._meta.sqlalchemy_session = db.session
    UserFactory.create_batch(resource_count)
    yield User.query.order_by(User.created_at.asc()).all()


@pytest.fixture
def user(db):
    """Generata a user."""
    UserFactory._meta.sqlalchemy_session = db.session
    yield UserFactory.create()
