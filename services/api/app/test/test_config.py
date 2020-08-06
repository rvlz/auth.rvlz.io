"""Test app configuration."""
import os
from datetime import timedelta

import pytest

from app.main import create_app


@pytest.mark.parametrize("env", ["development"])
def test_development_config(config):
    app = create_app()
    assert not app.config["TESTING"]
    assert app.config["SECRET_KEY"] == os.getenv("SECRET_KEY")
    assert app.config["SQLALCHEMY_DATABASE_URI"] == os.getenv("DATABASE_URL")
    assert not app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]
    assert app.config["BCRYPT_LOG_ROUNDS"] == 13
    assert app.config["VERSION"] == os.getenv("VERSION")
    assert app.config["JWT_SECRET_KEY"] == os.getenv("SECRET_KEY")
    assert app.config["JWT_ACCESS_TOKEN_EXPIRES"] == timedelta(
        minutes=int(os.getenv("ACCESS_TOKEN_EXPIRES")),
    )
    assert app.config["JWT_REFRESH_TOKEN_EXPIRES"] == timedelta(
        minutes=int(os.getenv("REFRESH_TOKEN_EXPIRES")),
    )


@pytest.mark.parametrize("env", ["testing"])
def test_testing_config(config):
    app = create_app()
    assert app.config["TESTING"]
    assert app.config["SECRET_KEY"] == os.getenv("SECRET_KEY")
    assert app.config["SQLALCHEMY_DATABASE_URI"] == os.getenv(
        "DATABASE_TEST_URL"
    )
    assert not app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]
    assert app.config["BCRYPT_LOG_ROUNDS"] == 4
    assert app.config["VERSION"] == os.getenv("VERSION")
    assert app.config["JWT_SECRET_KEY"] == os.getenv("SECRET_KEY")
    assert app.config["JWT_ACCESS_TOKEN_EXPIRES"] == timedelta(
        minutes=int(os.getenv("ACCESS_TOKEN_EXPIRES")),
    )
    assert app.config["JWT_REFRESH_TOKEN_EXPIRES"] == timedelta(
        minutes=int(os.getenv("REFRESH_TOKEN_EXPIRES")),
    )


@pytest.mark.parametrize("env", ["staging"])
def test_staging_config(config):
    app = create_app()
    assert not app.config["TESTING"]
    assert app.config["SECRET_KEY"] == os.getenv("SECRET_KEY")
    assert app.config["SQLALCHEMY_DATABASE_URI"] == os.getenv("DATABASE_URL")
    assert not app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]
    assert app.config["BCRYPT_LOG_ROUNDS"] == 13
    assert app.config["VERSION"] == os.getenv("VERSION")
    assert app.config["JWT_SECRET_KEY"] == os.getenv("SECRET_KEY")
    assert app.config["JWT_ACCESS_TOKEN_EXPIRES"] == timedelta(
        minutes=int(os.getenv("ACCESS_TOKEN_EXPIRES")),
    )
    assert app.config["JWT_REFRESH_TOKEN_EXPIRES"] == timedelta(
        minutes=int(os.getenv("REFRESH_TOKEN_EXPIRES")),
    )


@pytest.mark.parametrize("env", ["production"])
def test_production_config(config):
    app = create_app()
    assert not app.config["TESTING"]
    assert app.config["SECRET_KEY"] == os.getenv("SECRET_KEY")
    assert app.config["SQLALCHEMY_DATABASE_URI"] == os.getenv("DATABASE_URL")
    assert not app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]
    assert app.config["BCRYPT_LOG_ROUNDS"] == 13
    assert app.config["VERSION"] == os.getenv("VERSION")
    assert app.config["JWT_SECRET_KEY"] == os.getenv("SECRET_KEY")
    assert app.config["JWT_ACCESS_TOKEN_EXPIRES"] == timedelta(
        minutes=int(os.getenv("ACCESS_TOKEN_EXPIRES")),
    )
    assert app.config["JWT_REFRESH_TOKEN_EXPIRES"] == timedelta(
        minutes=int(os.getenv("REFRESH_TOKEN_EXPIRES")),
    )
