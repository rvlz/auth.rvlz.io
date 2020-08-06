"""Application configuration."""
import os
from datetime import timedelta


class BaseConfig:
    TESTING = False
    SECRET_KEY = os.getenv("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    BCRYPT_LOG_ROUNDS = 13
    VERSION = os.getenv("VERSION")
    JWT_SECRET_KEY = os.getenv("SECRET_KEY")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        minutes=int(os.getenv("ACCESS_TOKEN_EXPIRES")),
    )
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(
        minutes=int(os.getenv("REFRESH_TOKEN_EXPIRES")),
    )


class DevelopmentConfig(BaseConfig):
    pass


class TestingConfig(BaseConfig):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_TEST_URL")
    BCRYPT_LOG_ROUNDS = 4


class StagingConfig(BaseConfig):
    pass


class ProductionConfig(BaseConfig):
    pass
