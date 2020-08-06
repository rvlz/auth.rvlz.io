"""App module containing the app factory function."""
import os
import sys
import logging

from flask import Flask

from app.main.extensions import db, migrate, bcrypt, jwt
from app.main.api.auth import views as auth_views
from app.main.api.user import views as user_views
from app.main.api import ping as ping_views
from app.main.api.user import models
from app.main.errors import (
    url_not_found_handler,
    method_not_allowed_handler,
    server_error_handlers,
)


def create_app():
    """Application factory."""
    app = Flask(__name__)
    configuration = os.getenv("APP_CONFIG")
    app.config.from_object(configuration)
    register_extensions(app)
    register_blueprints(app)
    register_error_handlers(app)
    register_shellcontext(app)
    configure_logger(app)
    return app


def register_extensions(app):
    """Register extensions."""
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    jwt.init_app(app)


def register_blueprints(app):
    """Register blueprints."""
    url_base = f'/api/{app.config["VERSION"]}'
    app.register_blueprint(auth_views.bp, url_prefix=f"{url_base}/auth")
    app.register_blueprint(user_views.bp, url_prefix=f"{url_base}/users")
    app.register_blueprint(ping_views.bp, url_prefix=f"{url_base}/ping")


def register_error_handlers(app):
    """Register error handlers."""
    app.register_error_handler(404, url_not_found_handler)
    app.register_error_handler(405, method_not_allowed_handler)
    for code in range(500, 504):
        app.register_error_handler(code, server_error_handlers(code))


def register_shellcontext(app):
    """Register shell context objects."""

    def shell_context():
        """Shell context objects."""
        return {"db": db, "User": models.User}

    app.shell_context_processor(shell_context)


def configure_logger(app):
    """Configure loggers."""
    handler = logging.StreamHandler(sys.stdout)
    if not app.logger.handlers:
        app.logger.addHandler(handler)
