"""Ping endpoint."""
from flask import Blueprint

bp = Blueprint("ping", __name__)


@bp.route("", methods=["GET"])
def ping():
    return "pong", 200
