"""Request error handlers."""
from flask import jsonify


def url_not_found_handler(errror):
    """Handle URL not found error."""
    payload = {"message": "Request URL not found."}
    return jsonify(payload), 404


def method_not_allowed_handler(error):
    """Handle method not allowed error."""
    payload = {"message": "method is not allowed for the requested URL."}
    jsonify(payload), 405


def server_error_handlers(code):
    """Handle server errors."""
    payload = {"message": "Server error"}

    def handler(error):
        return jsonify(payload), code

    return handler
