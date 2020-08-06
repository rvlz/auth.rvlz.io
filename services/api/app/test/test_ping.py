"""Test for /ping endpoint."""
from app.test.util import API_URL_BASE

PING_ENDPOINT = f"{API_URL_BASE}/ping"


def test_ping(client):
    """Client should receive 'pong'."""
    response = client.get(PING_ENDPOINT)
    assert response.status_code == 200
    assert response.data == b"pong"
