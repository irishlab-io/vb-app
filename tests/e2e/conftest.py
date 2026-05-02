"""
End-to-end test fixtures.

E2e tests simulate realistic user sessions by driving the full Flask
request pipeline (including middleware, serialisation, and cookie/session
handling).  The only external dependency replaced is the database layer;
everything else – routing, auth, rate-limiting – runs as it would in
production.

Shared infrastructure from tests/conftest.py (app, client, token
generation, rate-limit clearing) is inherited automatically.
"""

import pytest

# ---------------------------------------------------------------------------
# Canonical DB rows
# ---------------------------------------------------------------------------

# (id, username, password, account_number, balance,
#  is_admin, profile_picture, reset_pin, bio, is_suspended)
E2E_USER = (
    10,
    "e2euser",
    "e2epass",
    "9000000001",
    5000.0,
    False,
    None,
    None,
    None,
    False,
)
E2E_USER2 = (
    11,
    "e2euser2",
    "e2epass2",
    "9000000002",
    3000.0,
    False,
    None,
    None,
    None,
    False,
)
E2E_ADMIN = (
    1,
    "admin",
    "adminpass",
    "0000000001",
    99999.0,
    True,
    None,
    None,
    None,
    False,
)


@pytest.fixture
def external_ip():
    return {"REMOTE_ADDR": "203.0.113.50"}


@pytest.fixture
def loopback_ip():
    return {"REMOTE_ADDR": "127.0.0.1"}


@pytest.fixture
def e2e_client(app):
    """
    Test client that persists cookies across requests, mimicking a real
    browser session.
    """
    with app.test_client() as c:
        c.cookie_jar.clear()
        yield c
