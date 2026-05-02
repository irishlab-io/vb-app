"""
Shared pytest fixtures and test configuration.

The psycopg2 connection pool is patched at module level so that importing
vuln_bank.app does not attempt a real database connection during test
collection or execution.
"""
from unittest.mock import MagicMock

import psycopg2.pool

# Must happen before any vuln_bank imports to intercept the module-level
# init_connection_pool() call in app.py.
psycopg2.pool.SimpleConnectionPool = MagicMock(return_value=MagicMock())

import pytest

import vuln_bank.app as _app_module
from vuln_bank.app import app as _flask_app
from vuln_bank.auth import generate_token, init_auth_routes


# ---------------------------------------------------------------------------
# App / client fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def app():
    _flask_app.config["TESTING"] = True
    # Register the auth API routes that main() would normally register.
    # Wrapped in try/except to silently ignore duplicate-endpoint errors when
    # the session fixture is shared across multiple test workers.
    try:
        init_auth_routes(_flask_app)
    except AssertionError:
        pass
    return _flask_app


@pytest.fixture
def client(app):
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Token / header fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def user_token():
    return generate_token(user_id=2, username="testuser", is_admin=False)


@pytest.fixture
def admin_token():
    return generate_token(user_id=1, username="admin", is_admin=True)


@pytest.fixture
def user_auth_headers(user_token):
    return {"Authorization": f"Bearer {user_token}"}


@pytest.fixture
def admin_auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


# ---------------------------------------------------------------------------
# State-isolation helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clear_rate_limit_storage():
    """Reset in-memory rate-limit state before and after every test."""
    _app_module.rate_limit_storage.clear()
    yield
    _app_module.rate_limit_storage.clear()
