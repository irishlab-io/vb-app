"""
Integration-test–specific fixtures.

Shared infrastructure (app, client, tokens, rate-limit clearing) is
provided by tests/conftest.py.  Fixtures defined here are only available
to the integration test module.
"""

import pytest

# ---------------------------------------------------------------------------
# Canonical DB row constants – re-exported so integration tests do not need
# to duplicate them.
# ---------------------------------------------------------------------------

# (id, username, password, account_number, balance,
#  is_admin, profile_picture, reset_pin, bio, is_suspended)
USER_ROW     = (2, "alice",  "pass",      "1111111111", 800.0,
                False, None, None, "Hello", False)
USER2_ROW    = (3, "bob",    "pass2",     "2222222222", 500.0,
                False, None, None, None, False)
ADMIN_ROW    = (1, "admin",  "adminpass", "0000000001", 9999.0,
                True,  None, None, None, False)
SUSPENDED_ROW = (4, "eve",   "pass",      "3333333333", 100.0,
                 False, None, None, None, True)


@pytest.fixture
def external_ip():
    return {"REMOTE_ADDR": "198.51.100.1"}


@pytest.fixture
def loopback_ip():
    return {"REMOTE_ADDR": "127.0.0.1"}
