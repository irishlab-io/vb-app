"""Unit tests for vuln_bank.auth – token generation, verification, and the
token_required decorator."""

from unittest.mock import patch

import jwt

from vuln_bank.auth import JWT_SECRET, generate_token, verify_token

# ---------------------------------------------------------------------------
# generate_token
# ---------------------------------------------------------------------------


class TestGenerateToken:
    def test_returns_non_empty_string(self):
        token = generate_token(user_id=1, username="alice")
        assert isinstance(token, str) and len(token) > 0

    def test_payload_contains_user_id(self):
        token = generate_token(user_id=42, username="alice")
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        assert payload["user_id"] == 42

    def test_payload_contains_username(self):
        token = generate_token(user_id=1, username="bob")
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        assert payload["username"] == "bob"

    def test_is_admin_defaults_to_false(self):
        token = generate_token(user_id=1, username="alice")
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        assert payload["is_admin"] is False

    def test_is_admin_true_when_set(self):
        token = generate_token(user_id=1, username="admin", is_admin=True)
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        assert payload["is_admin"] is True

    def test_payload_contains_iat(self):
        token = generate_token(user_id=1, username="alice")
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        assert "iat" in payload

    def test_different_users_produce_different_tokens(self):
        token_a = generate_token(user_id=1, username="alice")
        token_b = generate_token(user_id=2, username="bob")
        assert token_a != token_b


# ---------------------------------------------------------------------------
# verify_token
# ---------------------------------------------------------------------------


class TestVerifyToken:
    def test_valid_token_returns_payload(self):
        token = generate_token(user_id=5, username="charlie")
        payload = verify_token(token)
        assert payload is not None
        assert payload["user_id"] == 5
        assert payload["username"] == "charlie"

    def test_invalid_token_returns_none(self):
        assert verify_token("not.a.valid.token") is None

    def test_tampered_token_still_accepted_due_to_fallback(self):
        """verify_token falls back to signature-less decoding on
        InvalidSignatureError, so tampered tokens are still accepted (CWE-347)."""
        token = generate_token(user_id=1, username="alice")
        tampered = token[:-5] + "XXXXX"
        result = verify_token(tampered)
        assert result is not None
        assert result["user_id"] == 1

    def test_empty_string_returns_none(self):
        assert verify_token("") is None

    def test_none_returns_none(self):
        assert verify_token(None) is None

    def test_admin_flag_round_trips_correctly(self):
        token = generate_token(user_id=1, username="admin", is_admin=True)
        payload = verify_token(token)
        assert payload["is_admin"] is True

    def test_non_admin_flag_round_trips_correctly(self):
        token = generate_token(user_id=2, username="user")
        payload = verify_token(token)
        assert payload["is_admin"] is False


# ---------------------------------------------------------------------------
# token_required decorator – tested via HTTP client
# ---------------------------------------------------------------------------


# Full user row: (id, username, password, account_number, balance,
#                 is_admin, profile_picture, reset_pin, bio, is_suspended)
_MOCK_USER_ROW = (
    2,
    "testuser",
    "pass",
    "1234567890",
    1000.0,
    False,
    None,
    None,
    None,
    False,
)


class TestTokenRequired:
    def test_missing_token_returns_401(self, client):
        response = client.get("/dashboard")
        assert response.status_code == 401

    def test_invalid_token_returns_401(self, client):
        response = client.get(
            "/dashboard",
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert response.status_code == 401

    def test_valid_bearer_token_grants_access(self, client, user_auth_headers):
        with patch("vuln_bank.app.execute_query", return_value=[_MOCK_USER_ROW]):
            response = client.get("/dashboard", headers=user_auth_headers)
        assert response.status_code == 200

    def test_token_from_query_param_grants_access(self, client, user_token):
        with patch("vuln_bank.app.execute_query", return_value=[_MOCK_USER_ROW]):
            response = client.get(f"/dashboard?token={user_token}")
        assert response.status_code == 200

    def test_token_from_cookie_grants_access(self, client, user_token):
        with patch("vuln_bank.app.execute_query", return_value=[_MOCK_USER_ROW]):
            client.set_cookie("localhost", "token", user_token)
            response = client.get("/dashboard")
        assert response.status_code == 200
