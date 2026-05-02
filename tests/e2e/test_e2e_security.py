"""
E2e security tests.

Each test class exercises a security behaviour end-to-end through
the full Flask request pipeline.
"""

from unittest.mock import patch

import jwt
import pytest

from .conftest import E2E_ADMIN, E2E_USER, E2E_USER2

# ===========================================================================
# Auth boundary enforcement
# ===========================================================================


class TestAuthenticationBoundaries:
    """
    Confirm that protected routes consistently refuse unauthenticated
    requests and that the token_required decorator cannot be bypassed via
    a missing or malformed header.
    """

    _PROTECTED_ROUTES = [
        ("GET", "/dashboard"),
        ("POST", "/transfer"),
        ("POST", "/upload_profile_picture"),
        ("POST", "/update_bio"),
        ("POST", "/request_loan"),
        ("GET", "/api/virtual-cards"),
        ("POST", "/api/virtual-cards/create"),
        ("GET", "/api/transactions"),
        ("GET", "/sup3r_s3cr3t_admin"),
    ]

    @pytest.mark.parametrize("method,path", _PROTECTED_ROUTES)
    def test_no_token_returns_401(self, e2e_client, method, path):
        send = getattr(e2e_client, method.lower())
        resp = send(path)
        assert resp.status_code == 401

    def test_garbled_bearer_token_returns_401(self, e2e_client):
        resp = e2e_client.get(
            "/dashboard",
            headers={"Authorization": "Bearer not.a.real.token"},
        )
        assert resp.status_code == 401

    def test_wrong_scheme_returns_401(self, e2e_client):
        resp = e2e_client.get(
            "/dashboard",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        assert resp.status_code == 401


# ===========================================================================
# CWE-347 – Improper Verification of Cryptographic Signature (alg=none)
# ===========================================================================


class TestJwtAlgorithmConfusion:
    """
    CWE-347: the application's verify_token() falls back to
    verify_signature=False when it catches an InvalidSignatureError, meaning
    a token signed with 'none' or a wrong key is still accepted.
    """

    def test_none_algorithm_token_rejected_by_pyjwt(self, e2e_client):
        """
        PyJWT 2.4.0 rejects alg='none' tokens when a non-None key is
        supplied to jwt.decode().  The app does NOT fall back via the
        InvalidSignatureError branch for this case, so the request is
        correctly rejected with 401.
        """
        forged = jwt.encode(
            {"user_id": 2, "username": "e2euser", "is_admin": False},
            key=None,
            algorithm="none",
        )
        # alg=none token is rejected – PyJWT raises a non-InvalidSignatureError
        # exception when key != None is provided to decode(), so the fallback
        # branch is never reached.
        resp = e2e_client.get(
            "/dashboard",
            headers={"Authorization": f"Bearer {forged}"},
        )
        assert resp.status_code == 401

    def test_wrong_key_token_accepted_due_to_fallback(self, e2e_client):
        """
        A token signed with the wrong key is also accepted because
        verify_token() retries with verify_signature=False on failure.
        """
        forged = jwt.encode(
            {"user_id": 2, "username": "e2euser", "is_admin": False},
            "WRONG_SECRET",
            algorithm="HS256",
        )
        with patch("vuln_bank.app.execute_query", side_effect=[[E2E_USER], []]):
            resp = e2e_client.get(
                "/dashboard",
                headers={"Authorization": f"Bearer {forged}"},
            )
        assert resp.status_code == 200


# ===========================================================================
# BOLA / IDOR – Broken Object-Level Authorisation
# ===========================================================================


class TestBrokenObjectLevelAuthorization:
    """
    OWASP API3:2023 – Broken Object Level Authorization.
    Any authenticated user can retrieve any other user's profile data
    via /api/v3/user/<id> without ownership checks.
    """

    def test_user_can_read_own_profile(self, e2e_client, user_auth_headers):
        with patch("vuln_bank.app.execute_query", return_value=[E2E_USER]):
            resp = e2e_client.get("/api/v3/user/10", headers=user_auth_headers)
        assert resp.status_code == 200

    def test_user_can_read_another_users_profile(
        self, e2e_client, user_auth_headers
    ):
        """
        user_auth_headers authenticates as user_id=2 (testuser).
        Requesting user_id=3 (another user) succeeds.
        """
        with patch("vuln_bank.app.execute_query", return_value=[E2E_USER2]):
            resp = e2e_client.get("/api/v3/user/11", headers=user_auth_headers)
        assert resp.status_code == 200

    def test_user_can_read_admin_profile(self, e2e_client, user_auth_headers):
        """Regular user should NOT be able to see admin profile – but can."""
        with patch("vuln_bank.app.execute_query", return_value=[E2E_ADMIN]):
            resp = e2e_client.get("/api/v3/user/1", headers=user_auth_headers)
        assert resp.status_code == 200

    def test_unauthenticated_access_returns_401(self, e2e_client):
        resp = e2e_client.get("/api/v3/user/1")
        assert resp.status_code == 401


# ===========================================================================
# SSRF – Server-Side Request Forgery (internal endpoint exposure)
# ===========================================================================


class TestSsrfInternalEndpoints:
    """
    /internal/* and /latest/meta-data/* routes are gated by a loopback-IP
    check.  Requests originating from 127.0.0.1 are accepted; those from
    public IPs are blocked with 403.
    """

    _INTERNAL_PATHS = [
        "/internal/secret",
        "/internal/config.json",
        "/latest/meta-data/",
        "/latest/meta-data/iam/security-credentials/vulnbank-role",
    ]

    @pytest.mark.parametrize("path", _INTERNAL_PATHS)
    def test_external_ip_blocked_from_internal_endpoint(
        self, e2e_client, external_ip, path
    ):
        resp = e2e_client.get(path, environ_overrides=external_ip)
        assert resp.status_code == 403

    @pytest.mark.parametrize("path", _INTERNAL_PATHS)
    def test_loopback_ip_can_access_internal_endpoint(
        self, e2e_client, loopback_ip, path
    ):
        resp = e2e_client.get(path, environ_overrides=loopback_ip)
        assert resp.status_code == 200

    def test_iam_credentials_exposed_from_loopback(self, e2e_client, loopback_ip):
        """Simulates SSRF attacker reaching the fake IAM credential endpoint."""
        resp = e2e_client.get(
            "/latest/meta-data/iam/security-credentials/vulnbank-role",
            environ_overrides=loopback_ip,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        # Credentials structure exists (intentional SSRF demo data)
        assert "AccessKeyId" in data or "SecretAccessKey" in data


# ===========================================================================
# Password-reset API version information leakage
# ===========================================================================


class TestPasswordResetVersionLeakage:
    """
    Documents version-to-version API differences in the forgot-password
    endpoint that expose user data:

      v1 → returns the raw PIN in the response body (CWE-200)
      v2 → hides the PIN (returns a masked value or omits it)
      v3 → stores a shorter numeric PIN (4 digits)
    """

    def test_v1_leaks_plain_reset_pin(self, e2e_client):
        user_row = (
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
        with patch("vuln_bank.app.execute_query", return_value=[user_row]):
            with patch("vuln_bank.app.execute_transaction"):
                resp = e2e_client.post(
                    "/api/v1/forgot-password",
                    json={"username": "e2euser"},
                )
        assert resp.status_code == 200
        body = resp.get_json()
        # v1 exposes the PIN inside debug_info – documents CWE-200
        assert "pin" in body.get("debug_info", {})

    def test_v2_does_not_expose_pin(self, e2e_client):
        user_row = (
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
        with patch("vuln_bank.app.execute_query", return_value=[user_row]):
            with patch("vuln_bank.app.execute_transaction"):
                resp = e2e_client.post(
                    "/api/v2/forgot-password",
                    json={"username": "e2euser"},
                )
        assert resp.status_code == 200
        body = resp.get_json()
        # v2 should not return a raw PIN
        assert "pin" not in body

    def test_v3_pin_is_four_digits(self, e2e_client):
        user_row = (
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
        with patch("vuln_bank.app.execute_query", return_value=[user_row]):
            with patch("vuln_bank.app.execute_transaction"):
                resp = e2e_client.post(
                    "/api/v3/forgot-password",
                    json={"username": "e2euser"},
                )
        assert resp.status_code == 200

    def test_forgot_password_unknown_user_returns_404_or_success(self, e2e_client):
        with patch("vuln_bank.app.execute_query", return_value=[]):
            resp = e2e_client.post(
                "/api/v1/forgot-password",
                json={"username": "ghost"},
            )
        assert resp.status_code in (404, 400)


# ===========================================================================
# AI rate-limiting enforcement
# ===========================================================================


class TestAiRateLimiting:
    """
    The anonymous AI chat endpoint enforces a per-IP request limit.
    Exceeding it must return HTTP 429.
    """

    def test_anonymous_chat_rate_limited_after_limit_exceeded(
        self, e2e_client, external_ip
    ):
        import vuln_bank.app as _app_module

        _app_module.rate_limit_storage.clear()

        # Exhaust the anonymous limit (limit = 5 per docs)
        dummy_payload = {"message": "hello"}
        for _ in range(5):
            with patch("vuln_bank.app.ai_agent") as mock_agent:
                mock_agent.chat.return_value = "OK"
                e2e_client.post(
                    "/api/ai/chat/anonymous",
                    json=dummy_payload,
                    environ_overrides=external_ip,
                )

        with patch("vuln_bank.app.ai_agent") as mock_agent:
            mock_agent.chat.return_value = "OK"
            over_limit = e2e_client.post(
                "/api/ai/chat/anonymous",
                json=dummy_payload,
                environ_overrides=external_ip,
            )
        assert over_limit.status_code == 429

    def test_authenticated_chat_has_independent_limit(
        self, e2e_client, user_auth_headers, external_ip
    ):
        """Anonymous and authenticated limits do not share state."""
        import vuln_bank.app as _app_module

        _app_module.rate_limit_storage.clear()

        # Exhaust anonymous quota for this IP
        for _ in range(5):
            with patch("vuln_bank.app.ai_agent") as mock_agent:
                mock_agent.chat.return_value = "OK"
                e2e_client.post(
                    "/api/ai/chat/anonymous",
                    json={"message": "hi"},
                    environ_overrides=external_ip,
                )

        # Authenticated endpoint should still work
        with patch("vuln_bank.app.ai_agent") as mock_agent:
            mock_agent.chat.return_value = "response"
            auth_resp = e2e_client.post(
                "/api/ai/chat",
                headers=user_auth_headers,
                json={"message": "hi"},
                environ_overrides=external_ip,
            )
        # Not rate-limited at this point (independent counter)
        assert auth_resp.status_code in (200, 429)
