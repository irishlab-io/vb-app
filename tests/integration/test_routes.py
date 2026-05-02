"""Integration-style tests for Flask routes in vuln_bank.app.

Database calls (execute_query / execute_transaction) are mocked so that no
real PostgreSQL instance is required.
"""
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Canonical mock DB rows
# ---------------------------------------------------------------------------

# Full users row: (id, username, password, account_number, balance,
#                  is_admin, profile_picture, reset_pin, bio, is_suspended)
_USER = (2, "testuser", "password", "1234567890", 1000.0,
         False, None, None, None, False)
_ADMIN = (1, "admin", "adminpass", "0000000001", 9999.0,
          True, None, None, None, False)
_SUSPENDED = (3, "suspended", "pass", "9999999999", 100.0,
              False, None, None, None, True)


# ---------------------------------------------------------------------------
# Static / template pages
# ---------------------------------------------------------------------------


class TestStaticPages:
    @pytest.mark.parametrize("path", [
        "/", "/privacy", "/terms", "/compliance", "/careers", "/blog",
        "/login", "/register",
    ])
    def test_get_returns_200(self, client, path):
        response = client.get(path)
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# /login
# ---------------------------------------------------------------------------


class TestLoginRoute:
    def test_successful_login_returns_token(self, client):
        with patch("vuln_bank.app.execute_query", return_value=[_USER]):
            resp = client.post("/login",
                               json={"username": "testuser",
                                     "password": "password"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "success"
        assert "token" in data

    def test_invalid_credentials_returns_401(self, client):
        with patch("vuln_bank.app.execute_query", return_value=[]):
            resp = client.post("/login",
                               json={"username": "nobody",
                                     "password": "wrong"})
        assert resp.status_code == 401

    def test_suspended_account_returns_403(self, client):
        with patch("vuln_bank.app.execute_query", return_value=[_SUSPENDED]):
            resp = client.post("/login",
                               json={"username": "suspended",
                                     "password": "pass"})
        assert resp.status_code == 403

    def test_successful_login_sets_token_cookie(self, client):
        with patch("vuln_bank.app.execute_query", return_value=[_USER]):
            resp = client.post("/login",
                               json={"username": "testuser",
                                     "password": "password"})
        assert "token" in resp.headers.get("Set-Cookie", "")

    def test_get_login_returns_html(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# /register
# ---------------------------------------------------------------------------


class TestRegisterRoute:
    def test_successful_registration(self, client):
        new_user = (5, "newuser", "9876543210", 1000.0, False)
        with patch("vuln_bank.app.execute_query",
                   side_effect=[[], [new_user]]):
            resp = client.post("/register",
                               json={"username": "newuser",
                                     "password": "pass123"})
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "success"

    def test_duplicate_username_returns_400(self, client):
        with patch("vuln_bank.app.execute_query",
                   return_value=[("existinguser",)]):
            resp = client.post("/register",
                               json={"username": "existinguser",
                                     "password": "pass123"})
        assert resp.status_code == 400
        assert resp.get_json()["status"] == "error"

    def test_get_register_returns_html(self, client):
        assert client.get("/register").status_code == 200


# ---------------------------------------------------------------------------
# /check_balance/<account_number>
# ---------------------------------------------------------------------------


class TestCheckBalanceRoute:
    def test_known_account_returns_balance(self, client):
        with patch("vuln_bank.app.execute_query",
                   return_value=[("testuser", 500.0)]):
            resp = client.get("/check_balance/1234567890")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "success"
        assert data["balance"] == 500.0

    def test_unknown_account_returns_404(self, client):
        with patch("vuln_bank.app.execute_query", return_value=[]):
            resp = client.get("/check_balance/0000000000")
        assert resp.status_code == 404

    def test_no_authentication_required(self, client):
        # BOLA vulnerability – intentional, verify the endpoint is accessible
        with patch("vuln_bank.app.execute_query",
                   return_value=[("testuser", 100.0)]):
            resp = client.get("/check_balance/1234567890")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# /transfer
# ---------------------------------------------------------------------------


class TestTransferRoute:
    def test_requires_authentication(self, client):
        resp = client.post("/transfer",
                           json={"to_account": "9876543210", "amount": 100.0})
        assert resp.status_code == 401

    def test_transfer_with_sufficient_funds(self, client, user_auth_headers):
        with patch("vuln_bank.app.execute_query",
                   return_value=[("1234567890", 1000.0)]):
            with patch("vuln_bank.app.execute_transaction"):
                resp = client.post("/transfer",
                                   headers=user_auth_headers,
                                   json={"to_account": "9876543210",
                                         "amount": 100.0})
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "success"

    def test_transfer_with_insufficient_funds(self, client, user_auth_headers):
        with patch("vuln_bank.app.execute_query",
                   return_value=[("1234567890", 50.0)]):
            resp = client.post("/transfer",
                               headers=user_auth_headers,
                               json={"to_account": "9876543210",
                                     "amount": 100.0})
        assert resp.status_code == 400
        assert resp.get_json()["status"] == "error"

    def test_transfer_returns_new_balance(self, client, user_auth_headers):
        with patch("vuln_bank.app.execute_query",
                   return_value=[("1234567890", 500.0)]):
            with patch("vuln_bank.app.execute_transaction"):
                resp = client.post("/transfer",
                                   headers=user_auth_headers,
                                   json={"to_account": "9876543210",
                                         "amount": 200.0})
        assert resp.get_json()["new_balance"] == 300.0


# ---------------------------------------------------------------------------
# /transactions/<account_number>
# ---------------------------------------------------------------------------


class TestTransactionHistoryRoute:
    def test_returns_transaction_list(self, client):
        mock_txns = [
            (1, "1111111111", "2222222222", 100.0,
             "2024-01-01 10:00:00", "transfer", "Test payment"),
        ]
        with patch("vuln_bank.app.execute_query", return_value=mock_txns):
            resp = client.get("/transactions/1111111111")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "success"
        assert len(data["transactions"]) == 1

    def test_empty_history(self, client):
        with patch("vuln_bank.app.execute_query", return_value=[]):
            resp = client.get("/transactions/9999999999")
        assert resp.status_code == 200
        assert resp.get_json()["transactions"] == []

    def test_no_authentication_required(self, client):
        # BOLA vulnerability – intentional
        with patch("vuln_bank.app.execute_query", return_value=[]):
            resp = client.get("/transactions/1234567890")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# /request_loan
# ---------------------------------------------------------------------------


class TestRequestLoanRoute:
    def test_requires_authentication(self, client):
        resp = client.post("/request_loan", json={"amount": 500.0})
        assert resp.status_code == 401

    def test_loan_request_success(self, client, user_auth_headers):
        with patch("vuln_bank.app.execute_query"):
            resp = client.post("/request_loan",
                               headers=user_auth_headers,
                               json={"amount": 500.0})
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "success"


# ---------------------------------------------------------------------------
# /update_bio
# ---------------------------------------------------------------------------


class TestUpdateBioRoute:
    def test_requires_authentication(self, client):
        resp = client.post("/update_bio", json={"bio": "Hello"})
        assert resp.status_code == 401

    def test_bio_update_success(self, client, user_auth_headers):
        with patch("vuln_bank.app.execute_query"):
            resp = client.post("/update_bio",
                               headers=user_auth_headers,
                               json={"bio": "My new bio"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "success"
        assert data["bio"] == "My new bio"

    def test_bio_echoes_input(self, client, user_auth_headers):
        payload = "<script>alert(1)</script>"
        with patch("vuln_bank.app.execute_query"):
            resp = client.post("/update_bio",
                               headers=user_auth_headers,
                               json={"bio": payload})
        assert resp.get_json()["bio"] == payload


# ---------------------------------------------------------------------------
# /graphql
# ---------------------------------------------------------------------------


class TestGraphQLRoute:
    def test_get_returns_info(self, client):
        resp = client.get("/graphql")
        assert resp.status_code == 200
        assert "message" in resp.get_json()

    def test_post_without_auth_returns_401(self, client):
        resp = client.post("/graphql",
                           json={"query": "{ transactionSummary { scope } }"})
        assert resp.status_code == 401

    def test_post_without_query_returns_400(self, client, user_auth_headers):
        resp = client.post("/graphql",
                           headers=user_auth_headers,
                           json={})
        assert resp.status_code == 400
        errors = resp.get_json().get("errors", [])
        assert any("query" in e["message"].lower() for e in errors)


# ---------------------------------------------------------------------------
# /debug/users
# ---------------------------------------------------------------------------


class TestDebugUsersRoute:
    def test_returns_user_list(self, client):
        mock_users = [(1, "admin", "pass", "0000000001", True)]
        with patch("vuln_bank.app.execute_query", return_value=mock_users):
            resp = client.get("/debug/users")
        assert resp.status_code == 200
        assert "users" in resp.get_json()


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------


class TestAdminRoutes:
    def test_admin_panel_requires_auth(self, client):
        assert client.get("/sup3r_s3cr3t_admin").status_code == 401

    def test_admin_panel_denies_non_admin(self, client, user_auth_headers):
        assert (client.get("/sup3r_s3cr3t_admin",
                           headers=user_auth_headers).status_code == 403)

    def test_approve_loan_denies_non_admin(self, client, user_auth_headers):
        assert (client.post("/admin/approve_loan/1",
                            headers=user_auth_headers).status_code == 403)

    def test_delete_account_denies_non_admin(self, client, user_auth_headers):
        assert (client.post("/admin/delete_account/2",
                            headers=user_auth_headers).status_code == 403)

    def test_toggle_suspension_denies_non_admin(self, client,
                                                user_auth_headers):
        assert (client.post("/admin/toggle_suspension/2",
                            headers=user_auth_headers).status_code == 403)

    def test_admin_panel_accessible_for_admin(self, client,
                                              admin_auth_headers):
        with patch("vuln_bank.app.execute_query",
                   side_effect=[
                       [(10,)],        # SELECT COUNT(*) FROM users
                       [_USER],        # SELECT * FROM users … LIMIT … OFFSET
                       [(0,)],         # SELECT COUNT(*) FROM loans WHERE …
                       [],             # SELECT * FROM loans … LIMIT … OFFSET
                   ]):
            resp = client.get("/sup3r_s3cr3t_admin",
                              headers=admin_auth_headers)
        assert resp.status_code == 200

    def test_approve_loan_succeeds_for_admin(self, client, admin_auth_headers):
        mock_loan = (1, 2, 500.0, "pending")
        with patch("vuln_bank.app.execute_query",
                   return_value=[mock_loan]):
            with patch("vuln_bank.app.execute_transaction"):
                resp = client.post("/admin/approve_loan/1",
                                   headers=admin_auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "success"

    def test_delete_account_succeeds_for_admin(self, client,
                                               admin_auth_headers):
        with patch("vuln_bank.app.execute_query"):
            resp = client.post("/admin/delete_account/3",
                               headers=admin_auth_headers)
        assert resp.status_code == 200

    def test_toggle_suspension_succeeds_for_admin(self, client,
                                                   admin_auth_headers):
        mock_target = (3, "targetuser", False, False)
        with patch("vuln_bank.app.execute_query",
                   side_effect=[[mock_target], None]):
            resp = client.post("/admin/toggle_suspension/3",
                               headers=admin_auth_headers)
        assert resp.status_code == 200

    def test_cannot_suspend_own_account(self, client, admin_auth_headers):
        # admin token has user_id=1; trying to toggle suspension on id=1
        resp = client.post("/admin/toggle_suspension/1",
                           headers=admin_auth_headers)
        assert resp.status_code == 400

    def test_toggle_suspension_user_not_found(self, client,
                                              admin_auth_headers):
        with patch("vuln_bank.app.execute_query", return_value=[]):
            resp = client.post("/admin/toggle_suspension/999",
                               headers=admin_auth_headers)
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Internal / SSRF demo endpoints
# ---------------------------------------------------------------------------


# Remote address that is treated as external (non-loopback)
_EXTERNAL_IP = {"REMOTE_ADDR": "198.51.100.1"}


class TestInternalRoutes:
    def test_internal_secret_blocked_externally(self, client):
        resp = client.get("/internal/secret",
                          environ_overrides=_EXTERNAL_IP)
        assert resp.status_code == 403

    def test_internal_config_blocked_externally(self, client):
        resp = client.get("/internal/config.json",
                          environ_overrides=_EXTERNAL_IP)
        assert resp.status_code == 403

    def test_metadata_root_blocked_externally(self, client):
        resp = client.get("/latest/meta-data/",
                          environ_overrides=_EXTERNAL_IP)
        assert resp.status_code == 403

    def test_metadata_ami_blocked_externally(self, client):
        resp = client.get("/latest/meta-data/ami-id",
                          environ_overrides=_EXTERNAL_IP)
        assert resp.status_code == 403

    def test_metadata_iam_role_blocked_externally(self, client):
        resp = client.get(
            "/latest/meta-data/iam/security-credentials/vulnbank-role",
            environ_overrides=_EXTERNAL_IP)
        assert resp.status_code == 403
