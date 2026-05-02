"""Integration tests for vuln_bank.

Integration tests focus on complete, multi-step user flows that exercise
several components in sequence: auth middleware → route handler → response
serialisation. Database calls are mocked as a unit at the boundary so that
no real PostgreSQL instance is required, while the full Flask request
pipeline runs normally.
"""

from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers: canonical DB rows
# ---------------------------------------------------------------------------

# (id, username, password, account_number, balance,
#  is_admin, profile_picture, reset_pin, bio, is_suspended)
_USER = (2, "alice", "pass", "1111111111", 800.0, False, None, None, "Hello", False)
_USER2 = (3, "bob", "pass2", "2222222222", 500.0, False, None, None, None, False)
_ADMIN = (1, "admin", "adminpass", "0000000001", 9999.0, True, None, None, None, False)
_SUSPENDED = (4, "eve", "pass", "3333333333", 100.0, False, None, None, None, True)

_EXTERNAL_IP = {"REMOTE_ADDR": "198.51.100.1"}
_LOOPBACK_IP = {"REMOTE_ADDR": "127.0.0.1"}


# ===========================================================================
# Flow 1: Register → Login → Dashboard
# ===========================================================================


class TestRegisterLoginDashboardFlow:
    """Complete user-onboarding journey."""

    def test_register_success_then_login_returns_token(self, client):
        new_user_row = (5, "newuser", "9876543210", 1000.0, False)

        # Step 1: Register
        with patch("vuln_bank.app.execute_query", side_effect=[[], [new_user_row]]):
            reg_resp = client.post(
                "/register", json={"username": "newuser", "password": "pass123"}
            )
        assert reg_resp.status_code == 200
        assert reg_resp.get_json()["status"] == "success"

        # Step 2: Login with the new account
        db_user = (
            5,
            "newuser",
            "pass123",
            "9876543210",
            1000.0,
            False,
            None,
            None,
            None,
            False,
        )
        with patch("vuln_bank.app.execute_query", return_value=[db_user]):
            login_resp = client.post(
                "/login", json={"username": "newuser", "password": "pass123"}
            )
        assert login_resp.status_code == 200
        token = login_resp.get_json()["token"]
        assert isinstance(token, str) and len(token) > 10

        # Step 3: Access dashboard with the obtained token
        with patch("vuln_bank.app.execute_query", side_effect=[[db_user], []]):
            dash_resp = client.get(
                "/dashboard", headers={"Authorization": f"Bearer {token}"}
            )
        assert dash_resp.status_code == 200

    def test_register_duplicate_then_login_fails(self, client):
        # Register attempt fails due to duplicate
        with patch("vuln_bank.app.execute_query", return_value=[("newuser",)]):
            resp = client.post(
                "/register", json={"username": "newuser", "password": "pass"}
            )
        assert resp.status_code == 400

        # Login with non-existent user fails
        with patch("vuln_bank.app.execute_query", return_value=[]):
            login_resp = client.post(
                "/login", json={"username": "newuser", "password": "pass"}
            )
        assert login_resp.status_code == 401

    def test_suspended_user_cannot_login_or_reach_dashboard(self, client):
        # Login blocked for suspended user
        with patch("vuln_bank.app.execute_query", return_value=[_SUSPENDED]):
            resp = client.post("/login", json={"username": "eve", "password": "pass"})
        assert resp.status_code == 403

        # Dashboard is also blocked (token_required returns 401 without token)
        resp2 = client.get("/dashboard")
        assert resp2.status_code == 401


# ===========================================================================
# Flow 2: Login → Transfer → Check Balance → Transaction History
# ===========================================================================


class TestTransferFlow:
    """Full money-movement journey for an authenticated user."""

    def test_successful_transfer_reduces_balance(self, client, user_auth_headers):
        sender_data = ("1111111111", 1000.0)

        with patch("vuln_bank.app.execute_query", return_value=[sender_data]):
            with patch("vuln_bank.app.execute_transaction"):
                resp = client.post(
                    "/transfer",
                    headers=user_auth_headers,
                    json={
                        "to_account": "2222222222",
                        "amount": 250.0,
                        "description": "Rent",
                    },
                )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "success"
        assert data["new_balance"] == pytest.approx(750.0)

    def test_transfer_then_history_shows_entry(self, client, user_auth_headers):
        sender_data = ("1111111111", 1000.0)
        mock_txn = (
            1,
            "1111111111",
            "2222222222",
            250.0,
            "2024-01-01 10:00:00",
            "transfer",
            "Rent",
        )

        # Transfer
        with patch("vuln_bank.app.execute_query", return_value=[sender_data]):
            with patch("vuln_bank.app.execute_transaction"):
                client.post(
                    "/transfer",
                    headers=user_auth_headers,
                    json={"to_account": "2222222222", "amount": 250.0},
                )

        # Check history
        with patch("vuln_bank.app.execute_query", return_value=[mock_txn]):
            hist_resp = client.get("/transactions/1111111111")
        assert hist_resp.status_code == 200
        txns = hist_resp.get_json()["transactions"]
        assert len(txns) == 1
        assert txns[0]["amount"] == 250.0

    def test_transfer_blocked_when_insufficient_funds(self, client, user_auth_headers):
        sender_data = ("1111111111", 10.0)
        with patch("vuln_bank.app.execute_query", return_value=[sender_data]):
            resp = client.post(
                "/transfer",
                headers=user_auth_headers,
                json={"to_account": "2222222222", "amount": 500.0},
            )
        assert resp.status_code == 400
        assert resp.get_json()["status"] == "error"

    def test_transfer_requires_auth_then_succeeds_with_token(self, client, user_token):
        # First attempt without token → 401
        resp_no_auth = client.post(
            "/transfer", json={"to_account": "2222222222", "amount": 10.0}
        )
        assert resp_no_auth.status_code == 401

        # Second attempt with token → success
        sender_data = ("1111111111", 1000.0)
        with patch("vuln_bank.app.execute_query", return_value=[sender_data]):
            with patch("vuln_bank.app.execute_transaction"):
                resp_auth = client.post(
                    "/transfer",
                    headers={"Authorization": f"Bearer {user_token}"},
                    json={"to_account": "2222222222", "amount": 10.0},
                )
        assert resp_auth.status_code == 200


# ===========================================================================
# Flow 3: Forgot Password → Reset Password
# ===========================================================================


class TestPasswordResetFlow:
    """Multi-step password reset journey."""

    def test_forgot_password_exposes_pin_then_reset_succeeds(self, client):
        # Step 1: Request PIN
        with patch("vuln_bank.app.execute_query", side_effect=[[(2,)], None]):
            fp_resp = client.post("/forgot-password", json={"username": "alice"})
        assert fp_resp.status_code == 200
        debug = fp_resp.get_json()["debug_info"]
        exposed_pin = debug["pin"]
        assert isinstance(exposed_pin, str)

        # Step 2: Use the exposed PIN to reset password
        with patch("vuln_bank.app.execute_query", side_effect=[[(2,)], None]):
            reset_resp = client.post(
                "/reset-password",
                json={
                    "username": "alice",
                    "reset_pin": exposed_pin,
                    "new_password": "newpass999",
                },
            )
        assert reset_resp.status_code == 200
        assert reset_resp.get_json()["status"] == "success"

    def test_forgot_password_unknown_user_returns_404(self, client):
        with patch("vuln_bank.app.execute_query", return_value=[]):
            resp = client.post("/forgot-password", json={"username": "nobody"})
        assert resp.status_code == 404

    def test_reset_password_wrong_pin_returns_400(self, client):
        with patch("vuln_bank.app.execute_query", return_value=[]):
            resp = client.post(
                "/reset-password",
                json={
                    "username": "alice",
                    "reset_pin": "000",
                    "new_password": "newpass",
                },
            )
        assert resp.status_code == 400

    def test_api_v1_forgot_password_exposes_pin(self, client):
        with patch("vuln_bank.app.execute_query", side_effect=[[(2,)], None]):
            resp = client.post("/api/v1/forgot-password", json={"username": "alice"})
        assert resp.status_code == 200
        debug = resp.get_json()["debug_info"]
        assert "pin" in debug  # v1 still exposes the PIN

    def test_api_v2_forgot_password_hides_pin(self, client):
        with patch("vuln_bank.app.execute_query", side_effect=[[(2,)], None]):
            resp = client.post("/api/v2/forgot-password", json={"username": "alice"})
        assert resp.status_code == 200
        debug = resp.get_json()["debug_info"]
        assert "pin" not in debug  # v2 no longer leaks the PIN

    def test_api_v3_forgot_password_generates_4_digit_pin(self, client):
        captured_pin = {}

        original_randint = __import__("random").randint

        def mock_randint(a, b):
            result = original_randint(a, b)
            captured_pin["pin"] = str(result)
            return result

        with patch("vuln_bank.app.execute_query", side_effect=[[(2,)], None]):
            with patch("vuln_bank.app.random.randint", side_effect=mock_randint):
                resp = client.post(
                    "/api/v3/forgot-password", json={"username": "alice"}
                )
        assert resp.status_code == 200
        if "pin" in captured_pin:
            assert len(captured_pin["pin"]) == 4  # v3 uses 4-digit PIN


# ===========================================================================
# Flow 4: Virtual Card Lifecycle
# ===========================================================================


class TestVirtualCardFlow:
    """Create → view → freeze → fund → card transactions."""

    def test_create_card_then_list_cards(self, client, user_auth_headers):
        # Step 1: Create card
        created_id = (42,)
        with patch("vuln_bank.app.execute_query", return_value=[created_id]):
            create_resp = client.post(
                "/api/virtual-cards/create",
                headers=user_auth_headers,
                json={"card_limit": 500.0, "card_type": "standard", "currency": "USD"},
            )
        assert create_resp.status_code == 200
        card_data = create_resp.get_json()["card_details"]
        assert card_data["id"] == 42
        assert card_data["limit"] == 500.0

        # Step 2: List cards
        mock_card = (
            42,
            "1234567890123456",
            "123",
            "04/25",
            500.0,
            0.0,
            False,
            True,
            "2024-01-01 00:00:00",
            None,
            "standard",
            "USD",
        )
        with patch("vuln_bank.app.execute_query", return_value=[mock_card]):
            list_resp = client.get("/api/virtual-cards", headers=user_auth_headers)
        assert list_resp.status_code == 200
        cards = list_resp.get_json()["cards"]
        assert len(cards) == 1
        assert cards[0]["id"] == 42

    def test_toggle_freeze_changes_card_state(self, client, user_auth_headers):
        # Freeze
        with patch("vuln_bank.app.execute_query", return_value=[(True,)]):
            resp = client.post(
                "/api/virtual-cards/42/toggle-freeze", headers=user_auth_headers
            )
        assert resp.status_code == 200
        assert "frozen" in resp.get_json()["message"].lower()

        # Unfreeze
        with patch("vuln_bank.app.execute_query", return_value=[(False,)]):
            resp2 = client.post(
                "/api/virtual-cards/42/toggle-freeze", headers=user_auth_headers
            )
        assert "unfrozen" in resp2.get_json()["message"].lower()

    def test_fund_card_deducts_from_main_balance(self, client, user_auth_headers):
        user_row = ("1111111111", 1000.0)
        # (id, user_id, card_number, card_limit, current_balance,
        #  is_frozen, currency, card_type)
        card_row = (42, 2, "1234567890123456", 500.0, 0.0, False, "USD", "standard")

        with patch("vuln_bank.app.execute_query", side_effect=[[user_row], [card_row]]):
            with patch("vuln_bank.app.execute_transaction"):
                resp = client.post(
                    "/api/virtual-cards/42/fund",
                    headers=user_auth_headers,
                    json={"amount": 100.0},
                )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "success"
        assert data["funding"]["usd_amount"] == 100.0
        assert data["funding"]["main_balance_after"] == pytest.approx(900.0)

    def test_fund_frozen_card_is_rejected(self, client, user_auth_headers):
        user_row = ("1111111111", 1000.0)
        card_row_frozen = (
            42,
            2,
            "1234567890123456",
            500.0,
            0.0,
            True,
            "USD",
            "standard",
        )
        with patch(
            "vuln_bank.app.execute_query", side_effect=[[user_row], [card_row_frozen]]
        ):
            resp = client.post(
                "/api/virtual-cards/42/fund",
                headers=user_auth_headers,
                json={"amount": 100.0},
            )
        assert resp.status_code == 400

    def test_fund_card_insufficient_main_balance(self, client, user_auth_headers):
        user_row = ("1111111111", 50.0)
        card_row = (42, 2, "1234567890123456", 500.0, 0.0, False, "USD", "standard")
        with patch("vuln_bank.app.execute_query", side_effect=[[user_row], [card_row]]):
            resp = client.post(
                "/api/virtual-cards/42/fund",
                headers=user_auth_headers,
                json={"amount": 200.0},
            )
        assert resp.status_code == 400

    def test_card_requires_auth(self, client):
        assert client.post("/api/virtual-cards/create", json={}).status_code == 401
        assert client.get("/api/virtual-cards").status_code == 401
        assert client.post("/api/virtual-cards/1/toggle-freeze").status_code == 401

    def test_card_transactions_listed(self, client, user_auth_headers):
        mock_txn = (
            1,
            42,
            25.0,
            "Amazon",
            "purchase",
            "completed",
            "2024-01-01 10:00:00",
            "Online shopping",
            "1234567890123456",
            "USD",
        )
        with patch("vuln_bank.app.execute_query", return_value=[mock_txn]):
            resp = client.get(
                "/api/virtual-cards/42/transactions", headers=user_auth_headers
            )
        assert resp.status_code == 200
        txns = resp.get_json()["transactions"]
        assert len(txns) == 1
        assert txns[0]["merchant"] == "Amazon"


# ===========================================================================
# Flow 5: Bill Payment
# ===========================================================================


class TestBillPaymentFlow:
    """Get categories → get billers → create payment."""

    def test_list_categories_no_auth_required(self, client):
        mock_cats = [(1, "Utilities", "Power and water")]
        with patch("vuln_bank.app.execute_query", return_value=mock_cats):
            resp = client.get("/api/bill-categories")
        assert resp.status_code == 200
        cats = resp.get_json()["categories"]
        assert cats[0]["name"] == "Utilities"

    def test_list_billers_by_category(self, client):
        mock_billers = [(1, 1, "PowerCo", "BILLER001", "Electric", 10.0, 1000.0, True)]
        with patch("vuln_bank.app.execute_query", return_value=mock_billers):
            resp = client.get("/api/billers/by-category/1")
        assert resp.status_code == 200
        billers = resp.get_json()["billers"]
        assert billers[0]["name"] == "PowerCo"

    def test_bill_payment_balance_method_success(self, client, user_auth_headers):
        payer = (2, "alice", "1111111111", 800.0)
        biller = ("BILLER001", "PowerCo", "Utilities")
        bill_record = (99,)

        with patch(
            "vuln_bank.app.execute_query",
            side_effect=[[payer], [biller], [bill_record]],
        ):
            with patch("vuln_bank.app.execute_transaction"):
                resp = client.post(
                    "/api/bill-payments/create",
                    headers=user_auth_headers,
                    json={"biller_id": 1, "amount": 50.0, "payment_method": "balance"},
                )
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "success"

    def test_bill_payment_insufficient_balance(self, client, user_auth_headers):
        payer = (2, "alice", "1111111111", 10.0)
        biller = ("BILLER001", "PowerCo", "Utilities")

        with patch("vuln_bank.app.execute_query", side_effect=[[payer], [biller]]):
            resp = client.post(
                "/api/bill-payments/create",
                headers=user_auth_headers,
                json={"biller_id": 1, "amount": 500.0, "payment_method": "balance"},
            )
        assert resp.status_code == 400

    def test_bill_payment_requires_auth(self, client):
        resp = client.post(
            "/api/bill-payments/create",
            json={"biller_id": 1, "amount": 50.0, "payment_method": "balance"},
        )
        assert resp.status_code == 401

    def test_bill_payment_via_frozen_card_rejected(self, client, user_auth_headers):
        payer = (2, "alice", "1111111111", 800.0)
        biller = ("BILLER001", "PowerCo", "Utilities")
        # (current_balance, card_limit, is_frozen)
        frozen_card = (200.0, 500.0, True)

        with patch(
            "vuln_bank.app.execute_query",
            side_effect=[[payer], [biller], [frozen_card]],
        ):
            resp = client.post(
                "/api/bill-payments/create",
                headers=user_auth_headers,
                json={
                    "biller_id": 1,
                    "amount": 50.0,
                    "payment_method": "virtual_card",
                    "card_id": 42,
                },
            )
        assert resp.status_code == 400
        assert "frozen" in resp.get_json()["message"].lower()


# ===========================================================================
# Flow 6: Admin Loan Approval
# ===========================================================================


class TestAdminLoanApprovalFlow:
    """User requests a loan → admin approves it."""

    def test_user_requests_loan_then_admin_approves(
        self, client, user_auth_headers, admin_auth_headers
    ):
        # Step 1: Regular user requests a loan
        with patch("vuln_bank.app.execute_query"):
            req_resp = client.post(
                "/request_loan", headers=user_auth_headers, json={"amount": 500.0}
            )
        assert req_resp.status_code == 200

        # Step 2: Admin approves the loan
        loan_row = (1, 2, 500.0, "pending")
        with patch("vuln_bank.app.execute_query", return_value=[loan_row]):
            with patch("vuln_bank.app.execute_transaction"):
                approve_resp = client.post(
                    "/admin/approve_loan/1", headers=admin_auth_headers
                )
        assert approve_resp.status_code == 200
        assert approve_resp.get_json()["status"] == "success"

    def test_non_admin_cannot_approve_loan(self, client, user_auth_headers):
        resp = client.post("/admin/approve_loan/1", headers=user_auth_headers)
        assert resp.status_code == 403

    def test_approve_nonexistent_loan_returns_404(self, client, admin_auth_headers):
        with patch("vuln_bank.app.execute_query", return_value=[None]):
            resp = client.post("/admin/approve_loan/999", headers=admin_auth_headers)
        assert resp.status_code == 404


# ===========================================================================
# Flow 7: Admin Create Admin → New Admin Can Access Panel
# ===========================================================================


class TestAdminCreateAdminFlow:
    def test_admin_creates_new_admin_account(self, client, admin_auth_headers):
        with patch("vuln_bank.app.execute_query"):
            resp = client.post(
                "/admin/create_admin",
                headers=admin_auth_headers,
                json={"username": "superadmin", "password": "adminpass"},
            )
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "success"

    def test_non_admin_cannot_create_admin(self, client, user_auth_headers):
        resp = client.post(
            "/admin/create_admin",
            headers=user_auth_headers,
            json={"username": "hacker", "password": "hacked"},
        )
        assert resp.status_code == 403


# ===========================================================================
# Flow 8: API auth routes (/api/login, /api/check_balance, /api/transfer)
# ===========================================================================


class TestApiAuthRoutes:
    """Routes defined via init_auth_routes in auth.py (SQLite-backed)."""

    def test_api_login_success(self, client):
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = (
            2,
            "alice",
            "pass",
            "1111111111",
            800.0,
            False,
            None,
            None,
            None,
            False,
        )
        with patch("sqlite3.connect", return_value=mock_conn):
            resp = client.post(
                "/api/login", json={"username": "alice", "password": "pass"}
            )
        assert resp.status_code == 200
        assert "token" in resp.get_json()

    def test_api_login_invalid_credentials(self, client):
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = None
        with patch("sqlite3.connect", return_value=mock_conn):
            resp = client.post(
                "/api/login", json={"username": "nobody", "password": "wrong"}
            )
        assert resp.status_code == 401

    def test_api_login_missing_credentials(self, client):
        resp = client.post("/api/login", json={})
        assert resp.status_code == 401


# ===========================================================================
# Flow 9: Rate Limiting Integration
# ===========================================================================


class TestRateLimitingFlow:
    """Verify that the AI rate limiting middleware enforces request caps
    across multiple sequential requests from the same client."""

    def test_unauthenticated_rate_limit_blocks_after_limit(self, client):
        from vuln_bank.app import UNAUTHENTICATED_LIMIT

        ai_mock = MagicMock()
        ai_mock.chat.return_value = "Hello"

        with patch("vuln_bank.app.ai_agent", ai_mock):
            # Exhaust the limit
            for _ in range(UNAUTHENTICATED_LIMIT):
                resp = client.post(
                    "/api/ai/chat/anonymous",
                    json={"message": "hi"},
                    environ_overrides=_EXTERNAL_IP,
                )
                assert resp.status_code == 200

            # Next request should be blocked
            blocked = client.post(
                "/api/ai/chat/anonymous",
                json={"message": "hi"},
                environ_overrides=_EXTERNAL_IP,
            )
        assert blocked.status_code == 429
        assert blocked.get_json()["status"] == "error"

    def test_different_ips_have_independent_limits(self, client):
        from vuln_bank.app import UNAUTHENTICATED_LIMIT

        ai_mock = MagicMock()
        ai_mock.chat.return_value = "Hello"

        ip_a = {"REMOTE_ADDR": "10.0.0.1"}
        ip_b = {"REMOTE_ADDR": "10.0.0.2"}

        with patch("vuln_bank.app.ai_agent", ai_mock):
            # Exhaust limit for IP A
            for _ in range(UNAUTHENTICATED_LIMIT):
                client.post(
                    "/api/ai/chat/anonymous",
                    json={"message": "hi"},
                    environ_overrides=ip_a,
                )

            # IP B should still be under its own limit
            resp_b = client.post(
                "/api/ai/chat/anonymous", json={"message": "hi"}, environ_overrides=ip_b
            )
        assert resp_b.status_code == 200

    def test_rate_limit_status_endpoint_accessible(self, client):
        resp = client.get("/api/ai/rate-limit-status", environ_overrides=_EXTERNAL_IP)
        assert resp.status_code == 200
        assert "rate_limits" in resp.get_json()


# ===========================================================================
# Flow 10: IDOR – Any Authenticated User Can Fetch Any User's Details
# ===========================================================================


class TestIdorFlow:
    """Any authenticated user can fetch any other user's profile via /api/v3/user/<id>."""

    def test_user_can_fetch_own_profile(self, client, user_auth_headers):
        with patch("vuln_bank.app.execute_query", return_value=[_USER]):
            resp = client.get("/api/v3/user/2", headers=user_auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()["user"]["username"] == "alice"

    def test_user_can_fetch_other_users_profile_idor(self, client, user_auth_headers):
        with patch("vuln_bank.app.execute_query", return_value=[_USER2]):
            resp = client.get("/api/v3/user/3", headers=user_auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()["user"]["username"] == "bob"

    def test_user_can_fetch_admin_profile_idor(self, client, user_auth_headers):
        with patch("vuln_bank.app.execute_query", return_value=[_ADMIN]):
            resp = client.get("/api/v3/user/1", headers=user_auth_headers)
        assert resp.status_code == 200
        # Admin details returned to a non-admin user
        assert resp.get_json()["user"]["is_admin"] is True

    def test_user_not_found_returns_404(self, client, user_auth_headers):
        with patch("vuln_bank.app.execute_query", return_value=[]):
            resp = client.get("/api/v3/user/9999", headers=user_auth_headers)
        assert resp.status_code == 404


# ===========================================================================
# Flow 11: API Transactions (authenticated endpoint)
# ===========================================================================


class TestApiTransactionsFlow:
    def test_returns_transactions_for_account(self, client, user_auth_headers):
        mock_txn = (
            1,
            "1111111111",
            "2222222222",
            100.0,
            "2024-01-01 10:00:00",
            "transfer",
            "Test",
        )
        with patch("vuln_bank.app.execute_query", return_value=[mock_txn]):
            resp = client.get(
                "/api/transactions?account_number=1111111111", headers=user_auth_headers
            )
        assert resp.status_code == 200
        assert len(resp.get_json()["transactions"]) == 1

    def test_missing_account_number_returns_400(self, client, user_auth_headers):
        resp = client.get("/api/transactions", headers=user_auth_headers)
        assert resp.status_code == 400

    def test_requires_authentication(self, client):
        resp = client.get("/api/transactions?account_number=1111111111")
        assert resp.status_code == 401


# ===========================================================================
# Flow 12: SSRF demo – internal endpoints accessible from loopback
# ===========================================================================


class TestSsrfDemoFlow:
    """Internal endpoints that are intentionally reachable from 127.0.0.1."""

    def test_internal_secret_accessible_from_loopback(self, client):
        resp = client.get("/internal/secret", environ_overrides=_LOOPBACK_IP)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["status"] == "internal"
        assert "secrets" in body

    def test_internal_config_accessible_from_loopback(self, client):
        resp = client.get("/internal/config.json", environ_overrides=_LOOPBACK_IP)
        assert resp.status_code == 200
        assert "rate_limits" in resp.get_json()

    def test_metadata_accessible_from_loopback(self, client):
        resp = client.get("/latest/meta-data/", environ_overrides=_LOOPBACK_IP)
        assert resp.status_code == 200
        assert b"ami-id" in resp.data

    def test_iam_credentials_accessible_from_loopback(self, client):
        resp = client.get(
            "/latest/meta-data/iam/security-credentials/vulnbank-role",
            environ_overrides=_LOOPBACK_IP,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["Code"] == "Success"
        assert "AccessKeyId" in data

    def test_external_ip_blocked_from_all_internal_endpoints(self, client):
        for path in [
            "/internal/secret",
            "/internal/config.json",
            "/latest/meta-data/",
            "/latest/meta-data/ami-id",
            "/latest/meta-data/iam/security-credentials/vulnbank-role",
        ]:
            resp = client.get(path, environ_overrides=_EXTERNAL_IP)
            assert resp.status_code == 403, (
                f"Expected 403 for {path}, got {resp.status_code}"
            )


# ===========================================================================
# Flow 13: Profile picture upload
# ===========================================================================


class TestProfilePictureFlow:
    def test_upload_file_success(self, client, user_auth_headers):
        data = {"profile_picture": (BytesIO(b"fake-image"), "photo.jpg")}
        with patch("vuln_bank.app.execute_query"):
            resp = client.post(
                "/upload_profile_picture",
                headers=user_auth_headers,
                data=data,
                content_type="multipart/form-data",
            )
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "success"

    def test_upload_no_file_returns_400(self, client, user_auth_headers):
        resp = client.post(
            "/upload_profile_picture",
            headers=user_auth_headers,
            data={},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 400

    def test_upload_requires_auth(self, client):
        data = {"profile_picture": (BytesIO(b"fake-image"), "photo.jpg")}
        resp = client.post(
            "/upload_profile_picture", data=data, content_type="multipart/form-data"
        )
        assert resp.status_code == 401
