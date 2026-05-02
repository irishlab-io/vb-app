"""
E2e banking tests – complete user-journey scenarios.

Each test class simulates an end-to-end user story: from unauthenticated
entry through the full operation cycle.  The only substitution is at the
database boundary (execute_query / execute_transaction); auth middleware,
rate-limiting, and serialisation all run normally.
"""

from io import BytesIO
from unittest.mock import patch

import pytest

from .conftest import E2E_USER

# ===========================================================================
# Journey 1: New user registers, logs in, operates on their account
# ===========================================================================


class TestNewUserBankingJourney:
    """
    Simulates a brand-new customer from registration through day-to-day
    banking operations (balance check, transfer, transaction history,
    profile update).
    """

    def test_register_login_balance_transfer_history(self, e2e_client):
        """Complete new-user onboarding + first transfer in one session."""

        # ── Step 1: Register ──────────────────────────────────────────────
        with patch("vuln_bank.app.execute_query", side_effect=[[], [E2E_USER]]):
            reg = e2e_client.post(
                "/register",
                json={"username": "e2euser", "password": "e2epass"},
            )
        assert reg.status_code == 200
        assert reg.get_json()["status"] == "success"

        # ── Step 2: Login ─────────────────────────────────────────────────
        with patch("vuln_bank.app.execute_query", return_value=[E2E_USER]):
            login = e2e_client.post(
                "/login",
                json={"username": "e2euser", "password": "e2epass"},
            )
        assert login.status_code == 200
        token = login.get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # ── Step 3: Dashboard ─────────────────────────────────────────────
        with patch("vuln_bank.app.execute_query", side_effect=[[E2E_USER], []]):
            dash = e2e_client.get("/dashboard", headers=headers)
        assert dash.status_code == 200

        # ── Step 4: Transfer ──────────────────────────────────────────────
        sender_data = ("9000000001", 5000.0)
        with patch("vuln_bank.app.execute_query", return_value=[sender_data]):
            with patch("vuln_bank.app.execute_transaction"):
                xfer = e2e_client.post(
                    "/transfer",
                    headers=headers,
                    json={
                        "to_account": "9000000002",
                        "amount": 200.0,
                        "description": "E2E payment",
                    },
                )
        assert xfer.status_code == 200
        assert xfer.get_json()["new_balance"] == pytest.approx(4800.0)

        # ── Step 5: Transaction history ───────────────────────────────────
        txn_row = (
            1,
            "9000000001",
            "9000000002",
            200.0,
            "2024-06-01 12:00:00",
            "transfer",
            "E2E payment",
        )
        with patch("vuln_bank.app.execute_query", return_value=[txn_row]):
            hist = e2e_client.get("/transactions/9000000001", headers=headers)
        assert hist.status_code == 200
        txns = hist.get_json()["transactions"]
        assert len(txns) == 1
        assert txns[0]["amount"] == 200.0

    def test_update_bio_persists(self, e2e_client, user_auth_headers):
        with patch("vuln_bank.app.execute_query", return_value=[E2E_USER]):
            with patch("vuln_bank.app.execute_transaction"):
                resp = e2e_client.post(
                    "/update_bio",
                    headers=user_auth_headers,
                    json={"bio": "Testing the bank E2E"},
                )
        assert resp.status_code == 200
        assert resp.get_json()["message"] == "Bio updated successfully"

    def test_profile_picture_upload_then_dashboard_shows_picture(
        self, e2e_client, user_auth_headers
    ):
        """Uploading a profile picture should not break the dashboard."""
        img_data = BytesIO(
            b"GIF89a\x01\x00\x01\x00\x00\xff\x00,\x00\x00"
            b"\x00\x00\x01\x00\x01\x00\x00\x02\x00;"
        )
        img_data.name = "avatar.gif"

        with patch("vuln_bank.app.execute_transaction"):
            up = e2e_client.post(
                "/upload_profile_picture",
                headers=user_auth_headers,
                data={"profile_picture": (img_data, "avatar.gif")},
                content_type="multipart/form-data",
            )
        assert up.status_code == 200

        # Dashboard still loads after profile update
        with patch("vuln_bank.app.execute_query", side_effect=[[E2E_USER], []]):
            dash = e2e_client.get("/dashboard", headers=user_auth_headers)
        assert dash.status_code == 200

    def test_check_balance_by_account_number(self, e2e_client):
        """Unauthenticated balance check via account number."""
        account_row = ("9000000001", 5000.0)
        with patch("vuln_bank.app.execute_query", return_value=[account_row]):
            resp = e2e_client.get("/check_balance/9000000001")
        assert resp.status_code == 200
        assert resp.get_json()["balance"] == 5000.0


# ===========================================================================
# Journey 2: Virtual card full lifecycle
# ===========================================================================


class TestVirtualCardLifecycle:
    """
    Create a virtual card, fund it, view its transactions, freeze it,
    attempt a payment while frozen (expect rejection), then unfreeze.
    """

    # (id, user_id, card_number, card_limit, current_balance, is_frozen, currency, card_type)
    # Used by fund_virtual_card route (8 cols)
    _CARD_FUND_ROW = (1, 2, "4111111111111111", 500.0, 0.0, False, "USD", "standard")

    # Used by get_virtual_cards route (12 cols):
    # id, card_number, cvv, expiry_date, card_limit, current_balance,
    # is_frozen, is_active, created_at, last_used_at, card_type, currency
    _CARD_ACTIVE = (
        1,
        "4111111111111111",
        "123",
        "12/26",
        500.0,
        0.0,
        False,
        True,
        "2024-01-01",
        None,
        "standard",
        "USD",
    )
    _CARD_FUNDED = (
        1,
        "4111111111111111",
        "123",
        "12/26",
        500.0,
        200.0,
        False,
        True,
        "2024-01-01",
        None,
        "standard",
        "USD",
    )

    def test_create_then_fund_then_freeze_then_unfreeze(
        self, e2e_client, user_auth_headers
    ):
        # Create
        with patch(
            "vuln_bank.app.execute_query", return_value=[("9000000001", 5000.0)]
        ):
            with patch("vuln_bank.app.execute_transaction"):
                create = e2e_client.post(
                    "/api/virtual-cards/create",
                    headers=user_auth_headers,
                    json={"currency": "USD", "limit": 500.0},
                )
        assert create.status_code == 200

        # Fund: route queries user (account_number, balance) FIRST, then card
        # (id, user_id, card_number, card_limit, current_balance, is_frozen, currency, card_type)
        with patch(
            "vuln_bank.app.execute_query",
            side_effect=[[("9000000001", 5000.0)], [self._CARD_FUND_ROW]],
        ):
            with patch("vuln_bank.app.execute_transaction"):
                fund = e2e_client.post(
                    "/api/virtual-cards/1/fund",
                    headers=user_auth_headers,
                    json={"amount": 200.0},
                )
        assert fund.status_code == 200

        # List cards – shows funded balance
        with patch("vuln_bank.app.execute_query", return_value=[self._CARD_FUNDED]):
            cards = e2e_client.get("/api/virtual-cards", headers=user_auth_headers)
        assert cards.status_code == 200
        data = cards.get_json()["cards"]
        assert data[0]["balance"] == 200.0

        # Freeze: toggle route returns RETURNING is_frozen → (True,) means now frozen
        with patch("vuln_bank.app.execute_query", return_value=[(True,)]):
            freeze = e2e_client.post(
                "/api/virtual-cards/1/toggle-freeze",
                headers=user_auth_headers,
            )
        assert freeze.status_code == 200
        assert "frozen" in freeze.get_json()["message"].lower()

        # Unfreeze: RETURNING returns (False,) → now unfrozen
        with patch("vuln_bank.app.execute_query", return_value=[(False,)]):
            unfreeze = e2e_client.post(
                "/api/virtual-cards/1/toggle-freeze",
                headers=user_auth_headers,
            )
        assert unfreeze.status_code == 200
        assert "unfrozen" in unfreeze.get_json()["message"].lower()

    def test_card_transactions_visible_after_funding(
        self, e2e_client, user_auth_headers
    ):
        # SELECT ct.*, vc.card_number, vc.currency → 10 cols needed
        txn_row = (
            1,
            1,
            50.0,
            "merchant_x",
            "purchase",
            "completed",
            "2024-06-01 12:00:00",
            "Test payment",
            "4111111111111111",
            "USD",
        )
        with patch("vuln_bank.app.execute_query", return_value=[txn_row]):
            resp = e2e_client.get(
                "/api/virtual-cards/1/transactions",
                headers=user_auth_headers,
            )
        assert resp.status_code == 200
        txns = resp.get_json()["transactions"]
        assert len(txns) == 1


# ===========================================================================
# Journey 3: Bill payment end-to-end
# ===========================================================================


class TestBillPaymentJourney:
    """
    Browse categories → choose biller → pay bill → view payment history.
    """

    _CATEGORY = (1, "Utilities", "Electricity, water, gas", None)
    # Biller as returned by the JOIN query: (account_number, name, category_name)
    _BILLER_ROW = ("CITY_POWER_ACC", "City Power", "Utilities")
    # Payer as returned by users query: (id, username, account_number, balance)
    _PAYER_ROW = (2, "testuser", "9000000001", 5000.0)
    _PAYER_LOW = (2, "testuser", "9000000001", 5.0)
    # Payment history row – 14 cols: bp.* (11) + biller_name + category_name + card_number
    _PAYMENT = (
        1,
        2,
        1,
        200.0,
        "balance",
        None,
        "REF-0001",
        "success",
        "2024-06-01 12:00:00",
        None,
        "Bill Payment",
        "City Power",
        "Utilities",
        None,
    )

    def test_browse_categories_without_auth(self, e2e_client):
        """Bill categories are publicly accessible (no token required)."""
        with patch("vuln_bank.app.execute_query", return_value=[self._CATEGORY]):
            resp = e2e_client.get("/api/bill-categories")
        assert resp.status_code == 200
        cats = resp.get_json()["categories"]
        assert cats[0]["name"] == "Utilities"

    def test_browse_billers_by_category(self, e2e_client):
        # get_billers_by_category returns SELECT * FROM billers:
        # (id, category_id, name, account_number, description, min_amount, max_amount)
        _full_biller = (
            1,
            1,
            "City Power",
            "CITY_POWER_ACC",
            "Electric utility",
            10.0,
            10000.0,
        )
        with patch("vuln_bank.app.execute_query", return_value=[_full_biller]):
            resp = e2e_client.get("/api/billers/by-category/1")
        assert resp.status_code == 200
        assert resp.get_json()["billers"][0]["name"] == "City Power"

    def test_pay_bill_then_check_history(self, e2e_client, user_auth_headers):
        # Route queries payer (users) first, then biller.
        # payment_method="balance" triggers the balance-check path.
        with patch(
            "vuln_bank.app.execute_query",
            side_effect=[[self._PAYER_ROW], [self._BILLER_ROW]],
        ):
            with patch("vuln_bank.app.execute_transaction"):
                pay = e2e_client.post(
                    "/api/bill-payments/create",
                    headers=user_auth_headers,
                    json={"biller_id": 1, "amount": 200.0, "payment_method": "balance"},
                )
        assert pay.status_code == 200

        # History row needs 14 columns (bp.* 11 + biller_name + category + card)
        with patch("vuln_bank.app.execute_query", return_value=[self._PAYMENT]):
            hist = e2e_client.get(
                "/api/bill-payments/history",
                headers=user_auth_headers,
            )
        assert hist.status_code == 200
        payments = hist.get_json()["payments"]
        assert len(payments) == 1
        assert payments[0]["amount"] == 200.0

    def test_bill_payment_blocked_when_insufficient_funds(
        self, e2e_client, user_auth_headers
    ):
        # payer first, biller second; balance=5 < amount=200
        with patch(
            "vuln_bank.app.execute_query",
            side_effect=[[self._PAYER_LOW], [self._BILLER_ROW]],
        ):
            pay = e2e_client.post(
                "/api/bill-payments/create",
                headers=user_auth_headers,
                json={"biller_id": 1, "amount": 200.0, "payment_method": "balance"},
            )
        assert pay.status_code == 400


# ===========================================================================
# Journey 4: Loan request through to admin approval
# ===========================================================================


class TestLoanRequestToApprovalJourney:
    """
    User requests a loan; admin then reviews and approves it.
    End-to-end test using separate token contexts.
    """

    _LOAN_ROW = (1, 2, 1000.0, "pending", "2024-06-01 00:00:00")
    _LOAN_ROW_APPROVED = (1, 2, 1000.0, "approved", "2024-06-01 00:00:00")

    def test_user_requests_loan(self, e2e_client, user_auth_headers):
        with patch("vuln_bank.app.execute_transaction"):
            resp = e2e_client.post(
                "/request_loan",
                headers=user_auth_headers,
                json={"amount": 1000.0},
            )
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "success"

    def test_admin_approves_loan_requested_by_user(
        self, e2e_client, user_auth_headers, admin_auth_headers
    ):
        # User submits loan request
        with patch("vuln_bank.app.execute_transaction"):
            e2e_client.post(
                "/request_loan",
                headers=user_auth_headers,
                json={"amount": 1000.0},
            )

        # Admin views admin panel: 4 queries (count users, list users,
        # count pending loans, list pending loans)
        with patch(
            "vuln_bank.app.execute_query",
            side_effect=[[(1,)], [], [(1,)], [self._LOAN_ROW]],
        ):
            panel = e2e_client.get("/sup3r_s3cr3t_admin", headers=admin_auth_headers)
        assert panel.status_code == 200

        # Admin approves the loan
        account_row = ("9000000001", 500.0)
        with patch(
            "vuln_bank.app.execute_query", side_effect=[[self._LOAN_ROW], [account_row]]
        ):
            with patch("vuln_bank.app.execute_transaction"):
                approve = e2e_client.post(
                    "/admin/approve_loan/1",
                    headers=admin_auth_headers,
                )
        assert approve.status_code == 200
        assert approve.get_json()["status"] == "success"

    def test_non_admin_cannot_approve_loan(self, e2e_client, user_auth_headers):
        resp = e2e_client.post("/admin/approve_loan/1", headers=user_auth_headers)
        assert resp.status_code == 403
