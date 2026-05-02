"""
E2e admin-operations tests.

These tests cover the complete admin-management surface: accessing the
admin panel, approving/rejecting loans, toggling user suspension, deleting
accounts, and promoting a user to admin.  All scenarios verify both the
happy path and privilege-enforcement (non-admin must be rejected with 403).
"""

from unittest.mock import patch

from .conftest import E2E_USER

# (id, amount, user_id, status, created_at)
_LOAN_PENDING = (1, 2, 1000.0, "pending", "2024-06-01 00:00:00")
_LOAN_APPROVED = (1, 2, 1000.0, "approved", "2024-06-01 00:00:00")


# ===========================================================================
# Admin panel access
# ===========================================================================


class TestAdminPanelAccess:
    """Only admin-flagged tokens may reach the admin panel."""

    def test_admin_can_access_panel(self, e2e_client, admin_auth_headers):
        # Admin panel makes 4 execute_query calls:
        # 1: SELECT COUNT(*) users  2: SELECT * users
        # 3: SELECT COUNT(*) loans  4: SELECT * loans
        with patch("vuln_bank.app.execute_query", side_effect=[[(1,)], [], [(0,)], []]):
            resp = e2e_client.get("/sup3r_s3cr3t_admin", headers=admin_auth_headers)
        assert resp.status_code == 200

    def test_non_admin_blocked_from_panel(self, e2e_client, user_auth_headers):
        resp = e2e_client.get("/sup3r_s3cr3t_admin", headers=user_auth_headers)
        assert resp.status_code == 403

    def test_unauthenticated_blocked_from_panel(self, e2e_client):
        resp = e2e_client.get("/sup3r_s3cr3t_admin")
        assert resp.status_code == 401


# ===========================================================================
# Loan management
# ===========================================================================


class TestAdminLoanManagement:
    """Admin approves and non-admin is blocked from loan approval."""

    def test_admin_approves_loan(self, e2e_client, admin_auth_headers):
        account_row = ("9000000001", 500.0)
        with patch(
            "vuln_bank.app.execute_query", side_effect=[[_LOAN_PENDING], [account_row]]
        ):
            with patch("vuln_bank.app.execute_transaction"):
                resp = e2e_client.post(
                    "/admin/approve_loan/1",
                    headers=admin_auth_headers,
                )
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "success"

    def test_admin_approve_nonexistent_loan_returns_500(
        self, e2e_client, admin_auth_headers
    ):
        # The route does execute_query(...)[0] which raises IndexError
        # when the loan is not found; the inner try/except returns 500.
        with patch("vuln_bank.app.execute_query", return_value=[]):
            resp = e2e_client.post(
                "/admin/approve_loan/9999",
                headers=admin_auth_headers,
            )
        assert resp.status_code == 500

    def test_non_admin_cannot_approve_loan(self, e2e_client, user_auth_headers):
        resp = e2e_client.post("/admin/approve_loan/1", headers=user_auth_headers)
        assert resp.status_code == 403


# ===========================================================================
# User suspension management
# ===========================================================================


class TestAdminUserSuspension:
    """Admin can toggle suspension; non-admin cannot."""

    # (id, username, is_suspended, is_admin) – 4 columns from SELECT query
    _USER_ACTIVE = (10, "e2euser", False, False)
    _USER_SUSPENDED = (10, "e2euser", True, False)

    def test_admin_suspends_user(self, e2e_client, admin_auth_headers):
        # Route: SELECT (4 cols) then UPDATE (fetch=False), both via execute_query
        with patch(
            "vuln_bank.app.execute_query", side_effect=[[self._USER_ACTIVE], []]
        ):
            resp = e2e_client.post(
                "/admin/toggle_suspension/10",
                headers=admin_auth_headers,
            )
        assert resp.status_code == 200
        assert "suspended" in resp.get_json()["message"].lower()

    def test_admin_unsuspends_user(self, e2e_client, admin_auth_headers):
        with patch(
            "vuln_bank.app.execute_query", side_effect=[[self._USER_SUSPENDED], []]
        ):
            resp = e2e_client.post(
                "/admin/toggle_suspension/10",
                headers=admin_auth_headers,
            )
        assert resp.status_code == 200
        assert "unsuspended" in resp.get_json()["message"].lower()

    def test_non_admin_cannot_toggle_suspension(self, e2e_client, user_auth_headers):
        resp = e2e_client.post("/admin/toggle_suspension/10", headers=user_auth_headers)
        assert resp.status_code == 403

    def test_suspend_nonexistent_user_returns_404(self, e2e_client, admin_auth_headers):
        with patch("vuln_bank.app.execute_query", return_value=[]):
            resp = e2e_client.post(
                "/admin/toggle_suspension/9999",
                headers=admin_auth_headers,
            )
        assert resp.status_code == 404


# ===========================================================================
# Account deletion
# ===========================================================================


class TestAdminAccountDeletion:
    """Admin can delete user accounts; non-admin cannot."""

    def test_admin_deletes_user_account(self, e2e_client, admin_auth_headers):
        with patch("vuln_bank.app.execute_query", return_value=[E2E_USER]):
            with patch("vuln_bank.app.execute_transaction"):
                resp = e2e_client.post(
                    "/admin/delete_account/10",
                    headers=admin_auth_headers,
                )
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "success"

    def test_admin_delete_nonexistent_account_still_returns_200(
        self, e2e_client, admin_auth_headers
    ):
        # The route issues DELETE unconditionally and always returns 200;
        # no row-count check → missing user is not detected (vulnerability).
        with patch("vuln_bank.app.execute_query", return_value=[]):
            resp = e2e_client.post(
                "/admin/delete_account/9999",
                headers=admin_auth_headers,
            )
        assert resp.status_code == 200

    def test_non_admin_cannot_delete_account(self, e2e_client, user_auth_headers):
        resp = e2e_client.post("/admin/delete_account/10", headers=user_auth_headers)
        assert resp.status_code == 403


# ===========================================================================
# Admin promotion (create_admin)
# ===========================================================================


class TestAdminPromotion:
    """Admin can create new admin accounts; non-admin cannot."""

    def test_admin_creates_new_admin(self, e2e_client, admin_auth_headers):
        with patch("vuln_bank.app.execute_query", return_value=[E2E_USER]):
            with patch("vuln_bank.app.execute_transaction"):
                resp = e2e_client.post(
                    "/admin/create_admin",
                    headers=admin_auth_headers,
                    json={"username": "e2euser"},
                )
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "success"

    def test_admin_promote_any_username_always_inserts(
        self, e2e_client, admin_auth_headers
    ):
        # The route performs a raw INSERT without checking if the user
        # exists first (SQL-injection vulnerable); it always returns 200.
        with patch("vuln_bank.app.execute_query", return_value=[]):
            resp = e2e_client.post(
                "/admin/create_admin",
                headers=admin_auth_headers,
                json={"username": "ghost", "password": "pass"},
            )
        assert resp.status_code == 200

    def test_non_admin_cannot_create_admin(self, e2e_client, user_auth_headers):
        resp = e2e_client.post(
            "/admin/create_admin",
            headers=user_auth_headers,
            json={"username": "e2euser"},
        )
        assert resp.status_code == 403

    def test_unauthenticated_cannot_create_admin(self, e2e_client):
        resp = e2e_client.post(
            "/admin/create_admin",
            json={"username": "e2euser"},
        )
        assert resp.status_code == 401
