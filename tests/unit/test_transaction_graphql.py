"""Unit tests for pure helper functions in vuln_bank.transaction_graphql.

Functions that require database access are tested by mocking execute_query;
purely computational helpers are tested directly.
"""

import math
from unittest.mock import patch

import pytest

from vuln_bank.transaction_graphql import (
    _build_transaction_summary,
    _coerce_finite_float,
    _load_account_name_map,
    _load_transactions,
    _load_user_actor,
    _resolve_scope,
)

# ---------------------------------------------------------------------------
# _coerce_finite_float
# ---------------------------------------------------------------------------


class TestCoerceFiniteFloat:
    def test_int_converts_to_float(self):
        assert _coerce_finite_float(42) == 42.0

    def test_string_number_converts(self):
        assert _coerce_finite_float("3.14") == pytest.approx(3.14)

    def test_none_returns_default(self):
        assert _coerce_finite_float(None) == 0.0

    def test_none_treated_as_zero(self):
        # None is converted via `value or 0` → 0 → 0.0, not the default
        assert _coerce_finite_float(None) == 0.0

    def test_inf_returns_default(self):
        assert _coerce_finite_float(math.inf) == 0.0

    def test_negative_inf_returns_default(self):
        assert _coerce_finite_float(-math.inf) == 0.0

    def test_nan_returns_default(self):
        assert _coerce_finite_float(math.nan) == 0.0

    def test_invalid_string_returns_default(self):
        assert _coerce_finite_float("not_a_number") == 0.0

    def test_zero(self):
        assert _coerce_finite_float(0) == 0.0

    def test_negative_value(self):
        assert _coerce_finite_float(-5.5) == pytest.approx(-5.5)

    def test_large_value(self):
        assert _coerce_finite_float(1_000_000.99) == pytest.approx(1_000_000.99)


# ---------------------------------------------------------------------------
# _load_user_actor
# ---------------------------------------------------------------------------


class TestLoadUserActor:
    def test_returns_actor_dict(self):
        mock_row = (7, "alice", "ACC001", False)
        with patch(
            "vuln_bank.transaction_graphql.execute_query", return_value=[mock_row]
        ):
            actor = _load_user_actor(7)
        assert actor == {
            "id": 7,
            "username": "alice",
            "account_number": "ACC001",
            "is_admin": False,
        }

    def test_is_admin_coerced_to_bool(self):
        mock_row = (1, "admin", "ADMIN001", True)
        with patch(
            "vuln_bank.transaction_graphql.execute_query", return_value=[mock_row]
        ):
            actor = _load_user_actor(1)
        assert actor["is_admin"] is True

    def test_raises_when_user_not_found(self):
        from graphql import GraphQLError

        with patch("vuln_bank.transaction_graphql.execute_query", return_value=[]):
            with pytest.raises(GraphQLError):
                _load_user_actor(999)


# ---------------------------------------------------------------------------
# _resolve_scope
# ---------------------------------------------------------------------------


class TestResolveScope:
    _regular_actor = {
        "id": 2,
        "username": "testuser",
        "account_number": "1234567890",
        "is_admin": False,
    }
    _admin_actor = {
        "id": 1,
        "username": "admin",
        "account_number": "0000000001",
        "is_admin": True,
    }

    def test_regular_user_no_account_number_scopes_to_own(self):
        account, scope, user_id = _resolve_scope(self._regular_actor, None)
        assert account == "1234567890"
        assert scope == "account"
        assert user_id == 2

    def test_admin_no_account_number_gets_global_scope(self):
        account, scope, user_id = _resolve_scope(self._admin_actor, None)
        assert account is None
        assert scope == "global"
        assert user_id is None

    def test_admin_with_account_number_scopes_to_that_account(self):
        mock_scoped = (3, "other", "9876543210", False)
        with patch(
            "vuln_bank.transaction_graphql.execute_query", return_value=[mock_scoped]
        ):
            account, scope, user_id = _resolve_scope(self._admin_actor, "9876543210")
        assert account == "9876543210"
        assert scope == "account"
        assert user_id == 3

    def test_regular_user_requesting_own_account_is_allowed(self):
        mock_scoped = (2, "testuser", "1234567890", False)
        with patch(
            "vuln_bank.transaction_graphql.execute_query", return_value=[mock_scoped]
        ):
            account, scope, user_id = _resolve_scope(self._regular_actor, "1234567890")
        assert account == "1234567890"

    def test_regular_user_requesting_other_account_raises(self):
        from graphql import GraphQLError

        with pytest.raises(GraphQLError):
            _resolve_scope(self._regular_actor, "9999999999")

    def test_admin_requesting_nonexistent_account_raises(self):
        from graphql import GraphQLError

        with patch("vuln_bank.transaction_graphql.execute_query", return_value=[]):
            with pytest.raises(GraphQLError):
                _resolve_scope(self._admin_actor, "0000000000")


# ---------------------------------------------------------------------------
# _load_transactions
# ---------------------------------------------------------------------------


class TestLoadTransactions:
    def test_returns_rows_for_scoped_account(self):
        mock_rows = [
            (1, "ACC1", "ACC2", 100.0, "2024-01-01", "transfer", "desc"),
        ]
        with patch(
            "vuln_bank.transaction_graphql.execute_query", return_value=mock_rows
        ) as mock_eq:
            result = _load_transactions("ACC1")
        assert result == mock_rows
        called_query = mock_eq.call_args[0][0]
        assert "WHERE" in called_query

    def test_global_scope_omits_where_clause(self):
        with patch(
            "vuln_bank.transaction_graphql.execute_query", return_value=[]
        ) as mock_eq:
            _load_transactions(None)
        called_query = mock_eq.call_args[0][0]
        assert "WHERE" not in called_query


# ---------------------------------------------------------------------------
# _load_account_name_map
# ---------------------------------------------------------------------------


class TestLoadAccountNameMap:
    def test_merges_users_and_billers(self):
        mock_users = [("ACC1", "Alice"), ("ACC2", "Bob")]
        mock_billers = [("BILLER1", "Electric Co")]
        with patch(
            "vuln_bank.transaction_graphql.execute_query",
            side_effect=[mock_users, mock_billers],
        ):
            name_map = _load_account_name_map()
        assert name_map["ACC1"] == "Alice"
        assert name_map["BILLER1"] == "Electric Co"

    def test_users_take_precedence_over_billers(self):
        # If same account number exists in both, user entry wins (setdefault)
        mock_users = [("SHARED_ACC", "User Name")]
        mock_billers = [("SHARED_ACC", "Biller Name")]
        with patch(
            "vuln_bank.transaction_graphql.execute_query",
            side_effect=[mock_users, mock_billers],
        ):
            name_map = _load_account_name_map()
        assert name_map["SHARED_ACC"] == "User Name"


# ---------------------------------------------------------------------------
# _build_transaction_summary
# ---------------------------------------------------------------------------


class TestBuildTransactionSummary:
    _rows = [
        (1, "ACC1", "ACC2", 200.0, "2024-01-01", "transfer", "pay"),
        (2, "ACC2", "ACC1", 50.0, "2024-01-02", "transfer", "refund"),
    ]

    def _mock_lending_bill(self):
        """Return a side_effect list for execute_query covering name_map and
        lending/bill metric calls inside _build_transaction_summary."""
        users = [("ACC1", "Alice"), ("ACC2", "Bob")]
        billers = []
        loan_row = [(0.0, 0.0, 0)]
        bill_row = [(0.0, 0)]
        return [users, billers, loan_row, bill_row]

    def test_returns_dict(self):
        with patch(
            "vuln_bank.transaction_graphql.execute_query",
            side_effect=self._mock_lending_bill(),
        ):
            summary = _build_transaction_summary(self._rows, "ACC1", "account", 2, 5)
        assert isinstance(summary, dict)

    def test_total_transactions_count(self):
        with patch(
            "vuln_bank.transaction_graphql.execute_query",
            side_effect=self._mock_lending_bill(),
        ):
            summary = _build_transaction_summary(self._rows, "ACC1", "account", 2, 5)
        assert summary["total_transactions"] == 2

    def test_total_volume_is_sum_of_absolute_amounts(self):
        with patch(
            "vuln_bank.transaction_graphql.execute_query",
            side_effect=self._mock_lending_bill(),
        ):
            summary = _build_transaction_summary(self._rows, "ACC1", "account", 2, 5)
        assert summary["total_volume"] == pytest.approx(250.0)

    def test_largest_transaction(self):
        with patch(
            "vuln_bank.transaction_graphql.execute_query",
            side_effect=self._mock_lending_bill(),
        ):
            summary = _build_transaction_summary(self._rows, "ACC1", "account", 2, 5)
        assert summary["largest_transaction"] == pytest.approx(200.0)

    def test_recent_transactions_respect_limit(self):
        rows = self._rows * 5  # 10 rows
        side = self._mock_lending_bill()
        with patch("vuln_bank.transaction_graphql.execute_query", side_effect=side):
            summary = _build_transaction_summary(rows, "ACC1", "account", 2, 3)
        assert len(summary["recent_transactions"]) <= 3

    def test_global_scope_sums_all_transactions(self):
        with patch(
            "vuln_bank.transaction_graphql.execute_query",
            side_effect=self._mock_lending_bill(),
        ):
            summary = _build_transaction_summary(self._rows, None, "global", None, 5)
        assert summary["total_transactions"] == 2
        assert summary["scope"] == "global"
