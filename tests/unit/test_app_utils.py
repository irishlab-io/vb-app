"""Unit tests for pure utility functions in vuln_bank.app that do not require a
database connection: currency helpers, random generators, and rate limiting."""
import time

import pytest

from vuln_bank.app import (
    CARD_CURRENCY_RATES,
    RATE_LIMIT_WINDOW,
    check_rate_limit,
    cleanup_rate_limit_storage,
    convert_usd_to_card_currency,
    generate_account_number,
    generate_card_number,
    generate_cvv,
    normalize_card_currency,
    rate_limit_storage,
)


# ---------------------------------------------------------------------------
# normalize_card_currency
# ---------------------------------------------------------------------------


class TestNormalizeCardCurrency:
    def test_usd_passthrough(self):
        assert normalize_card_currency("USD") == "USD"

    @pytest.mark.parametrize("currency", list(CARD_CURRENCY_RATES.keys()))
    def test_all_supported_currencies(self, currency):
        assert normalize_card_currency(currency) == currency

    def test_lowercase_is_normalised(self):
        assert normalize_card_currency("usd") == "USD"

    def test_mixed_case_is_normalised(self):
        assert normalize_card_currency("GbP") == "GBP"

    def test_unknown_currency_falls_back_to_usd(self):
        assert normalize_card_currency("XYZ") == "USD"

    def test_none_falls_back_to_usd(self):
        assert normalize_card_currency(None) == "USD"

    def test_empty_string_falls_back_to_usd(self):
        assert normalize_card_currency("") == "USD"


# ---------------------------------------------------------------------------
# convert_usd_to_card_currency
# ---------------------------------------------------------------------------


class TestConvertUsdToCardCurrency:
    def test_usd_to_usd_is_identity(self):
        assert convert_usd_to_card_currency(100.0, "USD") == 100.0

    def test_usd_to_gbp_applies_rate(self):
        expected = round(100.0 * CARD_CURRENCY_RATES["GBP"]["rate"], 2)
        assert convert_usd_to_card_currency(100.0, "GBP") == expected

    def test_usd_to_eur_applies_rate(self):
        expected = round(50.0 * CARD_CURRENCY_RATES["EUR"]["rate"], 2)
        assert convert_usd_to_card_currency(50.0, "EUR") == expected

    def test_btc_result_is_positive_float(self):
        result = convert_usd_to_card_currency(100.0, "BTC")
        assert isinstance(result, float)
        assert result > 0

    def test_btc_high_precision(self):
        result = convert_usd_to_card_currency(100.0, "BTC")
        # Precision for BTC is 8 decimal places
        assert result == round(result, 8)

    def test_unknown_currency_defaults_to_usd(self):
        assert convert_usd_to_card_currency(100.0, "INVALID") == 100.0

    def test_zero_amount_returns_zero(self):
        assert convert_usd_to_card_currency(0.0, "EUR") == 0.0

    def test_result_is_rounded_to_currency_precision(self):
        rate_info = CARD_CURRENCY_RATES["NGN"]
        expected = round(1.0 * rate_info["rate"], rate_info["precision"])
        assert convert_usd_to_card_currency(1.0, "NGN") == expected


# ---------------------------------------------------------------------------
# Random generators
# ---------------------------------------------------------------------------


class TestGenerateAccountNumber:
    def test_length_is_ten(self):
        assert len(generate_account_number()) == 10

    def test_contains_only_digits(self):
        assert generate_account_number().isdigit()

    def test_produces_different_values(self):
        numbers = {generate_account_number() for _ in range(20)}
        assert len(numbers) > 1


class TestGenerateCardNumber:
    def test_length_is_sixteen(self):
        assert len(generate_card_number()) == 16

    def test_contains_only_digits(self):
        assert generate_card_number().isdigit()

    def test_produces_different_values(self):
        numbers = {generate_card_number() for _ in range(20)}
        assert len(numbers) > 1


class TestGenerateCvv:
    def test_length_is_three(self):
        assert len(generate_cvv()) == 3

    def test_contains_only_digits(self):
        assert generate_cvv().isdigit()

    def test_produces_different_values(self):
        cvvs = {generate_cvv() for _ in range(30)}
        assert len(cvvs) > 1


# ---------------------------------------------------------------------------
# check_rate_limit
# ---------------------------------------------------------------------------


class TestCheckRateLimit:
    def test_first_request_is_allowed(self):
        allowed, count, limit = check_rate_limit("rl_key_1", 5)
        assert allowed is True
        assert count == 1

    def test_requests_under_limit_are_allowed(self):
        for _ in range(4):
            allowed, _, _ = check_rate_limit("rl_key_2", 5)
            assert allowed is True

    def test_request_equal_to_limit_is_blocked(self):
        key = "rl_key_3"
        for _ in range(5):
            check_rate_limit(key, 5)
        allowed, count, limit = check_rate_limit(key, 5)
        assert allowed is False
        assert limit == 5

    def test_independent_keys_do_not_interfere(self):
        for _ in range(5):
            check_rate_limit("rl_key_a", 5)
        allowed, _, _ = check_rate_limit("rl_key_b", 5)
        assert allowed is True

    def test_limit_one_blocks_on_second_request(self):
        key = "rl_key_strict"
        check_rate_limit(key, 1)
        allowed, _, _ = check_rate_limit(key, 1)
        assert allowed is False

    def test_returns_tuple_of_three(self):
        result = check_rate_limit("rl_key_tuple", 3)
        assert len(result) == 3


# ---------------------------------------------------------------------------
# cleanup_rate_limit_storage
# ---------------------------------------------------------------------------


class TestCleanupRateLimitStorage:
    def test_removes_stale_entries(self):
        old_time = time.time() - RATE_LIMIT_WINDOW - 10
        rate_limit_storage["stale_key"] = [(old_time, 1)]
        cleanup_rate_limit_storage()
        assert "stale_key" not in rate_limit_storage

    def test_keeps_recent_entries(self):
        rate_limit_storage["fresh_key"] = [(time.time(), 1)]
        cleanup_rate_limit_storage()
        assert "fresh_key" in rate_limit_storage

    def test_removes_empty_key_lists(self):
        rate_limit_storage["empty_key"] = []
        cleanup_rate_limit_storage()
        assert "empty_key" not in rate_limit_storage

    def test_mixed_entries_pruned_correctly(self):
        now = time.time()
        old_time = now - RATE_LIMIT_WINDOW - 1
        rate_limit_storage["mixed_key"] = [(old_time, 1), (now, 1)]
        cleanup_rate_limit_storage()
        # Key should survive because the recent entry remains
        assert "mixed_key" in rate_limit_storage
        remaining = rate_limit_storage["mixed_key"]
        assert all(ts > now - RATE_LIMIT_WINDOW for ts, _ in remaining)
