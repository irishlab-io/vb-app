"""Unit tests for the feature flag framework (vuln_bank.feature_flags)."""

from __future__ import annotations

import threading
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from vuln_bank.feature_flags import FeatureFlags, _DEFAULTS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_yaml(path: Path, data: dict) -> None:
    path.write_text(yaml.safe_dump(data))


# ---------------------------------------------------------------------------
# FeatureFlags.is_enabled — default behaviour (no config file)
# ---------------------------------------------------------------------------


class TestIsEnabledDefaults:
    def test_known_flag_enabled_by_default(self, tmp_path):
        ff = FeatureFlags(config_path=tmp_path / "missing.yml")
        for name in _DEFAULTS:
            assert ff.is_enabled(name) is True, f"Flag '{name}' should default to True"

    def test_unknown_flag_defaults_to_true(self, tmp_path):
        ff = FeatureFlags(config_path=tmp_path / "missing.yml")
        assert ff.is_enabled("nonexistent_feature") is True

    def test_all_flags_snapshot_matches_defaults(self, tmp_path):
        ff = FeatureFlags(config_path=tmp_path / "missing.yml")
        assert ff.all_flags() == _DEFAULTS


# ---------------------------------------------------------------------------
# Loading from YAML — features: mapping style
# ---------------------------------------------------------------------------


class TestLoadFromYaml:
    def test_flag_disabled_via_yaml(self, tmp_path):
        cfg = tmp_path / "feature_flags.yml"
        _write_yaml(cfg, {"features": {"graphql": False}})
        ff = FeatureFlags(config_path=cfg)
        assert ff.is_enabled("graphql") is False

    def test_other_flags_still_enabled(self, tmp_path):
        cfg = tmp_path / "feature_flags.yml"
        _write_yaml(cfg, {"features": {"graphql": False}})
        ff = FeatureFlags(config_path=cfg)
        assert ff.is_enabled("registration") is True

    def test_all_flags_disabled(self, tmp_path):
        cfg = tmp_path / "feature_flags.yml"
        _write_yaml(cfg, {"features": {name: False for name in _DEFAULTS}})
        ff = FeatureFlags(config_path=cfg)
        for name in _DEFAULTS:
            assert ff.is_enabled(name) is False, f"Flag '{name}' should be False"

    def test_all_flags_explicitly_enabled(self, tmp_path):
        cfg = tmp_path / "feature_flags.yml"
        _write_yaml(cfg, {"features": {name: True for name in _DEFAULTS}})
        ff = FeatureFlags(config_path=cfg)
        for name in _DEFAULTS:
            assert ff.is_enabled(name) is True

    def test_flat_mapping_style_also_works(self, tmp_path):
        """YAML without a 'features' wrapper key is also accepted."""
        cfg = tmp_path / "feature_flags.yml"
        _write_yaml(cfg, {"registration": False})
        ff = FeatureFlags(config_path=cfg)
        assert ff.is_enabled("registration") is False

    def test_non_bool_value_is_ignored(self, tmp_path):
        cfg = tmp_path / "feature_flags.yml"
        _write_yaml(cfg, {"features": {"graphql": "yes"}})
        ff = FeatureFlags(config_path=cfg)
        # Non-bool value is ignored; default (True) is kept
        assert ff.is_enabled("graphql") is True

    def test_empty_yaml_uses_all_defaults(self, tmp_path):
        cfg = tmp_path / "feature_flags.yml"
        cfg.write_text("")
        ff = FeatureFlags(config_path=cfg)
        assert ff.all_flags() == _DEFAULTS

    def test_unknown_key_in_yaml_is_ignored(self, tmp_path):
        cfg = tmp_path / "feature_flags.yml"
        _write_yaml(cfg, {"features": {"future_feature": False}})
        ff = FeatureFlags(config_path=cfg)
        # The key is added to the flag store (defaults are True for unknown keys)
        # but it should not corrupt existing flags
        assert ff.is_enabled("registration") is True


# ---------------------------------------------------------------------------
# Reload
# ---------------------------------------------------------------------------


class TestReload:
    def test_reload_picks_up_new_value(self, tmp_path):
        cfg = tmp_path / "feature_flags.yml"
        _write_yaml(cfg, {"features": {"graphql": True}})
        ff = FeatureFlags(config_path=cfg)
        assert ff.is_enabled("graphql") is True

        _write_yaml(cfg, {"features": {"graphql": False}})
        ff.reload()
        assert ff.is_enabled("graphql") is False

    def test_reload_after_file_deleted_restores_defaults(self, tmp_path):
        cfg = tmp_path / "feature_flags.yml"
        _write_yaml(cfg, {"features": {"graphql": False}})
        ff = FeatureFlags(config_path=cfg)
        assert ff.is_enabled("graphql") is False

        cfg.unlink()
        ff.reload()
        assert ff.is_enabled("graphql") is True


# ---------------------------------------------------------------------------
# all_flags
# ---------------------------------------------------------------------------


class TestAllFlags:
    def test_returns_dict(self, tmp_path):
        ff = FeatureFlags(config_path=tmp_path / "missing.yml")
        result = ff.all_flags()
        assert isinstance(result, dict)

    def test_returns_copy_not_reference(self, tmp_path):
        ff = FeatureFlags(config_path=tmp_path / "missing.yml")
        snapshot = ff.all_flags()
        snapshot["registration"] = False
        # Internal state should be unchanged
        assert ff.is_enabled("registration") is True


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_reads_are_safe(self, tmp_path):
        ff = FeatureFlags(config_path=tmp_path / "missing.yml")
        errors: list[BaseException] = []

        def read():
            try:
                for _ in range(100):
                    ff.is_enabled("graphql")
            except BaseException as exc:  # noqa: BLE001 — collect any threading error
                errors.append(exc)

        threads = [threading.Thread(target=read) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []

    def test_concurrent_reload_and_read(self, tmp_path):
        cfg = tmp_path / "feature_flags.yml"
        _write_yaml(cfg, {"features": {"graphql": True}})
        ff = FeatureFlags(config_path=cfg)
        errors: list[BaseException] = []

        def reload_loop():
            try:
                for _ in range(20):
                    ff.reload()
            except BaseException as exc:  # noqa: BLE001 — collect any threading error
                errors.append(exc)

        def read_loop():
            try:
                for _ in range(100):
                    ff.is_enabled("graphql")
            except BaseException as exc:  # noqa: BLE001 — collect any threading error
                errors.append(exc)

        threads = [threading.Thread(target=reload_loop)] + [threading.Thread(target=read_loop) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []


# ---------------------------------------------------------------------------
# feature_required decorator (Flask integration)
# ---------------------------------------------------------------------------


class TestFeatureRequiredDecorator:
    """Test the feature_required decorator using a minimal Flask test client."""

    @pytest.fixture()
    def app_with_flags(self, tmp_path):
        """Return a tiny Flask app with two flag-gated routes."""
        from flask import Flask, jsonify

        from vuln_bank.feature_flags import FeatureFlags

        cfg = tmp_path / "ff.yml"
        _write_yaml(cfg, {"features": {"my_feature": True, "disabled_feature": False}})
        ff = FeatureFlags(config_path=cfg)

        flask_app = Flask(__name__)
        flask_app.config["TESTING"] = True

        @flask_app.route("/enabled")
        @ff.feature_required("my_feature")
        def enabled_route():
            return jsonify({"ok": True})

        @flask_app.route("/disabled")
        @ff.feature_required("disabled_feature")
        def disabled_route():
            return jsonify({"ok": True})

        return flask_app

    def test_enabled_feature_returns_200(self, app_with_flags):
        with app_with_flags.test_client() as c:
            resp = c.get("/enabled")
            assert resp.status_code == 200

    def test_disabled_feature_returns_404(self, app_with_flags):
        with app_with_flags.test_client() as c:
            resp = c.get("/disabled")
            assert resp.status_code == 404

    def test_disabled_feature_returns_json_error(self, app_with_flags):
        with app_with_flags.test_client() as c:
            resp = c.get("/disabled")
            data = resp.get_json()
            assert "error" in data
            assert "disabled_feature" in data["error"]

    def test_unknown_feature_defaults_enabled(self, tmp_path):
        """A flag that is not in the config file at all should default to enabled."""
        from flask import Flask, jsonify

        from vuln_bank.feature_flags import FeatureFlags

        cfg = tmp_path / "ff.yml"
        cfg.write_text("")
        ff = FeatureFlags(config_path=cfg)

        flask_app = Flask(__name__)
        flask_app.config["TESTING"] = True

        @flask_app.route("/mystery")
        @ff.feature_required("mystery_feature")
        def mystery_route():
            return jsonify({"ok": True})

        with flask_app.test_client() as c:
            resp = c.get("/mystery")
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Corrupt YAML — graceful degradation
# ---------------------------------------------------------------------------


class TestCorruptYaml:
    def test_invalid_yaml_falls_back_to_defaults(self, tmp_path):
        cfg = tmp_path / "feature_flags.yml"
        cfg.write_text(": invalid: yaml: {{{{")
        ff = FeatureFlags(config_path=cfg)
        assert ff.all_flags() == _DEFAULTS
