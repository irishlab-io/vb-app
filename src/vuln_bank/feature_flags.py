"""
Feature flag framework for VulnBank.

Flags are loaded from a YAML configuration file (``feature_flags.yml``)
located next to the package root.  Every flag defaults to ``True`` (enabled)
so the application works out-of-the-box with no configuration file present.

Typical usage
-------------
::

    from vuln_bank.feature_flags import feature_flags, feature_required

    # Programmatic check
    if feature_flags.is_enabled("graphql"):
        ...

    # Decorator — returns 404 when the named feature is disabled
    @app.route("/graphql", methods=["POST"])
    @feature_required("graphql")
    def graphql_endpoint():
        ...

Reloading
---------
Call ``feature_flags.reload()`` at runtime to re-read the YAML file without
restarting the process.
"""

from __future__ import annotations

import logging
import threading
from functools import wraps
from pathlib import Path

import yaml
from flask import jsonify

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default flag values — all features enabled
# ---------------------------------------------------------------------------

_DEFAULTS: dict[str, bool] = {
    # Core banking
    "registration": True,
    "login": True,
    "dashboard": True,
    "transfers": True,
    "transactions": True,
    "check_balance": True,
    "loan_requests": True,
    "password_reset": True,
    # Virtual cards
    "virtual_cards": True,
    # Bill payments
    "bill_payments": True,
    # Profile
    "file_upload": True,
    "profile_bio": True,
    # GraphQL
    "graphql": True,
    # AI / chat
    "ai_chat": True,
    "ai_chat_anonymous": True,
    "ai_system_info": True,
    # Admin
    "admin_panel": True,
    # Debug / internal / intentionally-vulnerable endpoints
    "debug_endpoints": True,
    "internal_endpoints": True,
    "ssrf_endpoints": True,
}

# Path to the YAML config file.  By default we look for ``feature_flags.yml``
# two directories above this file (i.e. the project root):
#   parents[0] → src/vuln_bank
#   parents[1] → src
#   parents[2] → project root
_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "feature_flags.yml"


class FeatureFlags:
    """Thread-safe, YAML-backed feature flag registry."""

    def __init__(self, config_path: Path | None = None) -> None:
        self._config_path: Path = config_path or _DEFAULT_CONFIG_PATH
        self._lock = threading.RLock()
        self._flags: dict[str, bool] = {}
        self.reload()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reload(self) -> None:
        """
        Reload flags from the YAML file.

        Missing file → all defaults apply.
        Unknown keys in the file are ignored.
        Unknown keys in defaults (not in file) keep their default value.
        """
        loaded: dict[str, bool] = {}
        if self._config_path.exists():
            try:
                raw = yaml.safe_load(self._config_path.read_text()) or {}
                features = raw.get("features", raw)
                for key, value in features.items():
                    if isinstance(value, bool):
                        loaded[key] = value
                    else:
                        logger.warning("feature_flags: non-bool value for '%s' — ignored", key)
            except Exception:
                logger.exception("feature_flags: failed to load %s — using defaults", self._config_path)
        else:
            logger.info("feature_flags: config file not found at %s — all features enabled", self._config_path)

        with self._lock:
            merged = dict(_DEFAULTS)
            merged.update(loaded)
            self._flags = merged

    def is_enabled(self, name: str) -> bool:
        """Return ``True`` when *name* is enabled (default: ``True``)."""
        with self._lock:
            return self._flags.get(name, True)

    def all_flags(self) -> dict[str, bool]:
        """Return a snapshot of every registered flag and its current value."""
        with self._lock:
            return dict(self._flags)

    # ------------------------------------------------------------------
    # Flask decorator
    # ------------------------------------------------------------------

    def feature_required(self, name: str):
        """
        Decorator that returns 404 when the named feature is disabled.

        Example::

            @app.route("/graphql", methods=["POST"])
            @feature_required("graphql")
            def graphql_endpoint():
                ...
        """

        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                if not self.is_enabled(name):
                    return jsonify({"error": f"Feature '{name}' is disabled"}), 404

                return f(*args, **kwargs)

            return wrapper

        return decorator


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

feature_flags = FeatureFlags()
feature_required = feature_flags.feature_required
