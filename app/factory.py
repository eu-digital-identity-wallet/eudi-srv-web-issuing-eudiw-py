# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
"""Flask application factory of the EUDIW PID Issuer.

The PID Issuer Web service is a component of the PID Provider backend. Its
main goal is to issue the PID in cbor/mdoc (ISO 18013-5 mdoc) and SD-JWT
format.

Start-up work with external side effects (Postgres pool, nightly sweep
scheduler, trusted CA loading) happens in :func:`create_app`, never at
import time, and is skipped in test environments unless explicitly enabled
with ``INIT_BACKGROUND_SERVICES`` / ``LOAD_TRUSTED_CAS``.
"""

from __future__ import annotations

import os
import secrets
from typing import Any, Mapping, Optional

from flask import Flask, Response
from flask_cors import CORS
from flask_session import Session

from app.core import config as app_config
from app.core.errors import handle_exception, page_not_found
from app.core.logging_setup import configure_logging
from app.core.rate_limit import init_rate_limits
from app.utils.frontend import allowed_cors_origins, frontend_origins
from app.utils.http import AUTO_SUBMIT_SCRIPT_HASH, frontend_payload_key

#: Blueprints registered by :func:`create_app`, as ``(module, attribute)``.
BLUEPRINTS = (
    ("app.routes.oidc", "oidc"),
    ("app.routes.revocation", "revocation"),
    ("app.routes.oid4vp", "oid4vp"),
    ("app.routes.dynamic", "dynamic"),
    ("app.routes.preauth", "preauth"),
    ("app.routes.metadata", "metadata"),
)


def _register_blueprints(app: Flask) -> None:
    """Imports and registers every blueprint in :data:`BLUEPRINTS`.

    Args:
        app: The application.
    """
    import importlib

    for module_name, attribute in BLUEPRINTS:
        app.register_blueprint(getattr(importlib.import_module(module_name), attribute))


def _start_background_services(app: Flask) -> None:
    """Initializes the status persistence pool and starts the scheduler.

    Args:
        app: The application (for logging).
    """
    from app.repositories.status_store import init_db_status
    from app.services.scheduler import start_scheduler

    init_db_status(app_config.CONFIGURATION["postgres"])
    start_scheduler()
    app.logger.info("Background services started (status DB pool, scheduler).")


#: Defaults of ``session_file_threshold`` (server-side session files kept)
#: and ``max_content_length`` (largest request body, bytes).
DEFAULT_SESSION_FILE_THRESHOLD = 10000
DEFAULT_MAX_CONTENT_LENGTH = 1024 * 1024

#: Secret key values that are publicly known and must never sign sessions.
WEAK_SECRET_KEYS = frozenset({"dev", "change-me", "secret", "changeme"})
_MIN_SECRET_KEY_LENGTH = 32


def _check_secret_key(app: Flask) -> None:
    """Makes sure the session cookie signing key is a real secret.

    The key comes from ``secret_key`` in the configuration, the
    ``FLASK_SECRET_KEY`` environment variable or the instance ``config.py``.
    Under tests a random key is used when none is set.

    Args:
        app: The application.

    Raises:
        RuntimeError: Outside tests, when the key is missing, publicly known
            or shorter than 32 characters.
    """
    key = app.config.get("SECRET_KEY")
    if isinstance(key, str) and key not in WEAK_SECRET_KEYS and len(key) >= _MIN_SECRET_KEY_LENGTH:
        return
    if app_config.IS_TEST_ENV:
        if not isinstance(key, str) or not key:
            app.config["SECRET_KEY"] = secrets.token_hex(32)
        return
    raise RuntimeError(
        "secret_key must be set (configuration secret_key or FLASK_SECRET_KEY) to a random value "
        f"of at least {_MIN_SECRET_KEY_LENGTH} characters"
    )


def _check_payload_keys() -> None:
    """Rejects a frontend ``payload_key`` too short to sign display payloads.

    Raises:
        RuntimeError: When a configured key is shorter than 32 characters.
    """
    frontends = (app_config.CONFIGURATION.get("frontend") or {}).get("frontends_config") or {}
    for frontend_id in frontends:
        try:
            frontend_payload_key(frontend_id)
        except ValueError as e:
            raise RuntimeError(str(e)) from e


def create_app(test_config: Optional[Mapping[str, Any]] = None) -> Flask:
    """Creates and configures the Flask application.

    Args:
        test_config: Configuration overriding the instance ``config.py``.
            ``INIT_BACKGROUND_SERVICES`` and ``LOAD_TRUSTED_CAS`` default to
            ``not IS_TEST_ENV``.

    Returns:
        The configured application.
    """
    # Imported here so tests can patch them on this module's namespace.
    from app.services.metadata import setup_metadata, setup_trusted_cas

    # API-only service: no static files are served.
    # CSRF: the browser POST routes are posted cross-site by the frontends, so
    # form tokens cannot be used; core.security.require_frontend_origin rejects
    # any Origin / Referer that is not a configured frontend.
    app = Flask(__name__, instance_relative_config=True, static_folder=None)  # NOSONAR
    app.config.from_mapping(
        SECRET_KEY=app_config.CONFIGURATION.get("secret_key") or os.environ.get("FLASK_SECRET_KEY"),
        INIT_BACKGROUND_SERVICES=not app_config.IS_TEST_ENV,
        LOAD_TRUSTED_CAS=not app_config.IS_TEST_ENV,
        # Larger bodies get 413 before any view parses them.
        MAX_CONTENT_LENGTH=int(app_config.CONFIGURATION.get("max_content_length") or DEFAULT_MAX_CONTENT_LENGTH),
    )
    if test_config is None:
        app.config.from_pyfile("config.py", silent=True)
    else:
        app.config.from_mapping(test_config)
    _check_secret_key(app)
    _check_payload_keys()

    os.makedirs(app.instance_path, exist_ok=True)

    configure_logging(app, app_config.CONFIGURATION["logging"])

    app.logger.debug("Running initialization setups...")
    setup_metadata()
    if app.config["LOAD_TRUSTED_CAS"]:
        setup_trusted_cas()
    if app.config["INIT_BACKGROUND_SERVICES"]:
        _start_background_services(app)

    app.register_error_handler(Exception, handle_exception)
    app.register_error_handler(404, page_not_found)

    @app.route("/", methods=["GET"])
    def health_check() -> tuple[str, int]:
        """Liveness probe."""
        return "OK", 200

    _register_blueprints(app)
    init_rate_limits(app)

    app.config["SESSION_FILE_THRESHOLD"] = int(
        app_config.CONFIGURATION.get("session_file_threshold") or DEFAULT_SESSION_FILE_THRESHOLD
    )
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_TYPE"] = "filesystem"
    # "None" lets a frontend on another site POST to the backend with the
    # session cookie; use "Lax" when frontend and backend share a site.
    app.config.update(
        SESSION_COOKIE_SAMESITE=app_config.CONFIGURATION.get("session_cookie_samesite", "None"),
        SESSION_COOKIE_SECURE=True,
    )
    Session(app)

    # Only the configured frontends (and cors_allowed_origins) may call the
    # backend cross-origin with credentials (cookies).
    CORS(app, origins=allowed_cors_origins(), supports_credentials=True)

    form_targets = " ".join(frontend_origins()) or "'none'"
    content_security_policy = (
        "default-src 'none'; "
        f"script-src {AUTO_SUBMIT_SCRIPT_HASH}; "
        "style-src 'unsafe-inline'; "
        f"form-action {form_targets}; "
        "base-uri 'none'; frame-ancestors 'none'"
    )

    @app.after_request
    def add_security_headers(response: Response) -> Response:
        """Adds the security headers to every response.

        The only HTML the backend serves is the auto-submit page of
        :func:`app.utils.http.post_redirect_with_payload`: its script is
        allowed by hash and its form may only post to a frontend.
        """
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Content-Security-Policy", content_security_policy)
        return response

    app.logger.info("Flask application created (blueprints: %d)", len(app.blueprints))
    return app
