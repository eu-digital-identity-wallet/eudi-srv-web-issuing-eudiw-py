# coding: latin-1
###############################################################################
# Copyright (c) 2026 European Commission
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
"""Per-client rate limits on the endpoints that sign, issue or look up data.

Configuration (``rate_limiting``, all optional):
    enabled: ``false`` turns the limits off (default ``true``).
    storage_uri: Flask-Limiter storage, e.g. ``redis://host:6379`` when
        several workers must share counters (default ``memory://``).
    trusted_proxies: Number of reverse proxies in front of the backend whose
        ``X-Forwarded-For`` is trusted (default ``0``). Behind nginx set
        ``1``; otherwise every user shares the proxy's address and limit.
    limits: ``{endpoint: "N per period"}`` overrides of :data:`ENDPOINT_LIMITS`.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from flask import Flask, jsonify
from flask_limiter import Limiter, RequestLimit
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from app.core.config import CONFIGURATION

logger = logging.getLogger(__name__)

#: Shared limit tiers of ENDPOINT_LIMITS (requests per client address).
HIGH_LIMIT = "60 per minute"
MEDIUM_LIMIT = "30 per minute"
LOW_LIMIT = "20 per minute"

#: Default limit per client address for each Flask endpoint.
ENDPOINT_LIMITS: Dict[str, str] = {
    "oidc.credential": HIGH_LIMIT,
    "oidc.deferred_credential": HIGH_LIMIT,
    "oidc.nonce": HIGH_LIMIT,
    "oidc.notification": HIGH_LIMIT,
    "oidc.auth_choice": MEDIUM_LIMIT,
    "oidc.credentialOffer": MEDIUM_LIMIT,
    "oidc.pid_authorization_get": "120 per minute",
    "oidc.get_logs_by_session": MEDIUM_LIMIT,
    "preauth.credentialOfferReq2": MEDIUM_LIMIT,
    "preauth.preauthRed": LOW_LIMIT,
    "preauth.preauth_form": LOW_LIMIT,
    "preauth.form_authorize_generate": LOW_LIMIT,
    "dynamic.Dynamic_form": LOW_LIMIT,
    "dynamic.red": LOW_LIMIT,
    "oid4vp.openid4vp": LOW_LIMIT,
    "oid4vp.getpidoid4vp": MEDIUM_LIMIT,
    "revocation.oid4vp_call": LOW_LIMIT,
    "revocation.oid4vp_get": MEDIUM_LIMIT,
    "revocation.revoke": "10 per minute",
    "metadata.metadata_signer": MEDIUM_LIMIT,
}


def _too_many_requests(limit: RequestLimit) -> Any:
    """Builds the ``429`` answer.

    Args:
        limit: The limit that was exceeded.

    Returns:
        A JSON ``429`` response.
    """
    logger.warning(f"Rate limit exceeded: {limit.limit}")
    return jsonify({"error": "too_many_requests", "error_description": "Rate limit exceeded"}), 429


def init_rate_limits(app: Flask) -> Limiter | None:
    """Applies :data:`ENDPOINT_LIMITS` to the registered endpoints.

    Must run after the blueprints are registered.

    Args:
        app: The application.

    Returns:
        The limiter, or ``None`` when rate limiting is disabled.
    """
    settings = CONFIGURATION.get("rate_limiting") or {}
    if settings.get("enabled", True) is False:
        logger.warning("Rate limiting is disabled")
        return None

    proxies = int(settings.get("trusted_proxies", 0) or 0)
    if proxies > 0:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=proxies, x_proto=proxies, x_host=proxies)

    limiter = Limiter(
        get_remote_address,
        app=app,
        storage_uri=settings.get("storage_uri", "memory://"),
        headers_enabled=True,
        on_breach=_too_many_requests,
    )
    limits = {**ENDPOINT_LIMITS, **(settings.get("limits") or {})}
    for endpoint, limit in limits.items():
        view = app.view_functions.get(endpoint)
        if view is None:
            continue
        app.view_functions[endpoint] = limiter.limit(limit)(view)
    logger.debug(f"Rate limits applied to {len(limits)} endpoints")
    return limiter
