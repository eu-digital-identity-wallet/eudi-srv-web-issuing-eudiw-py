# coding: latin-1
###############################################################################
# Copyright (c) 2025 European Commission
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
"""Shared exceptions and error responses.

Centralizes the OpenID4VCI credential error body, the OAuth error redirect
and the application-wide Flask error handlers.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any, Dict, Optional, Tuple

from flask import Response, jsonify, redirect, request
from werkzeug.exceptions import HTTPException

from app.core.log_utils import safe
from app.utils.http import url_get

logger = logging.getLogger(__name__)

C_NONCE_EXPIRES_IN = 86400


class CertificateVerificationError(Exception):
    """Raised when certificate verification fails."""


class OAuthEndpointError(Exception):
    """An OAuth / OpenID4VCI error to return to the client as JSON.

    Raised by request parsing and validation helpers; blueprints render it
    with :func:`oauth_error_response`. Messages are fixed strings, never
    request input.

    Args:
        error: OAuth error code (e.g. ``invalid_credential_request``), or
            ``None`` for a ``401`` to a request without credentials
            (RFC 6750 section 3.1: no error code then).
        status: HTTP status code. ``401`` / ``403`` are access token errors
            and get a ``WWW-Authenticate`` challenge (RFC 6750 section 3).
        description: Optional fixed ``error_description``.
        scheme: Challenge scheme (``Bearer`` / ``DPoP``) of a ``401`` /
            ``403``; by default the scheme the request used.
    """

    def __init__(
        self, error: Optional[str], status: int = 400, description: Optional[str] = None, scheme: Optional[str] = None
    ) -> None:
        super().__init__(error)
        self.error = error
        self.status = status
        self.description = description
        self.scheme = scheme


def clean_description(value: Any) -> str:
    """Restricts an ``error_description`` to the characters OAuth allows.

    RFC 6749 section 5.2 / RFC 6750 section 3 / OpenID4VCI 1.0 section
    8.3.1.2: ``%x20-21 / %x23-5B / %x5D-7E`` (printable ASCII without ``"``
    and ``\\``). Descriptions may come from library messages, which can
    quote names.

    Args:
        value: Description.

    Returns:
        The description with other characters removed.
    """
    return "".join(c for c in str(value) if " " <= c <= "~" and c not in '"\\')


def error_body(error: Optional[str], description: Any = None) -> Dict[str, str]:
    """Builds an OAuth / OpenID4VCI error body.

    Args:
        error: Error code.
        description: Optional ``error_description`` (cleaned with :func:`clean_description`).

    Returns:
        ``{"error"[, "error_description"]}``.
    """
    body = {"error": error}
    if description:
        body["error_description"] = clean_description(description)
    return body


def auth_challenge(error: Optional[str] = None, description: Optional[str] = None, scheme: Optional[str] = None) -> str:
    """Builds the ``WWW-Authenticate`` value of an access token error.

    RFC 6750 section 3 (``Bearer``) and RFC 9449 section 7.1 (``DPoP``, with
    ``algs``). Without ``scheme``, the scheme of the request's
    ``Authorization`` header is used; a request without (usable) credentials
    is offered both schemes.

    Args:
        error: Error code (omitted for a request without credentials).
        description: Optional ``error_description``.
        scheme: ``Bearer`` or ``DPoP``.

    Returns:
        The header value.
    """
    if scheme is None:
        used = request.headers.get("Authorization", "").split(" ", 1)[0].lower() if request else ""
        scheme = {"bearer": "Bearer", "dpop": "DPoP"}.get(used)
    # Imported here: app.services depends on this module.
    from app.services.dpop import DPOP_ALGORITHMS

    params = []
    if error:
        params.append(f'error="{clean_description(error)}"')
        if description:
            params.append(f'error_description="{clean_description(description)}"')
    dpop = ", ".join([*params, f'algs="{" ".join(DPOP_ALGORITHMS)}"'])
    bearer = "Bearer " + ", ".join(params) if params else "Bearer"
    if scheme == "DPoP":
        return f"DPoP {dpop}"
    if scheme == "Bearer":
        return bearer
    return f"{bearer}, DPoP {dpop}"


def token_error_response(
    error: Optional[str], status: int = 401, description: Optional[str] = None, scheme: Optional[str] = None
) -> Tuple[Response, int]:
    """Builds an access token error (RFC 6750 section 3, RFC 9449 section 7.1).

    Args:
        error: ``invalid_token``, ``insufficient_scope``, ``invalid_dpop_proof``...,
            or ``None`` for a request without credentials.
        status: ``401`` (``403`` for ``insufficient_scope``).
        description: Optional fixed ``error_description``.
        scheme: Challenge scheme (see :func:`auth_challenge`).

    Returns:
        ``(json_response, status)`` with a ``WWW-Authenticate`` header.
    """
    response = jsonify(error_body(error, description) if error else {})
    response.headers["WWW-Authenticate"] = auth_challenge(error, description, scheme)
    return response, status


def oauth_error_response(e: OAuthEndpointError) -> Tuple[Response, int]:
    """Renders an :class:`OAuthEndpointError` as a JSON response.

    ``401`` / ``403`` errors are access token errors and carry a
    ``WWW-Authenticate`` challenge (:func:`token_error_response`).

    Args:
        e: The error.

    Returns:
        ``(json_response, status)``.
    """
    if e.status in (401, 403):
        return token_error_response(e.error, e.status, e.description, e.scheme)
    return jsonify(error_body(e.error, e.description)), e.status


def credential_error_resp(error: str, desc: str) -> Tuple[Response, int]:
    """Builds an OpenID4VCI credential endpoint error response.

    A fresh ``c_nonce`` is included so the wallet can retry.

    Args:
        error: OAuth error code (e.g. ``invalid_proof``).
        desc: Human readable description.

    Returns:
        ``(json_response, 400)``.
    """
    return (
        jsonify(
            {
                "error": error,
                "error_description": desc,
                "c_nonce": secrets.token_urlsafe(16),
                "c_nonce_expires_in": C_NONCE_EXPIRES_IN,
            }
        ),
        400,
    )


def auth_error_redirect(return_uri: str, error: str, error_description: Optional[str] = None) -> Response:
    """Redirects the wallet to ``return_uri`` with an OAuth error.

    Args:
        return_uri: Wallet redirect URI.
        error: OAuth error code.
        error_description: Optional description.

    Returns:
        A ``302`` redirect response.
    """
    error_msg = {"error": error}
    if error_description is not None:
        error_msg["error_description"] = error_description
    return redirect(url_get(return_uri, error_msg), code=302)


def handle_exception(e: Exception) -> Any:
    """Application-wide handler for uncaught exceptions.

    HTTP exceptions are returned unchanged; anything else is logged and
    turned into a generic JSON 500.

    Args:
        e: The raised exception.

    Returns:
        The HTTP exception, or ``(json_response, 500)``.
    """
    if isinstance(e, HTTPException):
        return e

    logger.exception("Unhandled exception")
    return (
        jsonify(
            {
                "error": "Internal Server Error",
                "error_code": 500,
                "message": "An internal server error has occurred. Our team has been notified and is working to resolve the issue. Please try again later.",
            }
        ),
        500,
    )


def page_not_found(e: Exception) -> Tuple[Response, int]:
    """JSON 404 handler.

    Args:
        e: The ``NotFound`` exception.

    Returns:
        ``(json_response, 404)``.
    """
    logger.warning("404 Not Found: %s", safe(request.path))
    return (
        jsonify(
            {
                "error": "Not Found",
                "error_code": 404,
                "message": f"The requested path '{request.path}' could not be found.",
            }
        ),
        404,
    )
