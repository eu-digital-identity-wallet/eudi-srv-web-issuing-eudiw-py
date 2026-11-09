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
"""``/metadata`` blueprint: per-frontend issuer metadata (unsigned and signed).

All endpoints are for other EUDIW services and require an API key in the
``X-Api-Key`` header (see :mod:`app.core.security`).

* ``GET /metadata/<frontend_id>``: unsigned metadata documents of a frontend
  (``backend_api_key``).
* ``GET /metadata/<frontend_id>/signed``: signed credential issuer metadata
  (``backend_api_key``).
* ``POST /metadata/metadata_signer``: signs arbitrary issuer metadata
  (``admin_api_key``).
"""

from __future__ import annotations

import logging
from typing import Any, Tuple

import jwt
from flask import Blueprint, Response, jsonify, request

from app.core.config import CONFIGURATION
from app.core.security import require_admin_api_key, require_api_key
from app.core.log_utils import safe
from app.services.frontend_metadata import UnknownFrontendError, build_frontend_metadata, sign_frontend_metadata
from app.services.metadata import MetadataSigningError, sign_issuer_metadata

metadata = Blueprint("metadata", __name__, url_prefix="/metadata")

logger = logging.getLogger(__name__)


def _error(message: str, status: int, details: Any = None) -> Tuple[Response, int]:
    """Builds a JSON error response.

    Args:
        message: Error message.
        status: HTTP status.
        details: Optional details.

    Returns:
        ``(json_response, status)``.
    """
    body = {"error": message}
    if details is not None:
        body["details"] = details
    return jsonify(body), status


@metadata.route("metadata_signer", methods=["POST"])
@require_admin_api_key
def metadata_signer() -> Tuple[Response, int]:
    """Signs issuer metadata according to OpenID4VCI 12.2.3 (Signed Metadata).

    Requires the ``X-Api-Key`` header (``admin_api_key``): the caller chooses
    what is signed with a frontend's key.

    JSON body:
        metadata (required): Issuer metadata object.
        issuer_frontend_id (required): Frontend acting as credential issuer.
        iss (optional): Party attesting to the claims.

    Returns:
        ``({"signed_metadata": <jwt>}, 200)``, ``400`` for invalid input or
        ``500`` when signing fails.
    """
    try:
        data = request.get_json()
        if not data:
            return _error("No JSON data provided", 400)

        metadata_content = data.get("metadata")
        issuer_frontend_id = data.get("issuer_frontend_id")
        if not metadata_content:
            return _error("metadata is required", 400)
        if not issuer_frontend_id:
            return _error("issuer_frontend_id is required", 400)
        if not isinstance(metadata_content, dict):
            return _error("metadata must be a JSON object", 400)

        if issuer_frontend_id not in (CONFIGURATION.get("frontend", {}).get("frontends_config") or {}):
            return _unknown_frontend(issuer_frontend_id)

        signed = sign_issuer_metadata(metadata_content, issuer_frontend_id, iss=data.get("iss"))
        return jsonify({"signed_metadata": signed}), 200

    except MetadataSigningError as e:
        logger.exception(f"Metadata signing failed: {safe(e.message)}: {safe(e.details)}")
        return _error(e.message, 500)
    except jwt.PyJWTError:
        logger.exception("JWT encoding error")
        return _error("JWT encoding failed", 500)
    except Exception:
        logger.exception("General exception while signing metadata")
        return _error("Internal server error", 500)


def _unknown_frontend(frontend_id: str) -> Tuple[Response, int]:
    """Builds the 404 answer for an unconfigured frontend.

    Args:
        frontend_id: Requested frontend id.

    Returns:
        ``(json_response, 404)``.
    """
    logger.warning(f"Metadata requested for unknown frontend_id {safe(frontend_id, 64)}")
    return _error("unknown_frontend", 404)


@metadata.route("<frontend_id>", methods=["GET"])
@require_api_key
def frontend_metadata(frontend_id: str) -> Tuple[Response, int]:
    """Returns the unsigned metadata documents of a frontend.

    Requires the ``X-Api-Key`` header.

    Args:
        frontend_id: Frontend identifier (``frontend.frontends_config`` key).

    Returns:
        ``({"openid_credential_issuer", "jwt_vc_issuer"}, 200)`` or ``404``
        for an unknown frontend.
    """
    logger.debug(f"Unsigned metadata requested for frontend {safe(frontend_id, 64)}")
    try:
        documents = build_frontend_metadata(frontend_id)
    except UnknownFrontendError:
        return _unknown_frontend(frontend_id)
    return jsonify(documents.to_dict()), 200


@metadata.route("<frontend_id>/signed", methods=["GET"])
@require_api_key
def frontend_signed_metadata(frontend_id: str) -> Tuple[Response, int]:
    """Returns the signed credential issuer metadata of a frontend.

    Requires the ``X-Api-Key`` header.

    Args:
        frontend_id: Frontend identifier (``frontend.frontends_config`` key).

    Returns:
        ``({"signed_metadata": <jwt>}, 200)``, ``404`` for an unknown frontend
        or ``500`` when signing fails.
    """
    logger.debug(f"Signed metadata requested for frontend {safe(frontend_id, 64)}")
    try:
        signed = sign_frontend_metadata(frontend_id)
    except UnknownFrontendError:
        return _unknown_frontend(frontend_id)
    except MetadataSigningError as e:
        logger.exception(f"Signed metadata for {safe(frontend_id, 64)} failed: {safe(e.message)}: {safe(e.details)}")
        return _error(e.message, 500)
    return jsonify({"signed_metadata": signed}), 200
