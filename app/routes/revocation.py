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
"""``/revocation`` blueprint: lets a user revoke credentials they hold.

The user selects credential types, presents those credentials from their
wallet over OpenID4VP, and the status list entries found in them are
flipped to *revoked*.
"""

from __future__ import annotations

import hmac
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple

import jwt
from flask import Blueprint, abort, jsonify, request, session

from app.core.config import CONFIGURATION
from app.core.errors import CertificateVerificationError
from app.core.log_utils import safe
from app.core.security import require_frontend_origin
from app.core.state import oidc_metadata
from app.repositories.offer_store import revocation_requests
from app.repositories.status_store import batch_status_entries
from app.services.attributes import credential_display_names
from app.services.frontend_metadata import frontend_publishes
from app.services.oid4vp import (
    build_dcql_query,
    fetch_presentation_result,
    result_url_from_request,
    start_presentation,
)
from app.services.revocation_status import (
    describe_status_list,
    get_status_mdoc,
    get_status_sdjwt,
    set_token_status,
)
from app.utils.frontend import frontend_url
from app.utils.http import post_redirect_with_payload
from app.utils.ids import generate_unique_id
from app.utils.qr import qr_data_uri

revocation = Blueprint("revocation", __name__, url_prefix="/revocation")

logger = logging.getLogger(__name__)

#: mdoc configurations that cannot be revoked by the user.
NON_REVOCABLE_MDOC_SCOPES = (
    "eu.europa.ec.eudi.age_verification_mdoc_passport",
    "eu.europa.ec.eudi.age_verification_mdoc",
)
FORMATS = ("dc+sd-jwt", "mso_mdoc")
#: Browser session key of the frontend the revocation flow started from.
SESSION_FRONTEND_KEY = "revocation_frontend_id"


def _revocable(cid: str, cfg: Dict[str, Any]) -> bool:
    """Filters out credentials that cannot be revoked.

    Args:
        cid: Configuration id (unused).
        cfg: Configuration.

    Returns:
        ``False`` for age verification mdocs.
    """
    return not (cfg["format"] == "mso_mdoc" and cfg["scope"] in NON_REVOCABLE_MDOC_SCOPES)


def _flow_frontend_url() -> str:
    """Returns the URL of the frontend the revocation flow started from.

    Returns:
        That frontend's base URL (the default frontend when none was recorded).
    """
    return frontend_url(session.get(SESSION_FRONTEND_KEY))


# TODO finish revocation pages.
@revocation.route("revocation_choice", methods=["GET"])
def revocation_choice() -> Any:
    """Page for selecting the credential types to revoke.

    Only the credentials published in the requesting frontend's metadata
    (``frontends_config.<frontend_id>.credentials_supported``) are listed.
    Without ``frontend_id`` the default frontend is used. An unknown
    ``frontend_id`` gets ``404`` before the browser session is touched.

    Returns:
        The frontend selection page, or ``404`` for an unknown frontend.
    """
    frontend_id = request.args.get("frontend_id")
    if frontend_id is not None and frontend_id not in (CONFIGURATION["frontend"].get("frontends_config") or {}):
        logger.warning(f"revocation_choice: unknown frontend_id {safe(frontend_id, 64)}")
        return jsonify({"error": "unknown_frontend"}), 404
    session[SESSION_FRONTEND_KEY] = frontend_id

    published = frontend_publishes(frontend_id)
    return post_redirect_with_payload(
        target_url=f"{frontend_url(frontend_id)}/display_revocation_choice",
        data_payload={
            "cred": credential_display_names(lambda cid, cfg: published(cid) and _revocable(cid, cfg)),
            "redirect_url": f"{CONFIGURATION['service_url']}/revocation/oid4vp_call",
        },
    )


@revocation.route("oid4vp_call", methods=["GET", "POST"])
@require_frontend_origin
def oid4vp_call() -> Any:
    """Requests a presentation of the selected credentials.

    Only credentials the flow's frontend publishes and that can be revoked
    may be selected.

    Returns:
        The frontend page showing the deeplink and QR code, or ``400`` for
        any other credential.
    """
    selected = [key for key in request.form.keys() if key != "proceed"]
    credentials_supported = oidc_metadata["credential_configurations_supported"]
    published = frontend_publishes(session.get(SESSION_FRONTEND_KEY))
    if not all(
        published(cid) and cid in credentials_supported and _revocable(cid, credentials_supported[cid])
        for cid in selected
    ):
        return jsonify({"error": "invalid_request", "error_description": "Unsupported credential"}), 400
    session_id = str(uuid.uuid4())
    session["session_id"] = session_id

    # Only the issuer-signed status is used; one claim keeps the query valid
    # without disclosing the rest of the credential.
    dcql_query, formats = build_dcql_query(
        selected,
        credentials_supported,
        sdjwt_intent_to_retain=False,
        first_mandatory_only=True,
    )
    session.update(formats)  # query_id -> format, read back in oid4vp_get

    response_redirect_uri = (
        f"{CONFIGURATION['service_url']}/revocation/getoid4vp?response_code={{RESPONSE_CODE}}&session_id={session_id}"
    )
    presentation = start_presentation(dcql_query, response_redirect_uri)
    # The revocation flow has no SessionManager session; keep the same-device
    # transaction id in the browser session for oid4vp_get.
    session["oid4vp_transaction_id"] = presentation.same_device_id
    session["oid4vp_cross_device_id"] = presentation.cross_device_id
    session["oid4vp_nonce"] = presentation.nonce

    return post_redirect_with_payload(
        target_url=f"{_flow_frontend_url()}/display_revocation_qr_code",
        data_payload={
            "url_data": presentation.deeplink_url,
            "redirect_url": f"{CONFIGURATION['service_url']}/",
            "qrcode": qr_data_uri(presentation.qr_code_url),
            "presentation_id": presentation.cross_device["transaction_id"],
        },
    )


def _statuses_by_format(vp_token: Dict[str, List[str]]) -> Dict[str, List[Dict[str, Any]]]:
    """Extracts the status claims of every presented credential.

    Args:
        vp_token: ``{query_id: [credential, ...]}`` from the verifier.

    Returns:
        ``{format: [status, ...]}``.
    """
    statuses: Dict[str, List[Dict[str, Any]]] = {fmt: [] for fmt in FORMATS}
    for query_id, presented in vp_token.items():
        match session[query_id]:
            case "mso_mdoc":
                for credential in presented:
                    status = get_status_mdoc(credential)
                    statuses["mso_mdoc"].extend(status if isinstance(status, list) else [status])
            case "dc+sd-jwt":
                statuses["dc+sd-jwt"].extend(get_status_sdjwt(credential) for credential in presented)
    return statuses


@revocation.route("getoid4vp", methods=["GET", "POST"])
@require_frontend_origin
def oid4vp_get() -> Any:
    """Receives the presentation and asks the user to confirm revocation.

    Returns:
        The confirmation page, or ``400`` on missing parameters / verifier errors.
    """
    session_id = session.get("session_id")
    same_device = "response_code" in request.args and "session_id" in request.args
    logger.info(f", Session ID: {session_id}, oid4vp flow: {'same_device' if same_device else 'cross_device'}")

    try:
        url = result_url_from_request(
            request.args, session.get("oid4vp_transaction_id"), session.get("oid4vp_cross_device_id")
        )
    except ValueError as e:
        logger.warning(f", Session ID: {session_id}, OID4VP result rejected: {safe(e)}")
        return jsonify({"error": "invalid_request", "error_description": str(e)}), 400
    if url is None:
        return jsonify({"error": "Missing required parameters"}), 400

    response = fetch_presentation_result(url)
    if response.status_code != 200:
        return jsonify({"error": str(response.status_code)}), 400

    try:
        statuses = _statuses_by_format(response.json()["vp_token"])
    except (CertificateVerificationError, ValueError, KeyError, jwt.InvalidTokenError) as e:
        logger.warning(f", Session ID: {session_id}, Revocation presentation rejected: {safe(e)}")
        return jsonify({"error": "invalid_presentation", "error_description": "Credential not issued by this issuer"}), 400
    display_list = {
        fmt: [d for d in (describe_status_list(s) for s in fmt_statuses) if d]
        for fmt, fmt_statuses in statuses.items()
    }

    revocation_id = generate_unique_id()
    revocation_requests[revocation_id] = {
        "status_lists": statuses,
        "expires": datetime.now() + timedelta(minutes=CONFIGURATION["expiry"]["revocation_code"]),
    }
    # Only the browser that presented the credential may confirm.
    session["revocation_id"] = revocation_id

    return post_redirect_with_payload(
        target_url=f"{_flow_frontend_url()}/display_revocation_authorization",
        data_payload={
            "display_list": display_list,
            "redirect_url": f"{CONFIGURATION['service_url']}/revocation/revoke",
            "revocation_identifier": revocation_id,
            "revocation_choice_url": f"{CONFIGURATION['service_url']}/revocation/revocation_choice",
        },
    )


def _status_pointers(status: Dict[str, Any]) -> List[Tuple[str, Any, str]]:
    """Lists the status entries of a credential ``status`` claim.

    Args:
        status: ``status`` claim (identifier ids as bytes from an MSO, or text).

    Returns:
        ``[(field, value, uri)]`` for :func:`set_token_status`.
    """
    pointers = []
    if "identifier_list" in status:
        identifier = status["identifier_list"]
        value = identifier["id"]
        pointers.append(("id", value.decode("utf-8") if isinstance(value, bytes) else value, identifier["uri"]))
    if "status_list" in status:
        pointer = status["status_list"]
        pointers.append(("idx", pointer["idx"], pointer["uri"]))
    return pointers


@revocation.route("revoke", methods=["GET", "POST"])
@require_frontend_origin
def revoke() -> str:
    """Revokes every status list entry of a confirmed revocation request.

    Returns:
        The success page.

    Raises:
        werkzeug.exceptions.BadRequest: If the identifier is missing.
        werkzeug.exceptions.Forbidden: If it was issued to another browser session.
        werkzeug.exceptions.NotFound: If it is unknown or expired.
    """
    revocation_identifier = request.form.get("revocation_identifier")
    if not revocation_identifier:
        abort(400, description="Missing revocation identifier")
    expected = session.get("revocation_id")
    if not expected or not hmac.compare_digest(revocation_identifier.encode(), expected.encode()):
        logger.warning("Revocation rejected: identifier not issued to this browser session")
        abort(403, description="Revocation identifier does not belong to this session")
    pending = revocation_requests.get(revocation_identifier)
    if pending is None or pending["expires"] < datetime.now():
        revocation_requests.pop(revocation_identifier, None)
        abort(404, description="Invalid or expired revocation identifier")
    session.pop("revocation_id", None)

    pointers = set()
    for statuses in revocation_requests[revocation_identifier]["status_lists"].values():
        for status in statuses:
            pointers.update(_status_pointers(status))
            # Every instance issued with the presented one (#167): the
            # presented instance alone was already used when presenting it.
            for sibling in batch_status_entries(status):
                pointers.update(_status_pointers(sibling))

    revoked = sum(
        set_token_status(field, value, uri, respect_enabled_flag=False) for field, value, uri in sorted(pointers, key=str)
    )

    revocation_requests.pop(revocation_identifier)
    logger.info(f"Revocation request {safe(revocation_identifier, 64)} processed: {revoked} status entr(y/ies) revoked")

    return post_redirect_with_payload(
        target_url=f"{_flow_frontend_url()}/display_revocation_success",
        data_payload={"redirect_url": f"{CONFIGURATION['service_url']}/"},
    )
