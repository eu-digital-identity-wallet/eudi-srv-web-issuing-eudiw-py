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
"""OpenID4VP PID authentication: the user proves their identity by presenting
a PID from their wallet, which pre-fills the attribute form.

Supports both same-device and cross-device flows.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Tuple, Union
from uuid import uuid4

from flask import Blueprint, Response, jsonify, request, session

from app.core.config import CONFIGURATION
from app.core.log_utils import safe
from app.core.state import oidc_metadata, session_manager
from app.services.attributes import getAttributesForm, getAttributesForm2
from app.services.formatters import cbor2elems
from app.services.oid4vp import (
    build_dcql_query,
    fetch_presentation_result,
    result_url_from_request,
    start_presentation,
)
from app.services.vp_validation import validate_vp_token
from app.utils.frontend import frontend_url
from app.utils.http import post_redirect_with_payload
from app.utils.qr import qr_data_uri

oid4vp = Blueprint("oid4vp", __name__, url_prefix="/")
logger = logging.getLogger(__name__)

PID_CREDENTIAL = "eu.europa.ec.eudi.pid_mdoc"

HandlerResult = Union[Response, str, Tuple[Any, int]]


@oid4vp.route("/oid4vp", methods=["GET"])
def openid4vp() -> str:
    """Requests a PID presentation from the user's wallet.

    Returns:
        The frontend page showing the deeplink and QR code.
    """
    session_id = session["session_id"]
    logger.info(f", Session ID: {session_id}, Authorization selection, Type: oid4vp")

    dcql_query, _ = build_dcql_query(
        [PID_CREDENTIAL], oidc_metadata["credential_configurations_supported"], mandatory_only=True
    )
    response_redirect_uri = (
        f"{CONFIGURATION['service_url']}/getpidoid4vp?response_code={{RESPONSE_CODE}}&session_id={session_id}"
    )
    presentation = start_presentation(dcql_query, response_redirect_uri)

    session_manager.update_oid4vp_presentation(
        session_id=session_id,
        same_device_id=presentation.same_device_id,
        cross_device_id=presentation.cross_device_id,
        nonce=presentation.nonce,
    )
    current_session = session_manager.get_session(session_id=session_id)

    return post_redirect_with_payload(
        target_url=f"{frontend_url(current_session.frontend_id)}/display_pid_login",
        data_payload={
            "session_id": session_id,
            "deeplink_url": presentation.deeplink_url,
            "qr_img_base64": qr_data_uri(presentation.qr_code_url),
            "redirect_url": f"{CONFIGURATION['service_url']}/",
            "transaction_id": presentation.cross_device["transaction_id"],
        },
    )


def _prefill_forms(
    credentials_requested: list, mdoc_elements: Dict[str, list]
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Builds the mandatory / optional forms pre-filled with PID values.

    Args:
        credentials_requested: Credential configuration ids.
        mdoc_elements: Output of :func:`cbor2elems`.

    Returns:
        ``(mandatory_attributes, optional_attributes)``.
    """
    mandatory = getAttributesForm(credentials_requested)
    if "user_pseudonym" in mandatory:
        mandatory["user_pseudonym"] = {"type": "string", "filled_value": str(uuid4())}
    optional = getAttributesForm2(credentials_requested)

    for elements in mdoc_elements.values():
        for attribute, value in elements:
            if attribute in mandatory:
                mandatory[attribute]["filled_value"] = value
            elif attribute in optional:
                optional[attribute]["filled_value"] = value
    return mandatory, optional


@oid4vp.route("/getpidoid4vp", methods=["GET"])
def getpidoid4vp() -> HandlerResult:
    """Receives the PID presentation result and shows the pre-filled form.

    Returns:
        The form page, or ``400`` on missing parameters / verifier errors.

    Raises:
        ValueError: If the presentation is invalid.
    """
    session_id = session["session_id"]
    current_session = session_manager.get_session(session_id=session_id)

    same_device = "response_code" in request.args and "session_id" in request.args
    logger.info(f", Session ID: {session_id}, oid4vp flow: {'same_device' if same_device else 'cross_device'}")

    try:
        url = result_url_from_request(
            request.args, current_session.oid4vp_transaction_id, current_session.oid4vp_cross_device_id
        )
    except ValueError as e:
        logger.warning(f", Session ID: {session_id}, OID4VP result rejected: {safe(e)}")
        return jsonify({"error": "invalid_request", "error_description": str(e)}), 400
    if url is None:
        return jsonify({"error": "Missing required parameters"}), 400

    response = fetch_presentation_result(url)
    if response.status_code != 200:
        return jsonify({"error": str(response.status_code)}), 400

    response_json = response.json()
    error, error_msg = validate_vp_token(response_json, current_session.credentials_requested)
    if error:
        logger.error(f", Session ID: {session_id}, OID4VP error: {error_msg}")
        raise ValueError(f"invalid_request. Session ID: {session_id}")

    if not current_session.authorization_details:
        return jsonify({"error": "No authorization details in session"}), 400

    pid_elements = cbor2elems(response_json["vp_token"]["query_0"][0] + "==")
    mandatory, optional = _prefill_forms(current_session.credentials_requested, pid_elements)
    session_manager.update_verified_attributes(
        session_id=session_id,
        verified_attributes={name: value for elements in pid_elements.values() for name, value in elements},
    )
    session_manager.update_country(session_id=session_id, country="FC")

    return post_redirect_with_payload(
        target_url=f"{frontend_url(current_session.frontend_id)}/display_form",
        data_payload={
            "mandatory_attributes": mandatory,
            "optional_attributes": optional,
            "redirect_url": f"{CONFIGURATION['service_url']}/dynamic/form",
            "session_id": session_id,
        },
    )
