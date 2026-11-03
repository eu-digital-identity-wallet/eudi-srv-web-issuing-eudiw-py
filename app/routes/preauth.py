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
"""Pre-authorized code flow (test support).

The libraries used do not support pre-authorization natively; these routes
obtain a pre-authorized code from the authorization server, collect the
user attributes and produce a credential offer for testing purposes.
"""

from __future__ import annotations

import json
import logging
from http import HTTPStatus
from typing import Any, Dict, List, Optional, Tuple, Union

import jwt
from flask import Blueprint, Response, jsonify, request, session

from app.core.config import CONFIGURATION, feature_enabled
from app.core.constants import IMAGE_ATTRIBUTES
from app.core.log_utils import safe
from app.core.security import require_frontend_origin
from app.core.state import oidc_metadata, session_manager
from app.services.attributes import getAttributesForm, getAttributesForm2, optional_only, requested_credential_ids
from app.services.auth_server import generate_preauth_code
from app.services.credential_offer import offer_link, pre_authorized_offer
from app.services.presentation import InvalidFormError, form_formatter, presentation_formatter
from app.core.errors import CertificateVerificationError
from app.services.trust import (
    CREDENTIAL_OFFER_REQUEST_CONTEXT,
    PURPOSE_OFFER_REQUEST,
    trust_context,
    trust_use_case,
    verify_jwt_with_x5c,
)
from app.utils.forms import parse_form
from app.utils.frontend import frontend_url
from app.utils.http import post_redirect_with_payload
from app.utils.ids import generate_unique_id
from app.utils.qr import qr_data_uri

preauth = Blueprint("preauth", __name__, url_prefix="/")
logger = logging.getLogger(__name__)

#: Answer of the form routes when the ``form_countries`` feature is off.
FORM_ISSUANCE_DISABLED = "Pre-authorized form issuance is disabled"

#: Longest accepted ``exp - iat`` of a credentialOfferReq2 request JWT (seconds).
OFFER_REQUEST_MAX_LIFETIME = 3600

AGE_VERIFICATION_SCOPES = (
    "eu.europa.ec.eudi.age_verification_mdoc",
    "eu.europa.ec.eudi.age_verification_mdoc_passport",
)


def _authorization_details(credential_ids: list) -> list:
    """Builds ``openid_credential`` authorization details.

    Args:
        credential_ids: Credential configuration ids.

    Returns:
        One authorization detail per id.
    """
    return [{"type": "openid_credential", "credential_configuration_id": cid} for cid in credential_ids]


def request_preauth_token(scope: str, frontend_id: Optional[str] = None) -> str:
    """Obtains a pre-authorized code and creates the matching issuance session.

    Args:
        scope: Space separated credential configuration ids.
        frontend_id: Frontend whose offer it is (default: ``frontend.default``).

    Returns:
        The new session id (assigned by the authorization server).
    """
    frontend_id = frontend_id or CONFIGURATION["frontend"]["default"]
    response = generate_preauth_code(scope, frontend_id)
    session_id = response.get("session_id")
    logger.info(f", Session ID: {safe(session_id, 64)}, Pre-authorized code obtained for scope {safe(scope, 200)}")
    session_manager.add_session(
        session_id=session_id,
        pre_authorized_code=response.get("preauth_code"),
        scope=scope,
        tx_code=response.get("tx_code"),
        country="AV" if scope in AGE_VERIFICATION_SCOPES else "FC",
        frontend_id=frontend_id,
    )
    return session_id


def _requested_credentials(raw: Any) -> Optional[List[str]]:
    """Parses and validates the ``credentials_id`` parameter.

    Args:
        raw: Parameter value: a JSON list of credential configuration ids.

    Returns:
        The ids, or ``None`` when the value is missing, not a non-empty JSON
        list of strings, or names a credential the issuer does not support.
    """
    if not isinstance(raw, str) or not raw:
        return None
    try:
        credential_list = json.loads(raw)
    except ValueError:
        return None
    supported = oidc_metadata.get("credential_configurations_supported") or {}
    if (
        not isinstance(credential_list, list)
        or not credential_list
        or not all(isinstance(c, str) and c in supported for c in credential_list)
    ):
        return None
    return credential_list


@preauth.route("/preauth", methods=["POST"])
@require_frontend_origin
def preauthRed() -> Union[str, Tuple[str, int]]:
    """Starts a pre-authorized flow for the credentials chosen in the offer form.

    POST only (it obtains a pre-authorized code), reached from
    ``/credential_offer`` by a ``307`` redirect that re-posts the offer form.

    Parameters (query or form):
        credentials_id: JSON list of supported credential configuration ids.

    Returns:
        The attribute form page, ``400`` for a missing or invalid
        ``credentials_id``, or ``403`` when the feature is off.
    """
    if not feature_enabled("form_countries"):
        return FORM_ISSUANCE_DISABLED, HTTPStatus.FORBIDDEN

    credential_list = _requested_credentials(request.values.get("credentials_id"))
    if credential_list is None:
        logger.warning(f"/preauth rejected: invalid credentials_id {safe(request.values.get('credentials_id'), 200)}")
        return "Invalid or missing credentials_id", HTTPStatus.BAD_REQUEST
    session_id = request_preauth_token(scope=" ".join(credential_list), frontend_id=session.get("frontend_id"))
    session["session_id"] = session_id

    authorization_details = _authorization_details(credential_list)
    session_manager.update_authorization_details(session_id=session_id, authorization_details=authorization_details)

    credentials_requested = requested_credential_ids(authorization_details)
    session_manager.update_credentials_requested(session_id=session_id, credentials_requested=credentials_requested)

    mandatory_attributes = getAttributesForm(credentials_requested)
    optional_attributes = optional_only(getAttributesForm2(credentials_requested), mandatory_attributes)

    current_session = session_manager.get_session(session_id=session_id)
    return post_redirect_with_payload(
        target_url=f"{frontend_url(current_session.frontend_id)}/display_form",
        data_payload={
            "mandatory_attributes": mandatory_attributes,
            "optional_attributes": optional_attributes,
            "redirect_url": f"{CONFIGURATION['service_url']}/preauth_form",
            "session_id": session_id,
        },
    )


@preauth.route("/preauth_form", methods=["POST"])
@require_frontend_origin
def preauth_form() -> str:
    """Receives the attribute form and shows the consent page.

    Returns:
        The consent page.
    """
    if not feature_enabled("form_countries"):
        return FORM_ISSUANCE_DISABLED, HTTPStatus.FORBIDDEN

    form_data = parse_form(request.form)

    session_id = session["session_id"]
    current_session = session_manager.get_session(session_id=session_id)
    logger.info(f", Session ID: {session_id}, Pre-authorized attribute form submitted")
    logger.debug(f", Session ID: {session_id}, Form fields: {safe(sorted(form_data), 500)}")

    form_data.pop("proceed", None)
    try:
        cleaned_data = form_formatter(form_data, issuing_country=current_session.country)
    except InvalidFormError as e:
        logger.warning(f", Session ID: {session_id}, Attribute form rejected: {safe(e)}")
        return "Invalid attribute form", HTTPStatus.BAD_REQUEST
    session_manager.update_user_data(session_id=session_id, user_data=cleaned_data)

    presentation_data = presentation_formatter(
        cleaned_data=cleaned_data,
        credentials_requested=current_session.credentials_requested,
        country=current_session.country,
    )
    return post_redirect_with_payload(
        target_url=f"{frontend_url(current_session.frontend_id)}/display_authorization",
        data_payload={
            "presentation_data": presentation_data,
            "image_attributes": list(IMAGE_ATTRIBUTES),
            "redirect_url": f"{CONFIGURATION['service_url']}/form_authorize_generate",
            "session_id": session_id,
        },
    )


@preauth.route("/form_authorize_generate", methods=["GET", "POST"])
@require_frontend_origin
def form_authorize_generate() -> str:
    """Generates the credential offer after the user consented.

    Returns:
        The credential offer QR code page.
    """
    if not feature_enabled("form_countries"):
        return FORM_ISSUANCE_DISABLED, HTTPStatus.FORBIDDEN

    current_session = session_manager.get_session(session.get("session_id", ""))
    if current_session is None or not current_session.user_data:
        return "Unknown or expired session", HTTPStatus.BAD_REQUEST
    return generate_offer(current_session.user_data)


def generate_offer(data: Dict[str, Any]) -> str:
    """Shows the pre-authorized credential offer of the current session.

    Args:
        data: User data (unused; kept for API compatibility).

    Returns:
        The frontend page with the offer, its URI and QR code.
    """
    session_id = session["session_id"]
    current_session = session_manager.get_session(session_id=session_id)
    frontend_id = session.get("frontend_id")

    offer = pre_authorized_offer(
        credential_issuer=frontend_url(frontend_id),
        credential_configuration_ids=current_session.credentials_requested,
        issuer_state=session_id,
        pre_authorized_code=current_session.pre_authorized_code,
    )
    uri = offer_link(session["credential_offer_URI"], offer, session.get("credential_offer_mode"))

    return post_redirect_with_payload(
        target_url=f"{frontend_url(frontend_id)}/display_credential_offer_qr_code",
        data_payload={
            "wallet_dev": f"{CONFIGURATION['wallet_tester_url']}/redirect_preauth",
            "credential_offer": offer,
            "url_data": uri,
            "qrcode": qr_data_uri(uri, scale=2),
            "tx_code": current_session.tx_code,
            "code": generate_unique_id(),
        },
    )


@preauth.route("/credentialOfferReq2", methods=["POST"])
def credentialOfferReq2() -> Union[Dict[str, Any], Tuple[Response, int]]:
    """Creates a pre-authorized offer from a signed request.

    Test only: the signer chooses both the credential type and its data, so
    the endpoint answers ``403`` unless the ``credential_offer_request`` test
    feature is on. The ``request`` JWT must carry an ``x5c`` chain trusted by
    the trust validator or the local trusted CAs (see
    :mod:`app.services.trust`); its signature is verified, and ``exp`` and
    ``iat`` are required (lifetime at most :data:`OFFER_REQUEST_MAX_LIFETIME`).

    Form parameters:
        request: JWT whose payload has ``credentials: [{credential_configuration_id, data}]``.

    Returns:
        ``{"credential_offer", "tx_code"}`` (the bare offer with the
        ``tx_code`` value inside when the ``tx_code_in_offer`` test feature is
        on), ``400`` when ``request`` is missing or malformed,
        ``401`` when the JWT is not signed by a trusted certificate, or
        ``403`` when the feature is off.
    """
    if not feature_enabled("credential_offer_request"):
        logger.warning("credentialOfferReq2 rejected: credential_offer_request test feature is off")
        return jsonify({"error": "access_denied", "error_description": "Credential offer requests are disabled"}), 403

    json_token = request.form.get("request")
    if not json_token:
        return jsonify({"error": "invalid_request", "error_description": "Missing request JWT"}), 400

    try:
        json_payload = verify_jwt_with_x5c(
            json_token,
            verification_context=trust_context("credential_offer_request", CREDENTIAL_OFFER_REQUEST_CONTEXT),
            use_case=trust_use_case("credential_offer_request"),
            required_claims=("exp", "iat"),
            purpose=PURPOSE_OFFER_REQUEST,
        )
        if json_payload["exp"] - json_payload["iat"] > OFFER_REQUEST_MAX_LIFETIME:
            raise jwt.InvalidTokenError(f"Request JWT lifetime exceeds {OFFER_REQUEST_MAX_LIFETIME} s")
    except CertificateVerificationError as e:
        logger.warning(f"credentialOfferReq2 rejected: untrusted signer: {safe(e)}")
        return jsonify({"error": "invalid_request", "error_description": "Untrusted request signer"}), 401
    except jwt.InvalidTokenError as e:
        logger.warning(f"credentialOfferReq2 rejected: invalid JWT: {safe(e)}")
        return jsonify({"error": "invalid_request", "error_description": "Invalid request JWT signature"}), 401
    except ValueError as e:
        logger.warning(f"credentialOfferReq2 rejected: malformed JWT: {safe(e)}")
        return jsonify({"error": "invalid_request", "error_description": str(e)}), 400

    credentials = json_payload["credentials"]
    credential_ids = list(dict.fromkeys(c["credential_configuration_id"] for c in credentials))

    session_id = request_preauth_token(scope=" ".join(credential_ids))
    session_manager.update_authorization_details(
        session_id=session_id,
        authorization_details=_authorization_details([c["credential_configuration_id"] for c in credentials]),
    )
    session_manager.update_user_data(session_id=session_id, user_data=credentials[0]["data"])

    current_session = session_manager.get_session(session_id=session_id)
    if feature_enabled("tx_code_in_offer"):
        return pre_authorized_offer(
            credential_issuer=frontend_url(),
            credential_configuration_ids=credential_ids,
            issuer_state=session_id,
            pre_authorized_code=current_session.pre_authorized_code,
            tx_code_value=current_session.tx_code,
        )

    # The tx_code is a second factor: the caller hands it to the user out of
    # band, so it must not travel inside the offer (QR code / deeplink).
    offer = pre_authorized_offer(
        credential_issuer=frontend_url(),
        credential_configuration_ids=credential_ids,
        issuer_state=session_id,
        pre_authorized_code=current_session.pre_authorized_code,
    )
    return {"credential_offer": offer, "tx_code": current_session.tx_code}
