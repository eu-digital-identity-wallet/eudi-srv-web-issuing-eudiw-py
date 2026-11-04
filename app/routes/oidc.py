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
"""OpenID4VCI endpoints: authorization method choice, credential,
deferred credential, notification, nonce and credential offers.

The handlers only parse requests and shape responses; the business logic
lives in :mod:`app.services.credential_issuance`,
:mod:`app.services.credential_offer` and :mod:`app.services.auth_server`.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

import jwt
import requests
import werkzeug
from jwcrypto import jwk
from flask import Blueprint, Response, jsonify, redirect, request, session, url_for
from flask.helpers import make_response

from app.core.config import CONFIGURATION
from app.core.errors import OAuthEndpointError, error_body, oauth_error_response, token_error_response
from app.core.log_utils import safe, summarize_credential_request
from app.core.security import require_admin_api_key, require_frontend_origin
from app.core.state import oidc_metadata, session_manager
from app.repositories.offer_store import credential_offer_references
from app.repositories.status_store import persist_client_status
from app.services.attributes import (
    credential_display_names,
    requested_credential_ids,
    scope2details,
    vct2id,
)
from app.services.auth_server import (
    ACCESS_TOKEN_ALGORITHMS,
    SessionTokenError,
    StatusCheckError,
    authorization_details_claim,
    check_status_list_revocation,
    decode_authorization_server_jwt,
    introspect,
    verify_session_token,
)
from app.services.dpop import DPoPError, DPoPSchemeError, expected_htu, verify_dpop_request
from app.services.credential_issuance import (
    DEFERRED_ONLY_CONFIGURATION,
    InvalidEncryptionParametersError,
    ProvenKeys,
    check_response_encryption,
    create_c_nonce,
    encrypt_jwe,
    decrypt_jwe_credential_request,
    generate_credentials,
)
from app.services.credential_offer import authorization_code_offer, credential_offer_uri, is_valid_offer_prefix, offer_link
from app.services.frontend_metadata import frontend_publishes
from app.services.oid4vp import fetch_presentation_result, presentation_result_url, validate_presentation_id
from app.utils.frontend import frontend_url
from app.utils.http import post_redirect_with_payload
from app.utils.ids import generate_unique_id
from app.utils.qr import qr_data_uri, qr_png_base64

oidc = Blueprint("oidc", __name__, url_prefix="/")

logger = logging.getLogger(__name__)

HandlerResult = Union[Response, Tuple[Any, int]]

DEFERRED_INTERVAL_SECONDS = 30
#: OpenID4VCI 1.0 section 11.1 notification events.
NOTIFICATION_EVENTS = ("credential_accepted", "credential_failure", "credential_deleted")
_ANSI_ESCAPE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
#: Issuance session ids are UUIDs (authorization server / revocation flow).
_SESSION_ID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------


def _access_token() -> str:
    """Reads the access token of a request to a protected endpoint.

    The token is sent in the ``Authorization`` header with the ``Bearer``
    (RFC 6750 section 2.1) or ``DPoP`` (RFC 9449 section 7.1) scheme.

    Returns:
        The access token.

    Raises:
        OAuthEndpointError: ``401`` without an error code when the request
            has no Bearer / DPoP credentials (RFC 6750 section 3.1), ``401
            invalid_token`` when the scheme carries no token.
    """
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() not in ("bearer", "dpop"):
        raise OAuthEndpointError(None, 401)
    token = token.strip()
    if not token:
        raise OAuthEndpointError("invalid_token", 401, "Missing access token")
    return token


def _is_introspection_success(result: Any) -> bool:
    """Tells a successful :func:`verify_introspection` result from an error response.

    Args:
        result: Return value of :func:`verify_introspection`.

    Returns:
        ``True`` for ``(session_id: str, client_status)``.
    """
    return isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], str)


def _read_credential_request(invalid_jwt_error: str) -> Dict[str, Any]:
    """Reads a credential request body (JSON, or a JWE with ``application/jwt``).

    Args:
        invalid_jwt_error: ``error`` value used when the body cannot be read.

    Returns:
        The request dictionary.

    Raises:
        OAuthEndpointError: ``400`` if the JWE cannot be decrypted or the
            body is not a JSON object.
    """
    if request.content_type == "application/jwt":
        jwt_token = request.get_data(as_text=True)
        logger.debug(f"Credential request received as JWE ({len(jwt_token)} chars)")
        try:
            body = decrypt_jwe_credential_request(jwt_token)
        except Exception as e:
            logger.warning(f"Failed to decrypt credential request JWE: {safe(e)}")
            raise OAuthEndpointError(invalid_jwt_error) from e
    else:
        body = request.get_json(silent=True)

    if not isinstance(body, dict):
        raise OAuthEndpointError(invalid_jwt_error)
    return body


# ---------------------------------------------------------------------------
# Validation helpers (return Flask error responses)
# ---------------------------------------------------------------------------


def _client_status_list(client_status: Any) -> Optional[Dict[str, Any]]:
    """Returns the ``status.status_list`` pointer of a ``client_status`` claim.

    Args:
        client_status: ``client_status`` claim of the access token.

    Returns:
        ``{"idx", "uri"}``, or ``None`` when the claim does not have that shape.
    """
    status = client_status.get("status") if isinstance(client_status, dict) else None
    status_list = status.get("status_list") if isinstance(status, dict) else None
    if isinstance(status_list, dict) and "idx" in status_list and "uri" in status_list:
        return status_list
    return None


def verify_introspection(bearer_token: str) -> Any:
    """Validates an access token with the authorization server.

    When the access token is a JWT carrying a WIA ``client_status`` and the
    status validator is enabled, the WIA revocation status is checked too.
    When introspection reports ``cnf.jkt`` (a DPoP-bound token), the request
    must carry a valid DPoP proof for that key (:mod:`app.services.dpop`).

    Args:
        bearer_token: Access token.

    Returns:
        ``(session_id, client_status)`` on success (``client_status`` may be
        ``None``), otherwise a ``(json_response, status)`` error tuple. A WIA
        that is revoked or whose status cannot be checked yields ``401``.
    """
    try:
        response = introspect(bearer_token)
        response.raise_for_status()
        introspection_data = response.json()
    except requests.exceptions.RequestException as e:
        logger.exception(f"Token introspection request failed: {safe(e)}")
        return jsonify({"error": "Failed to validate token with the issuer."}), 502
    except json.JSONDecodeError:
        logger.exception("Failed to decode JSON from introspection response.")
        return jsonify({"error": "Invalid response from the introspection endpoint."}), 502

    if not introspection_data.get("active", False):
        return token_error_response("invalid_token", description="The access token is not active")

    username = introspection_data.get("username")
    if not username:
        logger.warning("Token is active but introspection returned no username.")
        return token_error_response("invalid_token")

    jkt = (introspection_data.get("cnf") or {}).get("jkt")
    if jkt and (error := _dpop_error(bearer_token, jkt, username)):
        return error

    try:
        client_status = _access_token_client_status(bearer_token)
    except (jwt.PyJWTError, OSError, ValueError) as e:
        logger.warning(f"Access token signature not verified for session tied to {safe(username, 64)}: {safe(e)}")
        return token_error_response("invalid_token")

    if client_status and CONFIGURATION["status_validator"]["enabled"]:
        if error := _wia_status_error(client_status, username):
            return error

    return username, client_status


def _access_token_client_status(bearer_token: str) -> Any:
    """Reads the ``client_status`` claim of a JWT access token.

    The claim is read from the access token itself: only after its signature
    is verified with the authorization server keys.

    Args:
        bearer_token: Access token.

    Returns:
        The claim, or ``None`` (opaque token or no claim).

    Raises:
        jwt.PyJWTError, OSError, ValueError: If the signature cannot be verified.
    """
    if bearer_token.count(".") != 2:
        logger.debug("Access token is not a JWT; no client_status claim available.")
        return None
    at_claims = decode_authorization_server_jwt(bearer_token, ACCESS_TOKEN_ALGORITHMS, options={"verify_aud": False})
    return at_claims.get("client_status")


def _dpop_error(bearer_token: str, jkt: str, username: str) -> Optional[HandlerResult]:
    """Checks the DPoP proof of a request made with a DPoP-bound access token.

    Args:
        bearer_token: Access token.
        jkt: ``cnf.jkt`` thumbprint the token is bound to.
        username: Session the token belongs to (for logging).

    Returns:
        ``None`` when the proof is valid, otherwise the ``401`` error:
        ``invalid_token`` for the token sent with another scheme (RFC 9449
        section 7.2), ``invalid_dpop_proof`` for a missing or invalid proof
        (section 7.1), both with a ``DPoP`` challenge.
    """
    try:
        verify_dpop_request(
            authorization=request.headers.get("Authorization", ""),
            proof=request.headers.get("DPoP"),
            access_token=bearer_token,
            jkt=jkt,
            method=request.method,
            htu=expected_htu(request.path, request.base_url),
        )
    except DPoPSchemeError as e:
        logger.warning(f"DPoP check failed for session tied to {safe(username)}: {safe(e)}")
        return token_error_response("invalid_token", description="DPoP-bound access token", scheme="DPoP")
    except DPoPError as e:
        logger.warning(f"DPoP check failed for session tied to {safe(username)}: {safe(e)}")
        return token_error_response("invalid_dpop_proof", description="Invalid DPoP proof", scheme="DPoP")
    return None


def _wia_status_error(client_status: Any, username: str) -> Optional[HandlerResult]:
    """Checks the revocation status of the WIA of an access token.

    Fails closed: a malformed, unverifiable or revoked status is rejected.

    Args:
        client_status: ``client_status`` claim of the access token.
        username: Session the token belongs to (for logging).

    Returns:
        ``None`` when the WIA is valid, otherwise the ``401`` error.
    """
    status_list = _client_status_list(client_status)
    if status_list is None:
        logger.error(f"Malformed WIA client_status for session tied to {safe(username, 64)}")
        return token_error_response("invalid_token", description="Malformed client_status")
    try:
        revoked = check_status_list_revocation(
            url=CONFIGURATION["status_validator"]["url"],
            status_idx=status_list["idx"],
            status_uri=status_list["uri"],
        )
    except StatusCheckError as e:
        logger.exception(f"WIA client_status could not be checked for session tied to {safe(username)}: {safe(e)}")
        return token_error_response("invalid_token", description="Wallet status could not be verified")
    if revoked:
        logger.error(f"WIA client_status revoked for session tied to {safe(username)}")
        return token_error_response("invalid_token")
    return None


def verify_credential_request(credential_request: Dict[str, Any], stored: bool = False) -> Dict[str, Any]:
    """Checks the structure of a credential request (OpenID4VCI 1.0 section 8.2).

    Args:
        credential_request: Credential request body.
        stored: The request was validated before (deferred issuance); its
            ``credential_configuration_id`` may then have been filled in
            from ``credential_identifier``.

    Returns:
        The request itself when valid.

    Raises:
        OAuthEndpointError: ``400`` with ``invalid_credential_request`` (no,
            both or misspelled credential identifiers, or a non-string one)
            or ``invalid_proof`` (missing, malformed or both ``proof`` and
            ``proofs``; ``proofs`` with other than one proof type).
    """
    if "credential_indentifier" in credential_request:
        raise OAuthEndpointError("invalid_credential_request")
    id_parameters = [p for p in ("credential_identifier", "credential_configuration_id") if p in credential_request]
    if not id_parameters:
        raise OAuthEndpointError("invalid_credential_request")
    if len(id_parameters) == 2 and not stored:
        raise OAuthEndpointError(
            "invalid_credential_request",
            description="credential_identifier and credential_configuration_id must not both be present",
        )
    if not all(isinstance(credential_request[p], str) and credential_request[p] for p in id_parameters):
        raise OAuthEndpointError("invalid_credential_request")
    if "proof" not in credential_request and "proofs" not in credential_request:
        raise OAuthEndpointError("invalid_proof")
    if "proof" in credential_request and "proofs" in credential_request:
        raise OAuthEndpointError("invalid_proof", description="proof and proofs must not both be present")

    if "proof" in credential_request:
        proof = credential_request["proof"]
        if not isinstance(proof, dict):
            raise OAuthEndpointError("invalid_proof")
        proof_type = proof.get("proof_type")
        if proof_type is None or (proof_type in ("attestation", "jwt") and proof_type not in proof):
            raise OAuthEndpointError("invalid_proof")
    else:
        proofs = credential_request["proofs"]
        if not isinstance(proofs, dict) or len(proofs) != 1:
            raise OAuthEndpointError("invalid_proof", description="proofs must contain exactly one proof type")

    if "credential_configuration_id" not in credential_request:
        # This issuer's credential identifiers are its configuration ids.
        credential_request["credential_configuration_id"] = credential_request["credential_identifier"]

    return credential_request


def _authorized_configuration_ids(current_session: Any) -> set:
    """Lists the credential configurations an issuance session was authorized for.

    Args:
        current_session: The access token's issuance session.

    Returns:
        Ids from ``credentials_requested``, ``authorization_details`` and ``scope``.
    """
    def as_list(value: Any) -> List[Any]:
        return list(value) if isinstance(value, (list, tuple)) else []

    authorized = {c for c in as_list(getattr(current_session, "credentials_requested", None)) if isinstance(c, str)}
    details = [d for d in as_list(getattr(current_session, "authorization_details", None)) if isinstance(d, dict)]
    authorized.update(c for c in requested_credential_ids(details, resolve_vct=vct2id) if isinstance(c, str))
    scope = getattr(current_session, "scope", None)
    if isinstance(scope, str):
        authorized.update(scope.split())
    return authorized


def require_authorized_configuration(
    session_id: str, credential_request: Dict[str, Any], by_identifier: bool = False
) -> None:
    """Rejects a credential the access token was not authorized for.

    Args:
        session_id: The access token's issuance session.
        credential_request: Validated credential request.
        by_identifier: The wallet sent ``credential_identifier`` (the
            identifiers it may use are those of its access token).

    Raises:
        OAuthEndpointError: ``401 invalid_token`` for an unknown session;
            ``400 unknown_credential_identifier`` for an identifier not
            issued with the access token; ``403 insufficient_scope`` for a
            supported credential configuration the access token does not
            cover (OpenID4VCI 1.0 section 8.3.1.1, RFC 6750 section 3.1);
            ``400 unknown_credential_configuration`` for an unsupported one.
    """
    current_session = session_manager.get_session(session_id=session_id)
    if current_session is None:
        raise OAuthEndpointError("invalid_token", status=401)
    requested = credential_request.get("credential_configuration_id")
    if requested in _authorized_configuration_ids(current_session):
        return
    logger.warning(f", Session ID: {safe(session_id, 64)}, Credential not authorized: {safe(requested, 100)}")
    if by_identifier:
        raise OAuthEndpointError("unknown_credential_identifier", description="Unknown credential identifier")
    if requested in (oidc_metadata.get("credential_configurations_supported") or {}):
        raise OAuthEndpointError(
            "insufficient_scope", 403, "The access token does not authorize this credential configuration"
        )
    raise OAuthEndpointError("unknown_credential_configuration", description="Unknown credential configuration")


def require_valid_response_encryption(credential_request: Dict[str, Any]) -> None:
    """Rejects unusable ``credential_response_encryption`` before issuance.

    Args:
        credential_request: Request that may carry ``credential_response_encryption``.

    Raises:
        OAuthEndpointError: ``400 invalid_encryption_parameters``.
    """
    if "credential_response_encryption" not in credential_request:
        return
    try:
        check_response_encryption(credential_request["credential_response_encryption"])
    except InvalidEncryptionParametersError as e:
        logger.warning(f"Credential response encryption rejected: {safe(e)}")
        raise OAuthEndpointError("invalid_encryption_parameters", description=str(e)) from e


def encrypt_response(credential_request: Dict[str, Any], credential_response: Dict[str, Any]) -> Response:
    """Encrypts a credential response as a compact JWE.

    The wallet key's ``kid`` (if any) is echoed in the JWE header so the
    wallet can select its decryption key.

    Args:
        credential_request: Request containing ``credential_response_encryption``
            (``jwk``, ``enc`` and ``alg`` in the config or the JWK).
        credential_response: Response body to encrypt.

    Returns:
        An ``application/jwt`` response, or a ``400`` error response.
    """
    encryption_config = credential_request.get("credential_response_encryption", {})

    def error(description: str) -> Response:
        """Builds an ``invalid_encryption_parameters`` 400 response (OpenID4VCI 1.0 section 8.3.1.2)."""
        return make_response(
            jsonify(error_body("invalid_encryption_parameters", description)),
            400,
        )

    if not encryption_config or not all(k in encryption_config for k in ("jwk", "enc")):
        return error("Missing required fields in credential_response_encryption.")

    alg = encryption_config.get("alg") or encryption_config["jwk"].get("alg")
    if alg is None:
        return error("Missing alg field in credential_response_encryption.")

    try:
        wallet_key = jwk.JWK(**encryption_config["jwk"])
        jwe_token = encrypt_jwe(
            credential_response,
            wallet_key,
            alg=alg,
            enc=encryption_config["enc"],
            kid=encryption_config["jwk"].get("kid"),
        )
    except Exception:
        return error("Failed to encrypt with the provided key.")

    response = make_response(jwe_token)
    response.headers["Content-Type"] = "application/jwt"
    return response


# ---------------------------------------------------------------------------
# Shared credential pipeline
# ---------------------------------------------------------------------------


def _issue(
    validated_request: Dict[str, Any],
    session_id: str,
    wia_client_status: Optional[Dict[str, Any]],
    holder_keys: ProvenKeys,
) -> Dict[str, Any]:
    """Records the WIA status and generates the credential(s).

    Args:
        validated_request: Validated credential request.
        session_id: Issuance session.
        wia_client_status: ``client_status`` from the access token.
        holder_keys: Keys proven by the request (filled in), or by the
            request that started a deferred transaction (reused).

    Returns:
        The credential response dict (possibly with ``error``).
    """
    if wia_client_status:
        session_manager.update_client_status_status(session_id, wia_client_status.get("status"))
        session_manager.update_client_status_exp(session_id, wia_client_status.get("exp"))

    response = generate_credentials(
        credential_request=validated_request,
        session_id=session_id,
        wia_client_status=wia_client_status,
        holder_keys=holder_keys,
    )
    if not isinstance(response, dict):
        return {"error": "invalid_proof", "error_description": "Unable to read proof"}
    return response


def _add_notification_id(session_id: str, response: Dict[str, Any]) -> None:
    """Generates a notification id, stores it in the session and adds it to ``response``.

    Args:
        session_id: Issuance session.
        response: Credential response (mutated).
    """
    notification_id = str(uuid.uuid4())
    session_manager.store_notification_id(session_id=session_id, notification_id=notification_id)
    response["notification_id"] = notification_id


def _finish(
    session_id: str,
    response: Dict[str, Any],
    is_deferred: bool,
    encryption_request: Dict[str, Any],
) -> HandlerResult:
    """Persists client status and returns the (optionally encrypted) response.

    Args:
        session_id: Issuance session.
        response: Credential (or deferred) response.
        is_deferred: Whether issuance is deferred (``202``).
        encryption_request: Request whose ``credential_response_encryption``
            governs encryption.

    Returns:
        ``(response, 200 | 202)`` or an encryption error response.
    """
    current_session = session_manager.get_session(session_id=session_id)
    if not is_deferred and current_session and current_session.client_status:
        persist_client_status(session_id, current_session.client_status)

    status = 202 if is_deferred else 200
    body: Any = response
    if "credential_response_encryption" in encryption_request:
        body = encrypt_response(credential_request=encryption_request, credential_response=response)
        if body.status_code != 200:
            return body

    if not is_deferred:
        session_manager.mark_credential_issued(session_id)
        logger.info(f", Session ID: {session_id}, Credential Issuance Successful")
    return body, status


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def _auth_methods(credentials_requested: List[str]) -> Tuple[bool, bool]:
    """Determines which authentication methods support all requested credentials.

    Args:
        credentials_requested: Credential configuration ids.

    Returns:
        ``(pid_auth, country_selection)``.
    """
    supported = CONFIGURATION["credential_auth_methods"]
    pid_auth = all(cred in supported["PID_login"] for cred in credentials_requested)
    country_selection = all(cred in supported["country_selection"] for cred in credentials_requested)
    return pid_auth, country_selection


@oidc.route("/auth_choice", methods=["GET"])
def auth_choice() -> HandlerResult:
    """Starts an issuance session and picks the user authentication method.

    Redirects to the PID (OID4VP) login or country selection when only one
    method fits; otherwise shows the method choice page.

    Returns:
        A redirect, the frontend POST-redirect page, or a ``400`` error.

    Raises:
        ValueError: If no credential was requested.
    """
    token = request.args.get("token")
    # session_id, scope and authorization_details come only from the token
    # signed by the authorization server: query parameters could be forged
    # to fix or take over another user's session.
    try:
        claims = verify_session_token(request.args.get("session_token"))
        authorization_details: List[Any] = authorization_details_claim(claims.get("authorization_details"))
    except SessionTokenError as e:
        logger.warning(f"auth_choice rejected: {safe(e)}")
        return jsonify({"error": "invalid_request", "error_description": "Invalid or missing session_token"}), 400

    session_id = claims["session_id"]
    scope = claims.get("scope")
    # The frontend whose issuer the wallet used; the authorization server
    # always names it.
    frontend_id = claims.get("frontend_id")
    if frontend_id not in (CONFIGURATION["frontend"].get("frontends_config") or {}):
        logger.warning(f", Session ID: {session_id}, auth_choice rejected: unknown frontend {safe(frontend_id, 64)}")
        return jsonify({"error": "invalid_request", "error_description": "Unknown frontend"}), 400

    if session_manager.get_session(session_id) is not None and session.get("session_id") != session_id:
        logger.warning(f", Session ID: {session_id}, auth_choice rejected: session already bound to another browser")
        return jsonify({"error": "invalid_request", "error_description": "Session already in use"}), 400

    session["session_id"] = session_id

    credential_configuration_id = None
    if scope:
        authorization_details.extend(scope2details(scope.split()))
        credential_configuration_id = scope.replace("openid", "").strip()

    if not authorization_details:
        raise ValueError(f"invalid authentication. Session ID: {session_id}")

    credentials_requested = requested_credential_ids(
        (d for d in authorization_details if isinstance(d, dict)), resolve_vct=vct2id
    )

    session_manager.add_session(
        session_id=session_id,
        jws_token=token,
        scope=credential_configuration_id,
        authorization_details=authorization_details,
        credentials_requested=credentials_requested,
        frontend_id=frontend_id,
    )

    return _show_auth_methods(session_id, credentials_requested, frontend_id)


@oidc.route("/auth_method_choice", methods=["GET"])
def auth_method_choice() -> HandlerResult:
    """Shows the authentication method choice again (the PID login page's Back).

    Returns:
        A redirect or the frontend POST-redirect page, or ``400`` when the
        browser has no active issuance session.
    """
    session_id = session.get("session_id")
    current_session = session_manager.get_session(session_id=session_id) if session_id else None
    if current_session is None:
        return jsonify({"error": "invalid_request", "error_description": "No active issuance session"}), 400
    return _show_auth_methods(session_id, current_session.credentials_requested, current_session.frontend_id)


def _show_auth_methods(session_id: str, credentials_requested: List[str], frontend_id: str) -> HandlerResult:
    """Redirects to the only authentication method that fits, or shows the choice.

    Args:
        session_id: Issuance session.
        credentials_requested: Credential configuration ids.
        frontend_id: Frontend the session's pages are shown on.

    Returns:
        A redirect, or the frontend POST-redirect page.
    """
    pid_auth, country_selection = _auth_methods(credentials_requested)

    if pid_auth and not country_selection:
        return redirect(f"{CONFIGURATION['service_url']}/oid4vp")
    if country_selection and not pid_auth:
        return redirect(f"{CONFIGURATION['service_url']}/dynamic/")

    return post_redirect_with_payload(
        target_url=f"{frontend_url(frontend_id)}/display_auth_method",
        data_payload={
            "pid_auth": pid_auth,
            "country_selection": country_selection,
            "redirect_url": f"{CONFIGURATION['service_url']}/",
            "session_id": session_id,
        },
    )


@oidc.route("/pid_authorization")
def pid_authorization_get() -> HandlerResult:
    """Checks whether the verifier has received the PID presentation.

    Returns:
        ``200`` once the presentation is available, ``500`` otherwise.

    Raises:
        ValueError: If ``presentation_id`` is missing or malformed.
    """
    presentation_id = validate_presentation_id(request.args.get("presentation_id"))
    response = fetch_presentation_result(presentation_result_url(presentation_id))
    if response.status_code != 200:
        return jsonify({"error": str(response.status_code)}), 500
    return jsonify({"message": {"message": "Sucess"}}), 200


@oidc.route("/credential", methods=["POST"])
def credential() -> HandlerResult:
    """OpenID4VCI credential endpoint.

    Returns:
        ``200`` with the credential(s), ``202`` with a ``transaction_id``
        for deferred issuance, or an error response.
    """
    bearer_token = _access_token()

    credential_request = _read_credential_request("invalid_credential_request")

    introspection = verify_introspection(bearer_token=bearer_token)
    if not _is_introspection_success(introspection):
        return introspection
    session_id, wia_client_status = introspection

    by_identifier = "credential_configuration_id" not in credential_request
    validated_request = verify_credential_request(credential_request)
    logger.info(f", Session ID: {session_id}, Credential Request, {summarize_credential_request(validated_request)}")
    require_authorized_configuration(session_id, validated_request, by_identifier=by_identifier)
    require_valid_response_encryption(validated_request)

    holder_keys = ProvenKeys()
    response = _issue(validated_request, session_id, wia_client_status, holder_keys)

    if response.get("error", "Pending") != "Pending":
        logger.warning(
            f", Session ID: {session_id}, Credential request denied: "
            f"error={safe(response.get('error'))} description={safe(response.get('error_description'))}"
        )
        # OpenID4VCI 1.0 section 8.3.1.2: only error / error_description.
        return jsonify(error_body(response["error"], response.get("error_description"))), 400

    is_deferred = (
        response.get("error") == "Pending"
        or validated_request.get("credential_configuration_id") == DEFERRED_ONLY_CONFIGURATION
    )
    if is_deferred:
        transaction_id = str(uuid.uuid4())
        # The proofs' c_nonces may be spent (or expire): the deferred request reuses the keys.
        session_manager.add_transaction_id(
            session_id=session_id,
            transaction_id=transaction_id,
            credential_request=validated_request,
            holder_keys=holder_keys,
        )
        response = {"transaction_id": transaction_id, "interval": DEFERRED_INTERVAL_SECONDS}
    else:
        # OpenID4VCI 1.0 section 8.3: notification_id only with issued credentials
        # (never in error or deferred responses).
        _add_notification_id(session_id, response)

    return _finish(session_id, response, is_deferred, validated_request)


@oidc.route("/admin/sessions/client_status", methods=["GET"])
@require_admin_api_key
def get_all_sessions_client_status() -> HandlerResult:
    """Returns the client_status of every active session that has one.

    Requires the ``X-Api-Key`` header (``admin_api_key``).

    Returns:
        ``({session_id: client_status}, 200)``.
    """
    return jsonify(session_manager.get_all_client_statuses()), 200


@oidc.route("/notification", methods=["POST"])
def notification() -> HandlerResult:
    """OpenID4VCI notification endpoint.

    The ``notification_id`` must be one issued to the access token's session
    (:meth:`SessionManager.get_session_by_notification_id`); nothing from the
    request is logged before that check.

    Returns:
        ``204`` on success; ``400`` ``invalid_notification_request`` for a
        malformed request (no JSON object, missing or non-string
        ``notification_id``, unknown ``event``), ``400``
        ``invalid_notification_id`` for an unknown or foreign id (OpenID4VCI
        1.0 section 11.3); ``401`` / ``403`` for access token errors.
    """
    bearer_token = _access_token()

    introspection = verify_introspection(bearer_token=bearer_token)
    if not _is_introspection_success(introspection):
        return introspection
    session_id, _ = introspection

    notification_request = request.get_json(silent=True)
    if (
        not isinstance(notification_request, dict)
        or not isinstance(notification_request.get("notification_id"), str)
        or notification_request.get("event") not in NOTIFICATION_EVENTS
    ):
        logger.warning(f", Session ID: {safe(session_id, 64)}, Notification rejected: malformed request")
        return jsonify({"error": "invalid_notification_request"}), 400

    notification_id = notification_request["notification_id"]
    owner = session_manager.get_session_by_notification_id(notification_id)
    if owner is None or owner.session_id != session_id:
        logger.warning(f", Session ID: {safe(session_id, 64)}, Notification rejected: unknown notification_id")
        return jsonify({"error": "invalid_notification_id"}), 400

    logger.info(
        f", Session ID: {safe(session_id, 64)}, Notification: event={safe(notification_request.get('event'), 50)} "
        f"notification_id={safe(notification_request.get('notification_id'), 64)}"
    )
    logger.debug(
        f", Session ID: {session_id}, Notification description: "
        f"{safe(notification_request.get('event_description'))}"
    )
    return make_response("", 204)


@oidc.route("/nonce", methods=["POST"])
def nonce() -> HandlerResult:
    """OpenID4VCI nonce endpoint.

    Returns:
        ``({"c_nonce": ...}, 200)`` with ``DPoP-Nonce`` and no-store headers.
    """
    c_nonce = create_c_nonce()
    response = jsonify({"c_nonce": c_nonce})
    response.headers["Cache-Control"] = "no-store"
    response.headers["DPoP-Nonce"] = c_nonce
    return response, 200


@oidc.route("/deferred_credential", methods=["POST"])
def deferred_credential() -> HandlerResult:
    """OpenID4VCI deferred credential endpoint.

    Returns:
        ``200`` with the credential(s), ``202`` while still pending, or an
        error response.
    """
    bearer_token = _access_token()
    deferred_request = _read_credential_request("invalid_credential_request")

    deferred_transaction_id = deferred_request.get("transaction_id")
    if not isinstance(deferred_transaction_id, str):
        # OpenID4VCI 1.0 section 9.3 / 8.3.1.2: a missing required parameter.
        raise OAuthEndpointError("invalid_credential_request", description="transaction_id is required")
    try:
        uuid.UUID(deferred_transaction_id, version=4)
    except ValueError:
        # Never issued by this issuer (its transaction ids are UUIDs).
        raise OAuthEndpointError("invalid_transaction_id") from None

    logger.debug(f"Deferred credential request received, Transaction ID: {deferred_transaction_id}")

    introspection = verify_introspection(bearer_token=bearer_token)
    if not _is_introspection_success(introspection):
        return introspection
    session_id, wia_client_status = introspection

    logger.info(f", Session ID: {session_id}, Deferred Request, Transaction ID: {deferred_transaction_id}")

    current_session = session_manager.get_session(session_id=session_id)
    if current_session is None or deferred_transaction_id not in current_session.transaction_id:
        logger.warning(f", Session ID: {session_id}, Unknown deferred transaction {deferred_transaction_id}")
        raise OAuthEndpointError(
            "invalid_transaction_id", 400, "The transaction ID is not associated with this session."
        )

    validated_request = verify_credential_request(current_session.transaction_id[deferred_transaction_id], stored=True)
    require_valid_response_encryption(deferred_request)
    holder_keys = current_session.deferred_holder_keys.get(deferred_transaction_id)
    if holder_keys is None:
        logger.warning(f", Session ID: {session_id}, Deferred transaction {deferred_transaction_id} has no proven keys")
        raise OAuthEndpointError("invalid_transaction_id", 400, "The transaction has no proven holder keys.")
    response = _issue(validated_request, session_id, wia_client_status, holder_keys)

    is_deferred = response.get("error") == "Pending"
    if "error" in response and not is_deferred:
        logger.warning(
            f", Session ID: {session_id}, Deferred credential request denied: "
            f"error={safe(response.get('error'))} description={safe(response.get('error_description'))}"
        )
        # OpenID4VCI 1.0 section 8.3.1.2: only error / error_description.
        return jsonify(error_body(response["error"], response.get("error_description"))), 400

    if is_deferred:
        response = {"transaction_id": deferred_transaction_id, "interval": DEFERRED_INTERVAL_SECONDS}
    else:
        # OpenID4VCI 1.0 section 9.1: the transaction_id is invalidated once the credential is obtained.
        session_manager.remove_transaction_id(session_id, deferred_transaction_id)
        _add_notification_id(session_id, response)

    logger.info(
        f", Session ID: {session_id}, Deferred credential response: "
        f"{'still pending' if is_deferred else str(len(response.get('credentials', []))) + ' credential(s)'}"
    )

    encryption_request = (
        {**validated_request, "credential_response_encryption": deferred_request["credential_response_encryption"]}
        if "credential_response_encryption" in deferred_request
        else {}
    )
    return _finish(session_id, response, is_deferred, encryption_request)


def _offer_choice_filter(cid: str, cfg: Dict[str, Any]) -> bool:
    """Keeps credentials issuable through one of the configured auth methods.

    Args:
        cid: Configuration id.
        cfg: Configuration (unused).

    Returns:
        ``True`` if ``cid`` is in ``PID_login`` or ``country_selection``.
    """
    methods = CONFIGURATION["credential_auth_methods"]
    return cid in methods["PID_login"] or cid in methods["country_selection"]


def _unpublished_credential(frontend_id: Optional[str], credentials_id: List[str]) -> Optional[HandlerResult]:
    """Rejects credentials the offering frontend does not publish.

    A wallet resolves the offered configuration ids in the metadata of the
    frontend (the credential issuer), so it can only use ids listed there.

    Args:
        frontend_id: Offering frontend; the default frontend when falsy.
        credentials_id: Requested configuration ids.

    Returns:
        ``400`` when one is not published, else ``None``.
    """
    published = frontend_publishes(frontend_id)
    if all(published(cid) for cid in credentials_id):
        return None
    return jsonify({"error": "invalid_request", "error_description": "Unsupported credential"}), 400


@oidc.route("credential_offer_choice", methods=["GET"])
def credential_offer() -> HandlerResult:
    """Shows the credential selection page for building a credential offer.

    An unknown ``frontend_id`` gets ``404`` before the browser session is
    touched, so anonymous GETs cannot fill the server-side session store.

    Returns:
        The frontend POST-redirect page, or ``404`` for an unknown frontend.
    """
    frontend_id = request.args.get("frontend_id")
    if frontend_id is not None and frontend_id not in (CONFIGURATION["frontend"].get("frontends_config") or {}):
        logger.warning(f"credential_offer_choice: unknown frontend_id {safe(frontend_id, 64)}")
        return jsonify({"error": "unknown_frontend"}), 404
    session["frontend_id"] = frontend_id

    published = frontend_publishes(frontend_id)
    return post_redirect_with_payload(
        target_url=f"{frontend_url(frontend_id)}/display_credential_offer",
        data_payload={
            "cred": credential_display_names(lambda cid, cfg: published(cid) and _offer_choice_filter(cid, cfg)),
            "redirect_url": f"{CONFIGURATION['service_url']}/",
            "credential_offer_URI": CONFIGURATION["credential_offer_scheme"],
        },
    )


@oidc.route("/logs", methods=["GET"])
@require_admin_api_key
def get_logs_by_session() -> HandlerResult:
    """Returns the backend / authorization server log lines of a session.

    Requires the ``X-Api-Key`` header (``admin_api_key``).

    Returns:
        ``{session_id, count, successful, logs}`` or ``400``. ``successful``
        comes from the session store (a credential was issued in the live
        session), never from the log text, which request values could forge.
    """
    session_id = request.args.get("session_id")
    if not session_id:
        return jsonify({"error": "Missing required parameter: session_id"}), 400
    if not _SESSION_ID_RE.fullmatch(session_id):
        return jsonify({"error": "Invalid session_id: a session UUID is expected"}), 400
    # Whole-token match: the id must not be part of a longer word.
    session_pattern = re.compile(rf"(?<![0-9A-Za-z-]){re.escape(session_id)}(?![0-9A-Za-z-])", re.IGNORECASE)

    log_files = [CONFIGURATION["logging"]["backend_path"]]
    if "authorization_server_path" in CONFIGURATION["logging"]:
        log_files.append(CONFIGURATION["logging"]["authorization_server_path"])

    matches: List[str] = []
    seen_lines = set()
    for log_file in log_files:
        try:
            with open(log_file, "r") as f:
                for line in f:
                    if not session_pattern.search(line):
                        continue
                    stripped_line = _ANSI_ESCAPE.sub("", line).strip()
                    if stripped_line not in seen_lines:
                        seen_lines.add(stripped_line)
                        matches.append(stripped_line)
        except FileNotFoundError:
            continue

    current_session = session_manager.get_session(session_id=session_id)
    return jsonify(
        {
            "session_id": session_id,
            "count": len(matches),
            "successful": bool(current_session is not None and current_session.credential_issued is True),
            "logs": matches,
        }
    )


@oidc.route("/credential_offer2", methods=["GET"])
def credentialOffer2() -> Response:
    """Creates an authorization code credential offer and its QR code.

    Returns:
        ``{"base64_img": <png base64>, "session_id": ...}``.
    """
    session_id = generate_unique_id()
    configuration_id = request.args.get("credential_configuration_id", "eu.europa.ec.eudi.pid_mdoc")

    offer = authorization_code_offer(frontend_url(), [configuration_id], session_id)
    uri = credential_offer_uri(CONFIGURATION["credential_offer_scheme"], offer)

    logger.info(f", Session ID: {safe(session_id, 64)}, Credential offer generated for {safe(configuration_id, 100)}")
    logger.debug(f", Session ID: {safe(session_id, 64)}, Credential offer URI: {safe(uri, 1000)}")
    return jsonify({"base64_img": qr_png_base64(uri), "session_id": session_id})


@oidc.route("/credential_offer_create", methods=["GET"])
def credentialOfferCreate() -> HandlerResult:
    """Creates an authorization code credential offer.

    Returns:
        The offer, or ``400`` when ``credential_configuration_id`` is missing.
    """
    configuration_id = request.args.get("credential_configuration_id")
    if not configuration_id:
        return {
            "error": "invalid_request",
            "error_description": "Missing required parameter: credential_configuration_id",
        }, 400
    rejected = _unpublished_credential(None, [configuration_id])
    if rejected:
        return rejected
    return authorization_code_offer(frontend_url(), [configuration_id], generate_unique_id())


@oidc.route("/credential_offer", methods=["GET", "POST"])
@require_frontend_origin
def credentialOffer() -> HandlerResult:
    """Handles the credential offer form.

    Pre-authorized offers continue in :mod:`app.routes.preauth`;
    authorization code offers are rendered as a QR code here.

    Returns:
        A redirect, the frontend POST-redirect page, or ``400``.
    """
    credentials_supported = oidc_metadata["credential_configurations_supported"]
    form_keys = list(request.form.keys())

    if "proceed" not in form_keys:
        query = f"?frontend_id={session['frontend_id']}" if "frontend_id" in session else ""
        return redirect(f"{CONFIGURATION['service_url']}/credential_offer_choice{query}")

    auth_choice = request.form.get("Authorization Code Grant")
    credential_offer_URI = request.form.get("credential_offer_URI")
    offer_mode = request.form.get("credential_offer_mode")
    excluded = {"proceed", "credential_offer_URI", "Authorization Code Grant", "credential_offer_mode"}
    credentials_id = [k for k in form_keys if k not in excluded]

    if not all(credential in credentials_supported for credential in credentials_id):
        return jsonify({"error": "invalid_request", "error_description": "Unsupported credential"}), 400
    rejected = _unpublished_credential(session.get("frontend_id"), credentials_id)
    if rejected:
        return rejected

    if not is_valid_offer_prefix(credential_offer_URI):
        return jsonify({"error": "invalid_request", "error_description": "Invalid credential offer URI"}), 400

    session["credentials_id"] = credentials_id

    if auth_choice == "pre_auth_code":
        session["credential_offer_URI"] = credential_offer_URI
        session["credential_offer_mode"] = offer_mode
        # 307 keeps the POST: /preauth is POST-only (it creates a pre-authorized code).
        return redirect(url_for("preauth.preauthRed", credentials_id=json.dumps(credentials_id)), code=307)

    frontend_id = session.get("frontend_id")
    offer = authorization_code_offer(frontend_url(frontend_id), credentials_id, generate_unique_id())

    uri = offer_link(credential_offer_URI, offer, offer_mode)

    return post_redirect_with_payload(
        target_url=f"{frontend_url(frontend_id)}/display_credential_offer_qr_code",
        data_payload={
            "wallet_dev": f"{CONFIGURATION['wallet_tester_url']}/credential_offer",
            "credential_offer": offer,
            "url_data": uri,
            "qrcode": qr_data_uri(uri),
        },
    )


@oidc.route("/credential-offer-reference/<string:reference_id>", methods=["GET"])
def offer_reference(reference_id: str) -> HandlerResult:
    """Serves a credential offer by reference (``credential_offer_uri``).

    A reference is single use: a pre-authorized offer carries the
    ``pre-authorized_code``, so it is removed once served.

    Args:
        reference_id: Offer reference id.

    Returns:
        The offer (``Cache-Control: no-store``), or ``404`` when unknown,
        already fetched or expired.
    """
    entry = credential_offer_references.pop(reference_id, None)
    if entry is None or entry["expires"] < datetime.now():
        return jsonify({"error": "not_found"}), 404
    response = jsonify(entry["credential_offer"])
    response.headers["Cache-Control"] = "no-store"
    return response


oidc.register_error_handler(OAuthEndpointError, oauth_error_response)


@oidc.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e: werkzeug.exceptions.BadRequest) -> Tuple[str, int]:
    """Blueprint handler for ``400 Bad Request``.

    Args:
        e: The exception.

    Returns:
        ``("bad request!", 400)``.
    """
    return "bad request!", 400
