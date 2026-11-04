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
"""``/dynamic`` blueprint: country selection, user attribute collection and
the internal credential creation endpoint.

The Dynamic Issuer Web service is a component of the Dynamic Provider
backend. Its main goal is to issue credentials in cbor/mdoc (ISO 18013-5
mdoc) and SD-JWT format.
"""

from __future__ import annotations

import hmac
import logging
import secrets
from http import HTTPStatus
from typing import Any, Dict, Iterable, Set, Tuple, Union
from uuid import uuid4

from flask import Blueprint, Response, abort, redirect, request, session

from app.core.config import CONFIGURATION, feature_enabled
from app.core.security import require_frontend_origin
from app.core.constants import IMAGE_ATTRIBUTES, ConfService as cfgserv
from app.core.log_utils import safe
from app.core.state import session_manager
from app.repositories.session_store import Session
from app.services.attributes import getAttributesForm, getAttributesForm2, optional_only
from app.services.countries import (
    collect_user_data,
    country_config,
    exchange_authorization_code,
    generate_connector_authorization_url,
    is_form_country,
    openid_authorization_url,
)
from app.services.presentation import (
    InvalidFormError,
    form_formatter,
    presentation_formatter,
    verified_form_formatter,
)
from app.utils.forms import parse_form
from app.utils.frontend import frontend_url
from app.utils.http import post_redirect_with_payload, url_get
from app.utils.validation import validate_mandatory_args

dynamic = Blueprint("dynamic", __name__, url_prefix="/dynamic")

logger = logging.getLogger(__name__)

AGE_VERIFICATION_PASSPORT = "eu.europa.ec.eudi.age_verification_mdoc_passport"

HandlerResult = Union[Response, str, Tuple[Any, int]]


def _current_session() -> Tuple[str, Session]:
    """Returns the issuance session bound to the browser session.

    Returns:
        ``(session_id, session)``.

    Raises:
        werkzeug.exceptions.BadRequest: When the browser has no issuance
            session (never started, expired, or already handed to the wallet).
    """
    session_id = session.get("session_id")
    current_session = session_manager.get_session(session_id=session_id) if session_id else None
    if current_session is None:
        logger.warning("Request without an active issuance session in this browser")
        abort(400, description="No active issuance session: it expired or was already completed. Start again from the wallet.")
    return session_id, current_session


def _redirect_to_user_verification(session_id: str, jws_token: str) -> Response:
    """Redirects back to the authorization server's user verification endpoint.

    Args:
        session_id: Issuance session (sent as ``username``).
        jws_token: Session JWS token.

    Returns:
        The redirect response.
    """
    return redirect(
        url_get(
            CONFIGURATION["authorization_server"]["user_verify_endpoint"],
            {"token": jws_token, "username": session_id},
        )
    )


def _display_authorization(current_session: Session, presentation_data: Dict[str, Any]) -> str:
    """Shows the consent page before redirecting back to the wallet flow.

    Args:
        current_session: Issuance session.
        presentation_data: See :func:`presentation_formatter`.

    Returns:
        The frontend POST-redirect page.
    """
    return post_redirect_with_payload(
        target_url=f"{frontend_url(current_session.frontend_id)}/display_authorization",
        data_payload={
            "presentation_data": presentation_data,
            "image_attributes": list(IMAGE_ATTRIBUTES),
            "redirect_url": f"{CONFIGURATION['service_url']}/dynamic/redirect_wallet",
            "session_id": current_session.session_id,
        },
    )


def _selectable_countries(current_session: Session) -> Dict[str, str]:
    """Lists the countries the user may choose for this session.

    A country must support every requested credential. Form countries, where
    the user types the attributes, are only offered when the
    ``form_countries`` test feature is on.

    Args:
        current_session: Issuance session.

    Returns:
        Country code -> display name.
    """
    allow_forms = feature_enabled("form_countries")
    return {
        str(country): str(config["name"])
        for country, config in CONFIGURATION["countries"].items()
        if all(c in config["supported_credential_ids"] for c in current_session.credentials_requested)
        and (allow_forms or not is_form_country(country))
    }


def _form_attribute_names(credentials_requested: Iterable[str]) -> Set[str]:
    """Lists the attributes the form for the requested credentials shows.

    Args:
        credentials_requested: Credential configuration ids.

    Returns:
        The mandatory and optional attribute names.
    """
    return set(getAttributesForm(credentials_requested)) | set(getAttributesForm2(credentials_requested))


@dynamic.route("/", methods=["GET", "POST"])
@require_frontend_origin
def Supported_Countries() -> HandlerResult:
    """Initial page: lets the user choose the country that authenticates them.

    Passport age verification skips the choice; a single eligible country
    is selected automatically.

    Returns:
        A redirect or the country selection page.
    """
    session_id, current_session = _current_session()

    if AGE_VERIFICATION_PASSPORT in current_session.credentials_requested and feature_enabled(
        "passport_age_verification"
    ):
        session_manager.update_user_data(session_id=session_id, user_data={"age_over_18": True})
        session_manager.update_country(session_id=session_id, country="AV")
        return _redirect_to_user_verification(session_id, current_session.jws_token)

    display_countries = _selectable_countries(current_session)

    if len(display_countries) == 1:
        country = next(iter(display_countries))
        logger.info(f", Session ID: {session_id}, Authorization selection, Type: {safe(country, 20)}")
        return dynamic_R1(country)

    return post_redirect_with_payload(
        target_url=f"{frontend_url(current_session.frontend_id)}/display_countries",
        data_payload={
            "countries": display_countries,
            "authorization_details": current_session.authorization_details,
            "redirect_url": f"{CONFIGURATION['service_url']}/",
            "session_id": session_id,
        },
    )


@dynamic.route("/country_selected", methods=["GET", "POST"])
@require_frontend_origin
def country_selected() -> HandlerResult:
    """Handles the country chosen on the selection page.

    Returns:
        See :func:`dynamic_R1`.
    """
    _, current_session = _current_session()
    form_country = request.form.get("country")
    if form_country not in _selectable_countries(current_session):
        logger.warning(f", Session ID: {safe(current_session.session_id, 64)}, Country not selectable: {safe(form_country, 20)}")
        return "Country not supported", HTTPStatus.BAD_REQUEST
    logger.info(f", Session ID: {current_session.session_id}, Authorization selection, Type: {safe(form_country, 20)}")
    return dynamic_R1(form_country)


def dynamic_R1(country: str) -> HandlerResult:
    """Sends the user to the attribute form or the country identity provider.

    Args:
        country: Selected country.

    Returns:
        The form page (form countries) or a redirect to the IdP.
    """
    session_id = session["session_id"]
    session_manager.update_country(session_id=session_id, country=country)
    current_session = session_manager.get_session(session_id=session_id)

    if is_form_country(country):
        mandatory_attributes = getAttributesForm(current_session.credentials_requested)
        if "user_pseudonym" in mandatory_attributes:
            mandatory_attributes["user_pseudonym"] = {"type": "string", "filled_value": str(uuid4())}

        optional_attributes = optional_only(
            getAttributesForm2(current_session.credentials_requested), mandatory_attributes
        )
        return post_redirect_with_payload(
            target_url=f"{frontend_url(current_session.frontend_id)}/display_form",
            data_payload={
                "mandatory_attributes": mandatory_attributes,
                "optional_attributes": optional_attributes,
                "redirect_url": f"{CONFIGURATION['service_url']}/dynamic/form",
                "session_id": session_id,
            },
        )

    match country_config(country)["connection_type"]:
        case "oauth":
            state = secrets.token_urlsafe(32)
            session["oauth_state"] = state
            return redirect(
                generate_connector_authorization_url(
                    oauth_data=country_config(country)["auth"],
                    country=country,
                    credentials_requested=current_session.credentials_requested,
                    state=state,
                )
            )
        case "openid":
            state = secrets.token_urlsafe(32)
            session["oauth_state"] = state
            return redirect(openid_authorization_url(country, state=state))
        case other:
            return f"Unsupported connection type: {other}", HTTPStatus.BAD_REQUEST


@dynamic.route("/redirect", methods=["GET", "POST"])
def red() -> HandlerResult:
    """Receives the authorization code from a country identity provider.

    GET parameters:
        code (mandatory): Authorization code to retrieve the attributes
            consented by the user.
        state (mandatory): The ``state`` sent with the authorization request.

    Returns:
        The consent page.

    Raises:
        ValueError: If ``code`` is missing or the IdP exchange fails.
    """
    session_id, current_session = _current_session()

    valid, missing = validate_mandatory_args(request.args, ["code"])
    if not valid:
        raise ValueError(f"Missing mandatory IdP fields: {missing}")

    # The state binds the IdP response to the authorization request this
    # browser started; it is single use.
    expected_state = session.pop("oauth_state", None)
    received_state = request.args.get("state") or ""
    if not expected_state or not hmac.compare_digest(received_state.encode(), expected_state.encode()):
        logger.warning(f", Session ID: {session_id}, IdP redirect rejected: state mismatch")
        return "Invalid state", HTTPStatus.BAD_REQUEST

    access_token = exchange_authorization_code(current_session.country, request.args.get("code"))
    session["access_token"] = access_token
    logger.info(f", Session ID: {session_id}, Country IdP authentication completed ({current_session.country})")

    data = collect_user_data(country=current_session.country, session_id=session_id, access_token=access_token)

    presentation_data = presentation_formatter(
        cleaned_data=data,
        credentials_requested=current_session.credentials_requested,
        country=current_session.country,
        include_optional=False,
    )
    return _display_authorization(current_session, presentation_data)


@dynamic.route("/auth_method", methods=["GET", "POST"])
@require_frontend_origin
def auth() -> HandlerResult:
    """Handles the authentication method chosen by the user.

    Returns:
        A redirect to PID login (``link1``) or country selection (``link2``).

    Raises:
        ValueError: If the user cancelled.
    """
    session_id = session["session_id"]
    if "Cancelled" in request.form.keys():
        raise ValueError(f"User canceled authentication. Session ID: {session_id}")

    match request.form.get("optionsRadios"):
        case "link1":
            return redirect(f"{CONFIGURATION['service_url']}/oid4vp")
        case "link2":
            return redirect(f"{CONFIGURATION['service_url']}/dynamic/")
        case _:
            return "Invalid authentication method", HTTPStatus.BAD_REQUEST


@dynamic.route("/form", methods=["GET", "POST"])
@require_frontend_origin
def Dynamic_form() -> HandlerResult:
    """Receives the attribute form filled in by the user.

    Returns:
        The consent page, or ``400`` for a GET (the form is only POSTed).
    """
    session_id, current_session = _current_session()

    if request.method == "GET":
        # The form is only ever POSTed by the frontend.
        return "Error 101: " + cfgserv.error_list["101"] + "\n", HTTPStatus.BAD_REQUEST

    if not is_form_country(current_session.country) or not (
        feature_enabled("form_countries") or current_session.verified_attributes
    ):
        logger.warning(f", Session ID: {session_id}, Attribute form not allowed for this session")
        return "Attribute form not allowed", HTTPStatus.FORBIDDEN

    form_data = parse_form(request.form)
    form_data.pop("proceed", None)
    logger.info(f", Session ID: {session_id}, Attribute form submitted")
    logger.debug(f", Session ID: {session_id}, Form fields: {safe(sorted(form_data), 500)}")

    try:
        if current_session.verified_attributes:
            # The verified PID values come from the session, never from the
            # form; the form only adds the other attributes it shows.
            cleaned_data = verified_form_formatter(
                form_data,
                verified=current_session.verified_attributes,
                allowed=_form_attribute_names(current_session.credentials_requested),
                issuing_country=current_session.country,
            )
        else:
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
    return _display_authorization(current_session, presentation_data)


@dynamic.route("/redirect_wallet", methods=["GET", "POST"])
@require_frontend_origin
def redirect_wallet() -> Response:
    """Returns the user to the authorization server after consent.

    Returns:
        The redirect response.
    """
    session_id, current_session = _current_session()
    # The browser part of the flow ends here: a copied session cookie must
    # not reopen the attribute form or the consent page.
    session.clear()
    return _redirect_to_user_verification(session_id, current_session.jws_token)
