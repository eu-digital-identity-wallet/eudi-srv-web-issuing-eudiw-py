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
"""Turns collected form data into signed credentials.

:func:`dynamic_formatter` takes the attributes collected for one credential
configuration, splits them into mandatory / optional / issuer-filled claims,
fills in dates and other issuer-controlled claims, and delegates signing to
:mod:`app.services.formatters`.
"""

from __future__ import annotations

import datetime
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.core.config import CONFIGURATION
from app.core.state import oidc_metadata, session_manager
from app.services.attributes import (
    getIssuerFilledAttributes,
    getIssuerFilledAttributesSDJWT,
    getMandatoryAttributes,
    getMandatoryAttributesSDJWT,
    getNamespaces,
    getOptionalAttributes,
    getOptionalAttributesSDJWT,
)
from app.services.countries import issuing_country_code
from app.services.formatters import mdocFormatter, sdjwtFormatter
from app.utils.dates import calculate_age, format_date

#: Scopes for which the UN distinguishing sign of the country is added.
MDL_SCOPES = ("eu.europa.ec.eudi.mdl_mdoc", "eu.europa.ec.eudi.aamva_mdl_mdoc")
#: Claims submitted as JSON strings / single-element lists that must be unwrapped.
JSON_OBJECT_FIELDS = (
    "places_of_work",
    "legislation",
    "employment_details",
    "competent_institution",
    "credential_holder",
    "subject",
    "residence_address",
)


def dynamic_formatter(
    format: str,
    scope: str,
    form_data: Dict[str, Any],
    device_publickey: str,
    session_id: str,
) -> str:
    """Formats and signs one credential from the user's form data.

    Args:
        format: ``"mso_mdoc"`` or ``"dc+sd-jwt"``.
        scope: Credential configuration id.
        form_data: Attributes collected for the user.
        device_publickey: Holder device public key (PEM, base64url).
        session_id: Issuance session id.

    Returns:
        The encoded credential.

    Raises:
        ValueError: If ``format`` is not supported.
    """
    current_session = session_manager.get_session(session_id=session_id)

    un_distinguishing_sign = (
        CONFIGURATION["countries"][current_session.country]["un_distinguishing_sign"]
        if scope in MDL_SCOPES
        else ""
    )

    data, requested_credential = formatter(dict(form_data), un_distinguishing_sign, scope, format)

    match format:
        case "mso_mdoc":
            return mdocFormatter(
                data=data,
                credential_metadata=requested_credential,
                country=current_session.country,
                device_publickey=device_publickey,
                session_id=session_id,
            )
        case "dc+sd-jwt":
            return sdjwtFormatter(
                PID={
                    "credential_metadata": requested_credential,
                    "data": data,
                    "device_publickey": device_publickey,
                },
                country=current_session.country,
                scope=scope,
                session_id=session_id,
            )
        case _:
            raise ValueError(f"Unsupported credential format: {format}")


def formatter(
    data: Dict[str, Any], un_distinguishing_sign: str, scope: str, format: str
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Builds the credential payload from flat form data.

    Args:
        data: Flat attribute dict (mutated).
        un_distinguishing_sign: Country UN distinguishing sign (mDL only).
        scope: Credential configuration id.
        format: ``"mso_mdoc"`` or ``"dc+sd-jwt"``.

    Returns:
        ``(payload, credential_configuration)``. For mdoc the payload is
        ``{namespace: {attr: value}}``; for SD-JWT it is
        ``{"evidence": [...], "claims": {...}}``.
    """
    today = datetime.date.today()

    requested_credential, pdata = get_requested_credential(data, scope, format, today)
    doctype_config = requested_credential["issuer_config"]
    expiry = today + datetime.timedelta(days=doctype_config["validity"])
    claims = requested_credential["credential_metadata"]["claims"]

    namespaces: Optional[List[str]] = None
    attributes_by_namespace: Optional[Dict[str, Dict[str, Dict[str, Any]]]] = None

    if format == "mso_mdoc":
        namespaces = getNamespaces(claims)
        attributes_by_namespace = {
            ns: {
                "mandatory": getMandatoryAttributes(claims, ns),
                "optional": getOptionalAttributes(claims, ns),
                "issuer": getIssuerFilledAttributes(claims, ns),
            }
            for ns in namespaces
        }
        attributes_req: Dict[str, Any] = {}
        attributes_req2: Dict[str, Any] = {}
        issuer_claims: Dict[str, Any] = {}
        for groups in attributes_by_namespace.values():
            attributes_req.update(groups["mandatory"])
            attributes_req2.update(groups["optional"])
            issuer_claims.update(groups["issuer"])
    else:  # "dc+sd-jwt"
        attributes_req = getMandatoryAttributesSDJWT(claims)
        attributes_req2 = getOptionalAttributesSDJWT(claims)
        issuer_claims = getIssuerFilledAttributesSDJWT(claims)

    update_dates_and_special_claims(
        data, issuer_claims, un_distinguishing_sign, today, expiry, requested_credential, doctype_config
    )
    normalize_list_and_type_fields(data, attributes_req, attributes_req2, requested_credential.get("scope"))
    populate_pdata(
        data,
        pdata,
        format,
        namespaces,
        attributes_req,
        attributes_req2,
        issuer_claims,
        attributes_by_namespace=attributes_by_namespace,
    )
    return pdata, requested_credential


def get_requested_credential(
    data: Dict[str, Any], scope: str, format: str, today: datetime.date
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Looks up the credential configuration and creates the empty payload.

    Args:
        data: Form data (``issuing_country`` is read for SD-JWT evidence).
        scope: Credential configuration id.
        format: Credential format.
        today: Issuance date (unused, kept for API compatibility).

    Returns:
        ``(credential_configuration, empty_payload)``.
    """
    cred = oidc_metadata["credential_configurations_supported"][scope]
    if format == "mso_mdoc":
        return cred, {}

    doctype_config = cred["issuer_config"]
    pdata = {
        "evidence": [
            {
                "type": cred["vct"],
                "source": {
                    "organization_name": doctype_config["organization_name"],
                    "organization_id": doctype_config["organization_id"],
                    "country_code": data["issuing_country"],
                },
            }
        ],
        "claims": {},
    }
    return cred, pdata


def update_dates_and_special_claims(
    data: Dict[str, Any],
    issuer_claims: Dict[str, Any],
    un_distinguishing_sign: str,
    today: datetime.date,
    expiry: datetime.date,
    requested_credential: Dict[str, Any],
    doctype_config: Dict[str, Any],
) -> None:
    """Fills issuer-controlled claims (age, dates, issuing authority, ...).

    Args:
        data: Form data (mutated).
        issuer_claims: Issuer-filled attribute names.
        un_distinguishing_sign: Country UN distinguishing sign.
        today: Issuance date.
        expiry: Expiry date.
        requested_credential: Credential configuration.
        doctype_config: ``issuer_config`` of the credential.
    """
    if "age_over_18" in issuer_claims and "birth_date" in data:
        data["age_over_18"] = calculate_age(data["birth_date"]) >= 18

    if "un_distinguishing_sign" in issuer_claims:
        data["un_distinguishing_sign"] = un_distinguishing_sign

    date_fields = {
        "issuance_date": today,
        "date_of_issuance": today,
        "issue_date": today,
        "expiry_date": expiry,
        "date_of_expiry": expiry,
    }
    data.update({f: format_date(v) for f, v in date_fields.items() if f in issuer_claims})

    if "issuing_authority" in issuer_claims:
        if requested_credential.get("scope") == "eu.europa.ec.eudi.ehic_sd_jwt_vc":
            data["issuing_authority"] = {
                "id": doctype_config["issuing_authority_id"],
                "name": doctype_config["issuing_authority"],
            }
        else:
            data["issuing_authority"] = doctype_config["issuing_authority"]

    if "issuing_authority_unicode" in issuer_claims:
        data["issuing_authority_unicode"] = doctype_config["issuing_authority"]

    if "credential_type" in issuer_claims:
        data["credential_type"] = doctype_config["credential_type"]


def _unwrap_json_object(value: Any) -> Any:
    """Parses a JSON string and unwraps single-object lists.

    Args:
        value: Submitted value.

    Returns:
        The decoded first object (or the value unchanged).
    """
    if isinstance(value, str):
        value = json.loads(value)
    if isinstance(value, list):
        value = value[0]
    return value


def normalize_list_and_type_fields(
    data: Dict[str, Any],
    attributes_req: Dict[str, Any],
    attributes_req2: Dict[str, Any],
    scope: Optional[str] = None,
) -> None:
    """Normalizes JSON-object fields and numeric strings in the form data.

    Args:
        data: Form data (mutated).
        attributes_req: Mandatory attributes.
        attributes_req2: Optional attributes.
        scope: Credential configuration id (PID SD-JWT also unwraps ``address``).
    """
    list_fields: List[str] = list(JSON_OBJECT_FIELDS)
    if scope == "eu.europa.ec.eudi.pid_vc_sd_jwt":
        list_fields.append("address")

    groups = (attributes_req, attributes_req2)
    for field in (f for f in list_fields if f in data):
        # Applied once per attribute group the field belongs to.
        for _ in range(sum(field in group for group in groups)):
            data[field] = _unwrap_json_object(data[field])

    _coerce_numeric_fields(data)


def _coerce_numeric_fields(data: Dict[str, Any]) -> None:
    """Converts the numeric form fields submitted as text to integers.

    Args:
        data: Form data (mutated).
    """
    for field in ("age_in_years", "age_birth_year"):
        if isinstance(data.get(field), str):
            data[field] = int(data[field])
    # PID Rulebook: sex is a uint (mdoc) / JSON number (SD-JWT VC).
    for field in ("gender", "sex"):
        if isinstance(data.get(field), str) and data[field].isdigit():
            data[field] = int(data[field])


def populate_pdata(
    data: Dict[str, Any],
    pdata: Dict[str, Any],
    format: str,
    namescapes: Optional[Iterable[str]],
    attributes_req: Dict[str, Any],
    attributes_req2: Dict[str, Any],
    issuer_claims: Dict[str, Any],
    attributes_by_namespace: Optional[Dict[str, Dict[str, Dict[str, Any]]]] = None,
) -> None:
    """Copies the known attributes from ``data`` into the credential payload.

    Args:
        data: Normalized form data.
        pdata: Payload being built (mutated).
        format: Credential format.
        namescapes: mdoc namespaces (mdoc only).
        attributes_req: Mandatory attributes.
        attributes_req2: Optional attributes.
        issuer_claims: Issuer-filled attributes.
        attributes_by_namespace: Per-namespace attribute groups (mdoc only).
    """
    if format == "mso_mdoc":
        for namespace in namescapes:
            groups = attributes_by_namespace[namespace]
            pdata[namespace] = {
                attr: data[attr]
                for group in (groups["mandatory"], groups["optional"], groups["issuer"])
                for attr in group
                if attr in data
            }
    else:  # "dc+sd-jwt"
        pdata["claims"].update(
            {
                attr: data[attr]
                for group in (attributes_req, attributes_req2, issuer_claims)
                for attr in group
                if attr in data
            }
        )


def _supports_country(country: str) -> bool:
    """Tells whether credentials can be created for ``country``.

    Args:
        country: Country code.

    Returns:
        ``True`` for form countries, ``sample``, and OAuth / OpenID connectors.
    """
    if country in ("FC", "AV", "AV2", "sample"):
        return True
    return CONFIGURATION["countries"].get(country, {}).get("connection_type") in ("oauth", "openid")


def credentialCreation(
    credential_request: Dict[str, Any], data: Dict[str, Any], country: str, session_id: str
) -> Dict[str, Any]:
    """Creates one credential per holder key in the formatter request.

    Args:
        credential_request: ``{"credential_configuration_id" | "credential_identifier",
            "proofs": [{"jwt" | "attestation": device_key}]}``.
        data: User attributes.
        country: Issuing country.
        session_id: Issuance session.

    Returns:
        ``{"credentials": [{"credential": ...}]}`` or an
        ``invalid_credential_request`` error dict.
    """
    credentials_supported = oidc_metadata["credential_configurations_supported"]
    invalid = {"error": "invalid_credential_request", "error_description": "invalid request"}

    if "credential_identifier" in credential_request:
        config = credentials_supported[credential_request["credential_identifier"]]
        scope, format = config["scope"], config["format"]
    elif "credential_configuration_id" in credential_request:
        scope = credential_request["credential_configuration_id"]
        format = credentials_supported[scope]["format"]
    else:
        return invalid

    if not _supports_country(country):
        return invalid

    credential_response: Dict[str, Any] = {"credentials": []}
    for proof in credential_request["proofs"]:
        device_publickey = proof.get("attestation", proof.get("jwt"))
        form_data = {**data, "issuing_country": issuing_country_code(country)}
        credential_response["credentials"].append(
            {"credential": dynamic_formatter(format, scope, form_data, device_publickey, session_id)}
        )
    return credential_response


def issue_credentials_for_session(session_id: str, credential_request: Dict[str, Any]) -> Dict[str, Any]:
    """Creates the credentials for a validated request with the session's user data.

    Args:
        session_id: Issuance session (holds the user data and country).
        credential_request: Formatter request (configuration id + ``proofs``
            holding the holder keys).

    Returns:
        ``{"credentials": [...]}``, or an ``invalid_credential_request``
        error dict when the session is unknown / expired or the request is
        invalid.
    """
    current_session = session_manager.get_session(session_id=session_id)
    if current_session is None:
        return {"error": "invalid_credential_request", "error_description": "Unknown or expired session"}

    return credentialCreation(
        credential_request=credential_request,
        data=current_session.user_data,
        country=current_session.country,
        session_id=session_id,
    )
