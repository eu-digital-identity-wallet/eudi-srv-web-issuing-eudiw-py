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
"""Credential formatters: build and sign mdoc (ISO 18013-5) and SD-JWT VC credentials.

The PID Issuer Web service is a component of the PID Provider backend. Its
main goal is to issue the PID and MDL in cbor/mdoc (ISO 18013-5 mdoc) and
SD-JWT format.

Both formatters sign with the issuing country's ``_default`` key, reserve a
status list entry when revocation is enabled, and cap the credential expiry
at the WIA / key attestation ceiling stored in the session
(:attr:`Session.max_credential_exp`, TS3 2.4.3).
"""

from __future__ import annotations

import base64
import copy
import datetime
import logging
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

import cbor2
import jwt
from jwcrypto.jwk import JWK
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pymdoccbor.mdoc.issuer import MdocCborIssuer
from sd_jwt.common import SDObj
from sd_jwt.issuer import SDJWTIssuer

from app.core.config import CONFIGURATION
from app.core.constants import IMAGE_ATTRIBUTES
from app.core.state import session_manager
from app.repositories.status_store import record_issued_status
from app.services.revocation_status import reserve_status_entry
from app.utils.crypto import ec_coordinates, ec_public_jwk, jwk_curve, private_value_bytes
from app.utils.dates import date_to_timestamp, format_date
from app.utils.encoding import b64url_decode, urlsafe_b64encode_nopad
from app.utils.frontend import frontend_url

logger = logging.getLogger(__name__)

#: mdoc elements whose value is a CBOR tagged date.
MDOC_DATE_ELEMENTS = ("birth_date", "expiry_date", "issuance_date", "issue_date")
#: Countries for which no status list entry is reserved (mdoc).
NO_REVOCATION_COUNTRIES = ("AV", "AV2")
LEARNING_CREDENTIAL_SCOPE = "eu.europa.ec.eudi.learning_credential_vc_sd_jwt"


def _country_key_entry(country: str) -> Dict[str, Any]:
    """Returns the ``_default`` key entry of a country.

    Args:
        country: Country code.

    Returns:
        ``CONFIGURATION["countries"][country]["keys"]["_default"]``.

    Raises:
        KeyError: If the country is not configured.
    """
    return CONFIGURATION["countries"][country]["keys"]["_default"]


def load_country_signing_key(country: str) -> ec.EllipticCurvePrivateKey:
    """Loads the private signing key of a country.

    Args:
        country: Country code.

    Returns:
        The private key.

    Raises:
        KeyError: If the country is not configured.
        ValueError: If the key cannot be decrypted / parsed.
    """
    entry = _country_key_entry(country)
    return serialization.load_pem_private_key(
        entry["private_key"], password=entry["private_key_password"]
    )


def _mdoc_validity(validity_days: int, current_session: Any, session_id: Optional[str]) -> Dict[str, datetime.datetime]:
    """Computes the issuance and expiry dates of an mdoc.

    Batch credentials are issued at midnight, and the expiry is clamped to
    the WIA / key attestation ceiling.

    Args:
        validity_days: Configured validity.
        current_session: Issuance session, or ``None``.
        session_id: Issuance session id (for logging).

    Returns:
        ``{"issuance_date", "expiry_date"}``.
    """
    issuance_date = datetime.datetime.now(datetime.timezone.utc)
    if current_session and current_session.is_batch_credential:
        issuance_date = issuance_date.replace(hour=0, minute=0, second=0)

    expiry_date = issuance_date + datetime.timedelta(days=validity_days)

    if current_session and current_session.max_credential_exp is not None:
        max_expiry_date = datetime.datetime.fromtimestamp(
            current_session.max_credential_exp, tz=datetime.timezone.utc
        )
        if expiry_date >= max_expiry_date:
            logger.debug(
                f", Session ID: {session_id}, clamping mdoc expiry from "
                f"{expiry_date.isoformat()} to WIA/KA ceiling {max_expiry_date.isoformat()}"
            )
            expiry_date = max_expiry_date.replace(tzinfo=None)

    return {"issuance_date": issuance_date, "expiry_date": expiry_date}


def mdocFormatter(
    data: Dict[str, Any],
    credential_metadata: Dict[str, Any],
    country: str,
    device_publickey: str,
    session_id: Optional[str],
) -> str:
    """Constructs and signs an mdoc with the country private key.

    Note:
        The signing key comes from ``country``, while the certificate and
        status list reservation use the *session* country when a session
        exists.

    Args:
        data: Doctype data, ``{namespace: {element: value}}``.
        credential_metadata: Credential configuration.
        country: Issuing country (selects the signing key).
        device_publickey: Holder device public key (PEM, base64url).
        session_id: Issuance session id, or ``None`` outside an issuance flow.

    Returns:
        The base64url (unpadded) encoded mdoc.
    """
    current_session = session_manager.get_session(session_id=session_id) if session_id else None
    private_key = load_country_signing_key(country)

    validity = _mdoc_validity(credential_metadata["issuer_config"]["validity"], current_session, session_id)

    namespace = credential_metadata["issuer_config"]["namespace"]
    namespace_data = data[namespace]
    for element in IMAGE_ATTRIBUTES:
        if element in namespace_data:
            namespace_data[element] = base64.urlsafe_b64decode(namespace_data[element])
    if "user_pseudonym" in namespace_data:
        namespace_data["user_pseudonym"] = namespace_data["user_pseudonym"].encode("utf-8")

    cose_pkey = {
        "KTY": "EC2",
        "CURVE": "P_256",
        "ALG": "ES256",
        "D": private_value_bytes(private_key),
        "KID": b"mdocIssuer",
    }
    mdoci = MdocCborIssuer(private_key=cose_pkey, alg="ES256")

    if current_session is not None:
        country = current_session.country
    revocation_json = None
    if CONFIGURATION["revocation"]["enabled"] and country not in NO_REVOCATION_COUNTRIES:
        revocation_json = reserve_status_entry(
            credential_metadata["doctype"], country, format_date(validity["expiry_date"])
        )
        if revocation_json is not None:
            session_manager.update_key_status_by_key(
                session_id=session_id,
                key=device_publickey,
                key_status=copy.deepcopy(revocation_json),
            )
            record_issued_status(session_id, credential_metadata["doctype"], revocation_json)
            revocation_json["identifier_list"]["id"] = revocation_json["identifier_list"]["id"].encode("utf-8")

    mdoci.new(
        doctype=credential_metadata["doctype"],
        data=data,
        validity=validity,
        devicekeyinfo=device_publickey,
        cert_path=_country_key_entry(country)["certificate_path"],
        revocation=revocation_json,
    )
    logger.debug(
        f", Session ID: {session_id}, Signed mdoc {credential_metadata['doctype']} "
        f"(country={country}, expires={validity['expiry_date'].isoformat()}, status_list={revocation_json is not None})"
    )
    return urlsafe_b64encode_nopad(mdoci.dump())


def _date_element_value(value: Any) -> Any:
    """Normalizes an mdoc date element to its ``YYYY-MM-DD`` text form.

    cbor2 < 5.5 returns full-date (tag 1004) values as :class:`cbor2.CBORTag`;
    newer releases decode them to :class:`datetime.date`.

    Args:
        value: Decoded ``elementValue``.

    Returns:
        The date as text (or ``value`` unchanged if it is neither form).
    """
    if isinstance(value, cbor2.CBORTag):
        return value.value
    if isinstance(value, (datetime.date, datetime.datetime)):
        return value.isoformat()
    return value


def cbor2elems(mdoc: str) -> Dict[str, List[Tuple[str, Any]]]:
    """Lists the ``(element, value)`` pairs of each namespace of an mdoc.

    Args:
        mdoc: Base64url encoded mdoc ``DeviceResponse``.

    Returns:
        E.g. ``{'ns1': [('e1', 'v1'), ('e2', 'v2')], 'ns2': [('e3', 'v3')]}``.
        Tagged date values are unwrapped.
    """
    namespaces = cbor2.loads(base64.urlsafe_b64decode(mdoc))["documents"][0]["issuerSigned"][
        "nameSpaces"
    ]
    result: Dict[str, List[Tuple[str, Any]]] = {}
    for namespace, elements in namespaces.items():
        items = []
        for tagged in elements:
            item = cbor2.loads(tagged.value)
            identifier = item["elementIdentifier"]
            value = item["elementValue"]
            items.append((identifier, _date_element_value(value) if identifier in MDOC_DATE_ELEMENTS else value))
        result[namespace] = items
    return result


def _disclosable_list(value: List[Any]) -> List[Any]:
    """Makes the keys of dict elements of a list selectively disclosable.

    Args:
        value: Claim value list.

    Returns:
        The list with each dict element's keys wrapped in :class:`SDObj`.
    """
    return [
        {SDObj(value=attribute): v for attribute, v in element.items()} if isinstance(element, dict) else element
        for element in value
    ]


def sdjwtNestedClaims(claims: Dict[str, Any], credential_metadata: Dict[str, Any]) -> Dict[Any, Any]:
    """Wraps credential claims in :class:`SDObj` for selective disclosure.

    Claims flagged ``selective_disclosure: false`` in the credential
    metadata are kept as plain claims. Nested dicts / lists of dicts get
    selectively disclosable members; each nationality is disclosable on
    its own.

    Args:
        claims: ``{claim_name: value}``.
        credential_metadata: Credential configuration.

    Returns:
        The claims dict ready for :class:`SDJWTIssuer`.
    """
    sd_map = {
        claim_meta["path"][-1]: claim_meta.get("selective_disclosure", True)
        for claim_meta in credential_metadata.get("credential_metadata", {}).get("claims", [])
        if "overall_issuer_conditions" not in claim_meta
    }

    nested: Dict[Any, Any] = {}
    for claim, value in claims.items():
        if not sd_map.get(claim, True):
            nested[claim] = value
        elif isinstance(value, list) and claim == "nationalities":
            nested[SDObj(value=claim)] = [SDObj(value=nationality) for nationality in value]
        elif isinstance(value, list) and value:
            nested[SDObj(value=claim)] = _disclosable_list(value)
        elif isinstance(value, dict):
            nested[SDObj(value=claim)] = {SDObj(value=attribute): v for attribute, v in value.items()}
        else:
            nested[SDObj(value=claim)] = value
    return nested


def picture_data_url(claims: Dict[str, Any]) -> Dict[str, Any]:
    """Encodes the ``picture`` claim as a JPEG data URL.

    The PID Rulebook (section 4.1) requires the SD-JWT VC ``picture`` to be a
    data URL with the base64-encoded JPEG; the form holds it as base64url.

    Args:
        claims: ``{claim_name: value}``.

    Returns:
        A copy of ``claims`` with ``picture`` as a data URL (``claims`` itself
        when there is no picture or it already is a data URL).
    """
    picture = claims.get("picture")
    if not isinstance(picture, str) or picture.startswith("data:"):
        return claims
    encoded = base64.b64encode(b64url_decode(picture)).decode("ascii")
    return {**claims, "picture": "data:image/jpeg;base64," + encoded}


def credential_issuer_url(current_session: Any) -> str:
    """Returns the Credential Issuer Identifier used as the SD-JWT VC ``iss``.

    Wallets know the issuer by its frontend URL (the ``credential_issuer`` of
    the metadata they fetch), and the x5c certificate SAN names that host,
    not the backend ``service_url``. The frontend of the session is used when
    it is configured, else the default frontend.

    The signing certificate is chosen per country, not per frontend, so the
    SAN only matches for frontends whose host the certificate names.

    Args:
        current_session: Issuance session, or ``None``.

    Returns:
        The frontend base URL.
    """
    frontend_id = getattr(current_session, "frontend_id", None)
    if frontend_id not in (CONFIGURATION["frontend"].get("frontends_config") or {}):
        frontend_id = None
    return frontend_url(frontend_id)


def sdjwtFormatter(PID: Dict[str, Any], country: str, scope: Optional[str], session_id: Optional[str]) -> str:
    """Constructs an SD-JWT VC signed with the country private key.

    Args:
        PID: ``{"data": {"claims": ...}, "credential_metadata": ...,
            "device_publickey": ...}``.
        country: Issuing country.
        scope: Credential scope (learning credentials get a ``jti``).
        session_id: Issuance session id.

    Returns:
        The SD-JWT issuance (compact serialization).
    """

    today = datetime.date.today()
    iat = DatestringFormatter(format_date(today))
    validity = format_date(
        today + datetime.timedelta(PID["credential_metadata"]["issuer_config"]["validity"])
    )
    exp = DatestringFormatter(validity)

    current_session = session_manager.get_session(session_id=session_id) if session_id else None
    if current_session and current_session.max_credential_exp is not None:
        if exp >= current_session.max_credential_exp:
            logger.debug(
                f", Session ID: {session_id}, clamping sd-jwt exp from {exp} "
                f"to WIA/KA ceiling {current_session.max_credential_exp}"
            )
            exp = current_session.max_credential_exp

    pid_data = PID.get("data", {})
    device_key = PID["device_publickey"]
    vct = PID["credential_metadata"]["vct"]

    revocation_json = None
    if CONFIGURATION["revocation"]["enabled"]:
        revocation_json = reserve_status_entry(vct, country, validity)
        if revocation_json is not None:
            revocation_json.pop("identifier_list", None)
            session_manager.update_key_status_by_key(
                session_id=session_id, key=device_key, key_status=revocation_json
            )
            record_issued_status(session_id, vct, revocation_json)

    claims: Dict[Any, Any] = {
        "iss": credential_issuer_url(current_session),
        "iat": iat,
        "exp": exp,
        "vct": vct,
    }
    if scope == LEARNING_CREDENTIAL_SCOPE:
        claims["jti"] = str(uuid4())
    if revocation_json:
        claims["status"] = revocation_json
    claims.update(sdjwtNestedClaims(picture_data_url(pid_data["claims"]), PID["credential_metadata"]))

    certificate_base64 = base64.b64encode(_country_key_entry(country)["certificate"]).decode("utf-8")
    private_key = load_country_signing_key(country)
    # kid selects the key in the issuer's /.well-known/jwt-vc-issuer JWKS.
    header_parameters = {"x5c": [certificate_base64], "kid": ec_public_jwk(private_key)["kid"]}

    private_key_curve, private_key_x, private_key_y = KeyData(private_key, "private")

    public_key = serialization.load_pem_public_key(base64.urlsafe_b64decode(device_key.encode("utf-8")))
    public_key_curve, public_key_x, public_key_y = KeyData(public_key, "public")

    b64 = lambda raw: jwt.utils.base64url_encode(raw).decode("utf-8")  # noqa: E731
    # Built directly: sd_jwt's demo get_jwk(..., no_randomness=True) reseeds
    # the global random module with a constant.
    keys = {
        "issuer_key": JWK(
            kty="EC",
            d=b64(private_value_bytes(private_key)),
            crv=private_key_curve,
            x=b64(private_key_x),
            y=b64(private_key_y),
        ),
        "holder_key": JWK(kty="EC", crv=public_key_curve, x=b64(public_key_x), y=b64(public_key_y)),
    }

    SDJWTIssuer.unsafe_randomness = False
    SDJWTIssuer.SD_JWT_HEADER = "dc+sd-jwt"
    sdjwt_at_issuer = SDJWTIssuer(
        claims,
        keys["issuer_key"],
        keys["holder_key"],
        add_decoy_claims=False,
        extra_header_parameters=header_parameters,
    )
    logger.debug(
        f", Session ID: {session_id}, Signed SD-JWT {vct} (country={country}, exp={exp}, "
        f"status_list={revocation_json is not None}, claims={len(pid_data.get('claims', {}))})"
    )
    return sdjwt_at_issuer.sd_jwt_issuance


def DatestringFormatter(date: str) -> int:
    """Converts a ``YYYY-MM-DD`` string to an epoch timestamp.

    Args:
        date: Date string.

    Returns:
        Local-midnight epoch seconds.
    """
    return date_to_timestamp(date)


#: Byte length of an EC JWK ``x`` / ``y`` coordinate per curve.
_JWK_COORDINATE_LENGTHS = {"P-256": 32, "P-384": 48, "P-521": 66}


def KeyData(key: Any, type: str) -> Tuple[Optional[str], bytes, bytes]:
    """Returns the JOSE curve and x / y coordinates of an EC key.

    The coordinates are left-padded to the curve's field size (32, 48 or 66
    bytes for P-256, P-384, P-521), as JWK requires (RFC 7518 section 6.2.1.2).

    Args:
        key: EC public or private key.
        type: ``"public"`` or ``"private"`` (kept for API compatibility; the
            key type is detected automatically).

    Returns:
        ``(crv, x, y)``.
    """
    crv = jwk_curve(key)
    x, y = ec_coordinates(key, min_length=_JWK_COORDINATE_LENGTHS.get(crv, 32))
    return (crv, x, y)
