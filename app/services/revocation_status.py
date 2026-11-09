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
"""Client for the token status list (revocation) service.

* :func:`reserve_status_entry` reserves a status list entry for a credential
  being issued (``/token_status_list/take``).
* :func:`set_token_status` flips the status bit of an entry
  (``/token_status_list/set``).
* :func:`get_status_sdjwt` / :func:`get_status_mdoc` read the ``status``
  claim from presented credentials, after checking that they were signed
  by one of this issuer's document signer certificates.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import cbor2
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pycose.headers import X5chain
from pycose.keys import EC2Key
from pycose.messages import Sign1Message

from app.core.config import CONFIGURATION
from app.core.log_utils import safe
from app.core.errors import CertificateVerificationError
from app.services.trust import verify_and_decode_sdjwt
from app.utils.crypto import ec_coordinates
from app.utils.encoding import b64url_decode_strict

logger = logging.getLogger(__name__)

REVOKED = 1
_HTTP_TIMEOUT = 15


def _headers() -> Dict[str, str]:
    """Returns the headers expected by the status list service.

    Returns:
        Form content type and API key headers.
    """
    return {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Api-Key": CONFIGURATION["revocation"]["api_key"],
    }


def reserve_status_entry(doctype: str, country: str, expiry_date: str) -> Optional[Dict[str, Any]]:
    """Reserves a status list entry for a credential about to be issued.

    Args:
        doctype: Credential doctype (mdoc) or ``vct`` (SD-JWT).
        country: Issuing country.
        expiry_date: Credential expiry as ``YYYY-MM-DD``.

    Returns:
        The service response (``status_list`` / ``identifier_list``
        pointers), or ``None`` when the service does not answer ``200``.
    """
    response = requests.post(
        CONFIGURATION["revocation"]["take_url"],
        headers=_headers(),
        data=f"doctype={doctype}&country={country}&expiry_date={expiry_date}",
        timeout=_HTTP_TIMEOUT,
    )
    if response.status_code != 200:
        logger.warning(f"Status list reservation failed for {safe(doctype, 100)}: HTTP {response.status_code}")
        return None
    return response.json()


def set_token_status(
    field: str,
    value: Any,
    uri: str,
    status: int = REVOKED,
    respect_enabled_flag: bool = True,
) -> bool:
    """Sets the status of one status list entry.

    Args:
        field: ``"idx"`` for a ``status_list`` pointer or ``"id"`` for an
            ``identifier_list`` pointer.
        value: Index / identifier.
        uri: Status list URI.
        status: New status (``1`` = revoked).
        respect_enabled_flag: Skip the call when ``revocation.enabled`` is
            false in the configuration.

    Returns:
        ``True`` if the service accepted the update; ``False`` when skipped
        or on any error (errors are logged, never raised).
    """
    if respect_enabled_flag and not CONFIGURATION["revocation"].get("enabled", True):
        logger.debug(f"Revocation disabled via config; skipping set for {safe(uri, 300)}")
        return False

    try:
        response = requests.post(
            CONFIGURATION["revocation"]["set_url"],
            data={field: value, "status": status, "uri": uri},
            headers=_headers(),
            timeout=_HTTP_TIMEOUT,
        )
        response.raise_for_status()
    except Exception:
        # Never abort a multi-entry revocation because one entry failed.
        logger.exception(f"Failed to set status {status} for {field}={safe(value, 64)}, uri={safe(uri, 300)}")
        return False

    logger.info(f"Set token status {status} for {field}={safe(value, 64)}, uri={safe(uri, 300)}")
    return True


def _load_certificate(data: bytes) -> x509.Certificate:
    """Loads a DER or PEM certificate.

    Args:
        data: Certificate bytes.

    Returns:
        The certificate.

    Raises:
        ValueError: If ``data`` is neither DER nor PEM.
    """
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError:
        return x509.load_pem_x509_certificate(data)


def issuer_certificates() -> List[x509.Certificate]:
    """Returns the document signer certificates this issuer signs credentials with.

    Returns:
        Every ``countries.<cc>.keys.<entry>.certificate`` in the configuration
        that can be parsed.
    """
    certificates = []
    for country, country_config in (CONFIGURATION.get("countries") or {}).items():
        for entry_name, entry in (country_config.get("keys") or {}).items():
            data = entry.get("certificate")
            if not data:
                continue
            try:
                certificates.append(_load_certificate(data))
            except ValueError:
                logger.warning(f"Unreadable document signer certificate for {country}/{entry_name}")
    return certificates


def is_issuer_certificate(certificate: x509.Certificate) -> bool:
    """Tells whether a certificate is one of this issuer's document signers.

    Args:
        certificate: Signer certificate of a presented credential.

    Returns:
        ``True`` if it equals a configured document signer certificate.
    """
    fingerprint = certificate.fingerprint(hashes.SHA256())
    return any(own.fingerprint(hashes.SHA256()) == fingerprint for own in issuer_certificates())


def get_status_sdjwt(sd_jwt: str) -> Dict[str, Any]:
    """Verifies a presented SD-JWT issued by this issuer and returns its ``status``.

    Args:
        sd_jwt: SD-JWT in compact serialization.

    Returns:
        The ``status`` claim.

    Raises:
        CertificateVerificationError: If it was not signed by this issuer.
        ValueError: If the SD-JWT or its ``x5c`` header is malformed.
        jwt.InvalidTokenError: If the signature is invalid.
        KeyError: If the credential has no ``status`` claim.
    """
    return verify_and_decode_sdjwt(sd_jwt, is_issuer_certificate)["status"]


def _verified_mso_status(document: Dict[str, Any]) -> Dict[str, Any]:
    """Verifies a document's MSO signature and returns its ``status``.

    The MSO must be signed by one of this issuer's document signer
    certificates (``x5chain`` in the COSE unprotected header).

    Args:
        document: Decoded mdoc ``documents[i]`` entry.

    Returns:
        The MSO ``status`` map.

    Raises:
        CertificateVerificationError: If the signer is not this issuer or the
            signature is invalid.
        KeyError: If the MSO has no ``status``.
    """
    try:
        message = Sign1Message.decode(cbor2.dumps(cbor2.CBORTag(18, document["issuerSigned"]["issuerAuth"])))
    except Exception as e:
        raise CertificateVerificationError(f"Malformed mdoc issuerAuth: {e}") from e
    chain = message.uhdr.get(X5chain)
    leaf = chain[0] if isinstance(chain, list) else chain
    if not leaf:
        raise CertificateVerificationError("mdoc MSO has no x5chain")
    certificate = x509.load_der_x509_certificate(leaf)
    if not is_issuer_certificate(certificate):
        raise CertificateVerificationError(f"Untrusted mdoc signer: {certificate.subject.rfc4514_string()}")

    x, y = ec_coordinates(certificate.public_key(), min_length=0)
    message.key = EC2Key(x=x, y=y, crv=1)
    try:
        signature_valid = message.verify_signature()
    except Exception as e:
        raise CertificateVerificationError(f"mdoc MSO signature check failed: {e}") from e
    if signature_valid is not True:
        raise CertificateVerificationError("mdoc MSO signature not valid")

    return cbor2.loads(cbor2.loads(message.payload).value)["status"]


def get_status_mdoc(mdoc_credential: str) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
    """Verifies a presented mdoc issued by this issuer and extracts its status.

    Args:
        mdoc_credential: Base64url encoded ``DeviceResponse``.

    Returns:
        The status map for a single document, or a list of them for several.

    Raises:
        ValueError: If the input is not valid base64url.
        CertificateVerificationError: If a document was not signed by this
            issuer or its signature is invalid.
    """
    documents = cbor2.loads(b64url_decode_strict(mdoc_credential))["documents"]
    statuses = [_verified_mso_status(document) for document in documents]
    return statuses[0] if len(statuses) == 1 else statuses


def describe_status_list(status: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Derives display information from a ``status_list`` URI.

    The URI path is expected to look like
    ``/<a>/<b>/<doctype>/<status_list_identifier>/...``.

    Args:
        status: A credential ``status`` claim.

    Returns:
        ``{"doctype", "status_list_identifier"}``, or ``None`` when the
        status has no ``status_list`` pointer or its URI path is too short.
    """
    if "status_list" not in status:
        return None
    uri = status["status_list"].get("uri", "")
    path_parts = urlparse(uri).path.strip("/").split("/")
    if len(path_parts) < 4:
        logger.warning(f"Cannot derive doctype / list identifier from status list URI: {safe(uri)}")
        return None
    return {"doctype": path_parts[2], "status_list_identifier": path_parts[3]}
