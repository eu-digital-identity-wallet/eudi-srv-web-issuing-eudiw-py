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
"""Validation of PID mdoc presentations received over OpenID4VP.

Holder binding (``deviceSigned`` / DeviceAuth over the OpenID4VP session
transcript and nonce) is checked by the verifier backend that receives the
wallet response; this module re-checks the issuer side of the PID.

Note:
    The two public functions use *opposite* boolean conventions, kept for
    backwards compatibility: :func:`validate_vp_token` returns
    ``(is_error, message)`` whereas :func:`validate_certificate` returns
    ``(is_valid, message)``.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import logging
from typing import Any, Dict, Iterable, Optional, Tuple

import cbor2
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pycose.headers import X5chain
from pycose.keys import EC2Key
from pycose.messages import Sign1Message

from app.core.errors import CertificateVerificationError
from app.services.trust import PURPOSE_PID_SIGNER, check_leaf_certificate, trust_store
from app.utils.crypto import certificate_validity, ec_coordinates

logger = logging.getLogger(__name__)

#: MSO digest algorithm name -> hashlib constructor.
DIGEST_ALGORITHMS = {"SHA-256": hashlib.sha256, "SHA-512": hashlib.sha512}
#: The only document type accepted as a PID presentation.
PID_DOCTYPE = "eu.europa.ec.eudi.pid.1"
_UNTRUSTED_CA = "Certificate wasn't emitted by a Trusted CA "


def _decode_base64url_lenient(data: str) -> bytes:
    """Decodes base64url data, retrying with ``==`` padding.

    Args:
        data: Base64url text.

    Returns:
        The decoded bytes.
    """
    try:
        return base64.urlsafe_b64decode(data)
    except Exception:
        return base64.urlsafe_b64decode(data + "==")


def validate_vp_token(response_json: Dict[str, Any], credentials_requested: Iterable[str]) -> Tuple[bool, str]:
    """Validates the PID mdoc in an OpenID4VP verifier response.

    Args:
        response_json: Verifier response containing ``vp_token.query_0``.
        credentials_requested: Credential ids requested (currently unused).

    Returns:
        ``(True, error_message)`` on failure, ``(False, "")`` when valid.
    """
    vp_token = response_json.get("vp_token")
    if vp_token is None or "query_0" not in vp_token:
        return True, "The path value from presentation_submission is not valid."

    mdoc_cbor = cbor2.loads(_decode_base64url_lenient(vp_token["query_0"][0]))

    if mdoc_cbor["status"] != 0:
        return True, "Status invalid:" + str(mdoc_cbor["status"])

    documents = mdoc_cbor.get("documents") or []
    if len(documents) != 1 or documents[0].get("docType") != PID_DOCTYPE:
        return True, "The presentation must contain exactly one PID document"

    valid, error_msg = validate_certificate(documents[0])
    if valid is False:
        return True, error_msg

    return False, ""


def validate_certificate(mdoc: Dict[str, Any]) -> Tuple[bool, str]:
    """Validates the MSO certificate, signature, digests and validity of a document.

    The document signer must be issued by a ``pid_signer`` trust anchor
    (:func:`app.services.trust.trust_store`) and be a signing certificate
    with the mdoc DS extended key usage when it has one
    (:func:`app.services.trust.check_leaf_certificate`).

    Args:
        mdoc: Decoded ``documents[0]`` entry of a ``DeviceResponse``.

    Returns:
        ``(True, "")`` when valid, otherwise ``(False, reason)``.
    """
    message = Sign1Message.decode(cbor2.dumps(cbor2.CBORTag(18, mdoc["issuerSigned"]["issuerAuth"])))
    certificate = x509.load_der_x509_certificate(message.uhdr[X5chain], default_backend())

    ca_info = trust_store(PURPOSE_PID_SIGNER).get(certificate.issuer)
    if ca_info is None:
        return False, _UNTRUSTED_CA
    if error := _signer_error(certificate, ca_info):
        return False, error

    x, y = ec_coordinates(certificate.public_key(), min_length=0)
    message.key = EC2Key(x=x, y=y, crv=1)

    # pycose returns False for a bad signature (it only raises on malformed input),
    # so the result must be checked explicitly.
    try:
        signature_valid = message.verify_signature()
    except Exception:
        signature_valid = False
    if signature_valid is not True:
        return False, "Signature not valid"

    payload_decoded = cbor2.loads(cbor2.loads(message.payload).value)
    if error := _mso_error(mdoc, payload_decoded, certificate_validity(certificate)):
        return False, error
    return True, ""


def _signer_error(certificate: x509.Certificate, ca_info: Dict[str, Any]) -> Optional[str]:
    """Checks a document signer certificate against its trust anchor.

    Args:
        certificate: Document signer certificate.
        ca_info: Trust store entry of its issuer.

    Returns:
        ``None`` when trusted and currently valid, otherwise the reason.
    """
    try:
        check_leaf_certificate(certificate, PURPOSE_PID_SIGNER)
    except CertificateVerificationError as e:
        return str(e)

    try:
        # Checks issuer name and signature for EC and RSA CAs alike.
        certificate.verify_directly_issued_by(ca_info["certificate"])
    except Exception:
        return _UNTRUSTED_CA

    ca_not_after = ca_info["not_valid_after"].replace(tzinfo=datetime.timezone.utc)
    ca_not_before = ca_info["not_valid_before"].replace(tzinfo=datetime.timezone.utc)
    not_valid_before, not_valid_after = certificate_validity(certificate)
    now = datetime.datetime.now(datetime.timezone.utc)
    if now < ca_not_before or ca_not_after < now:
        return "Certificate not valid"
    if now < not_valid_before or not_valid_after < now:
        return "Document signer certificate not valid"
    return None


def _mso_error(
    mdoc: Dict[str, Any],
    payload_decoded: Dict[str, Any],
    signer_validity: Tuple[datetime.datetime, datetime.datetime],
) -> Optional[str]:
    """Checks the signed MSO against the document it protects.

    Args:
        mdoc: Decoded ``documents[0]`` entry.
        payload_decoded: Decoded MSO.
        signer_validity: ``(not_valid_before, not_valid_after)`` of the signer.

    Returns:
        ``None`` when the doctype, digests and validity are consistent,
        otherwise the reason.
    """
    if payload_decoded["docType"] != mdoc["docType"]:
        return "Doctype from MSO not equal to doctype in document"

    digest = DIGEST_ALGORITHMS.get(payload_decoded["digestAlgorithm"])
    if digest is None:
        return f"Unsupported digest algorithm: {payload_decoded['digestAlgorithm']}"

    for namespace, elements in mdoc["issuerSigned"]["nameSpaces"].items():
        expected = set(payload_decoded["valueDigests"][namespace].values())
        matched = sum(
            1 for e in elements if digest(cbor2.dumps(cbor2.CBORTag(e.tag, e.value))).digest() in expected
        )
        if matched != len(elements):
            return "Missing digests or there aren't enough digests that correspond to the values in document"

    not_valid_before, not_valid_after = signer_validity
    validity_info = payload_decoded["validityInfo"]
    signed = validity_info["signed"]
    if signed < not_valid_before or not_valid_after < signed:
        return "Signed date isn't within validity period of the certificate"

    now = datetime.datetime.now(datetime.timezone.utc)
    if now < validity_info["validFrom"] or validity_info["validUntil"] < now:
        return "Period defined in ValidityInfo is invalid"
    return None
