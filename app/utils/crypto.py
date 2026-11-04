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
"""Elliptic-curve key helpers shared by the credential formatters and JWK code."""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
from typing import Any, Dict, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from app.utils.encoding import b64url_uint, int_to_bytes, urlsafe_b64encode_nopad

#: Mapping of ``cryptography`` curve names to JOSE ``crv`` identifiers.
CURVE_TO_JWK = {
    "secp256r1": "P-256",
    "secp384r1": "P-384",
    "secp521r1": "P-521",
}

#: JWS ``alg`` of each JOSE curve.
JWK_CURVE_TO_ALG = {
    "P-256": "ES256",
    "P-384": "ES384",
    "P-521": "ES512",
}

EcKey = Union[ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey]


def ec_public_numbers(key: EcKey) -> ec.EllipticCurvePublicNumbers:
    """Returns the public numbers of an EC public or private key.

    Args:
        key: EC key.

    Returns:
        The public numbers (x, y, curve).
    """
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.private_numbers().public_numbers
    return key.public_numbers()


def ec_coordinates(key: EcKey, min_length: int = 32) -> Tuple[bytes, bytes]:
    """Extracts the big-endian x / y coordinates of an EC key.

    Args:
        key: EC public or private key.
        min_length: Left-pad each coordinate with zeros to at least this length.

    Returns:
        ``(x, y)`` byte strings.
    """
    numbers = ec_public_numbers(key)
    return int_to_bytes(numbers.x).rjust(min_length, b"\x00"), int_to_bytes(numbers.y).rjust(
        min_length, b"\x00"
    )


def jwk_curve(key: EcKey) -> Optional[str]:
    """Returns the JOSE ``crv`` name of an EC key.

    Args:
        key: EC key.

    Returns:
        ``"P-256"``, ``"P-384"``, ``"P-521"`` or ``None`` if unsupported.
    """
    return CURVE_TO_JWK.get(key.curve.name)


def private_value_bytes(key: ec.EllipticCurvePrivateKey) -> bytes:
    """Returns the private scalar ``d`` as minimal big-endian bytes.

    Args:
        key: EC private key.

    Returns:
        ``d`` encoded as bytes.
    """
    return int_to_bytes(key.private_numbers().private_value)


def certificate_validity(certificate: x509.Certificate) -> Tuple[datetime.datetime, datetime.datetime]:
    """Returns a certificate's validity period as timezone-aware UTC datetimes.

    Uses ``not_valid_before_utc`` / ``not_valid_after_utc`` (cryptography >= 42)
    and falls back to the naive properties of older releases.

    Args:
        certificate: X.509 certificate.

    Returns:
        ``(not_before, not_after)`` in UTC.
    """

    def utc(aware_name: str, naive_name: str) -> datetime.datetime:
        aware = getattr(certificate, aware_name, None)
        if aware is not None:
            return aware
        return getattr(certificate, naive_name).replace(tzinfo=datetime.timezone.utc)

    return utc("not_valid_before_utc", "not_valid_before"), utc("not_valid_after_utc", "not_valid_after")


def ec_public_jwk(key: EcKey) -> Dict[str, str]:
    """Builds the public JWK of an EC key.

    The coordinates are sized to the curve and the ``kid`` is the RFC 7638
    JWK thumbprint (SHA-256).

    Args:
        key: EC public or private key (only the public part is exported).

    Returns:
        ``{"kty", "crv", "x", "y", "kid"}``.

    Raises:
        ValueError: If the key is not an EC key on a supported curve.
    """
    if not isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        raise ValueError("Only EC keys are supported")
    crv = jwk_curve(key)
    if crv is None:
        raise ValueError(f"Unsupported EC curve: {key.curve.name}")

    numbers = ec_public_numbers(key)
    size = (key.curve.key_size + 7) // 8
    jwk = {"kty": "EC", "crv": crv, "x": b64url_uint(numbers.x, size), "y": b64url_uint(numbers.y, size)}
    thumbprint_json = json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode()
    jwk["kid"] = urlsafe_b64encode_nopad(hashlib.sha256(thumbprint_json).digest())
    return jwk


def ec_signing_jwk_from_cert(cert_der: bytes) -> Dict[str, Any]:
    """Builds the signing JWK of a DER encoded EC certificate.

    Args:
        cert_der: DER encoded X.509 certificate.

    Returns:
        :func:`ec_public_jwk` plus ``use``, ``alg``, ``x5c`` and ``x5t#S256``.

    Raises:
        ValueError: If the certificate cannot be parsed or its key is not a
            supported EC key.
    """
    jwk: Dict[str, Any] = ec_public_jwk(x509.load_der_x509_certificate(cert_der).public_key())
    jwk["use"] = "sig"
    jwk["alg"] = JWK_CURVE_TO_ALG[jwk["crv"]]
    jwk["x5c"] = [base64.b64encode(cert_der).decode("utf-8")]
    jwk["x5t#S256"] = urlsafe_b64encode_nopad(hashlib.sha256(cert_der).digest())
    return jwk
