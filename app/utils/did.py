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
"""Resolution of DID URLs that carry the public key in the identifier itself.

OpenID4VCI 1.0 (appendix F.1) lets a JWT proof name the holder key with a
``kid`` DID URL instead of a ``jwk`` header. Only the DID methods that need
no network resolution are supported: ``did:jwk`` and ``did:key`` (P-256).

Attributes:
    SUPPORTED_DID_METHODS: Values advertised in
        ``cryptographic_binding_methods_supported``.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from cryptography.hazmat.primitives.asymmetric import ec

from app.utils.encoding import b64url_decode_strict, b64url_uint

SUPPORTED_DID_METHODS = ("did:jwk", "did:key")

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
#: multicodec prefix (varint 0x1200) of a P-256 public key.
_MULTICODEC_P256_PUB = b"\x80\x24"
#: Compressed SEC1 P-256 point length (did:key encodes compressed keys).
_P256_COMPRESSED_LEN = 33
#: Upper bound on the DID URL length (base58 decoding is quadratic).
_MAX_DID_URL_LENGTH = 2048


def _b58decode(value: str) -> bytes:
    """Decodes base58btc text.

    Args:
        value: Base58btc text (without the multibase ``z`` prefix).

    Returns:
        The decoded bytes.

    Raises:
        ValueError: If ``value`` contains a character outside the alphabet.
    """
    number = 0
    for char in value:
        number = number * 58 + _BASE58_ALPHABET.index(char)
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + decoded


def _did_jwk(method_id: str, fragment: str) -> Dict[str, Any]:
    """Returns the JWK of a ``did:jwk`` DID URL.

    Args:
        method_id: Base64url encoded JWK.
        fragment: DID URL fragment (``0`` or empty).

    Returns:
        The public JWK.

    Raises:
        ValueError: If the DID URL is malformed or holds private key material.
    """
    if fragment not in ("", "0"):
        raise ValueError("did:jwk verification method must be #0")
    jwk = json.loads(b64url_decode_strict(method_id))
    if not isinstance(jwk, dict):
        raise ValueError("did:jwk does not contain a JWK")
    if "d" in jwk:
        raise ValueError("did:jwk must not contain private key material")
    return jwk


def _did_key(method_id: str, fragment: str) -> Dict[str, Any]:
    """Returns the JWK of a ``did:key`` DID URL.

    Args:
        method_id: Multibase (base58btc, ``z`` prefix) multicodec key.
        fragment: DID URL fragment (the method id, or empty).

    Returns:
        The public P-256 JWK.

    Raises:
        ValueError: If the DID URL is malformed or not a P-256 key.
    """
    if fragment not in ("", method_id):
        raise ValueError("did:key verification method must be the key itself")
    if not method_id.startswith("z"):
        raise ValueError("did:key must use base58btc multibase encoding")
    key_bytes = _b58decode(method_id[1:])
    if not key_bytes.startswith(_MULTICODEC_P256_PUB):
        raise ValueError("Credential Issuer only supports P-256 keys")
    point = key_bytes[len(_MULTICODEC_P256_PUB) :]
    if len(point) != _P256_COMPRESSED_LEN:
        raise ValueError("did:key P-256 key must be a compressed point")
    numbers = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point).public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64url_uint(numbers.x, 32), "y": b64url_uint(numbers.y, 32)}


def jwk_from_did_url(did_url: Any) -> Dict[str, Any]:
    """Resolves a ``did:jwk`` / ``did:key`` DID URL to its public JWK.

    Args:
        did_url: DID URL from a JWT proof ``kid`` header.

    Returns:
        The public JWK.

    Raises:
        ValueError: If the DID URL is malformed or uses an unsupported method.
    """
    if not isinstance(did_url, str) or len(did_url) > _MAX_DID_URL_LENGTH:
        raise ValueError("kid is not a supported DID URL")
    did, _, fragment = did_url.partition("#")
    scheme, _, rest = did.partition(":")
    method, _, method_id = rest.partition(":")
    if scheme != "did" or not method_id:
        raise ValueError("kid is not a supported DID URL")
    try:
        if method == "jwk":
            return _did_jwk(method_id, fragment)
        if method == "key":
            return _did_key(method_id, fragment)
    except ValueError as e:  # JSONDecodeError, UnicodeDecodeError and point errors too
        raise ValueError(f"Invalid DID URL in kid: {e}") from e
    raise ValueError("Unsupported DID method in kid: supported are did:jwk and did:key")
