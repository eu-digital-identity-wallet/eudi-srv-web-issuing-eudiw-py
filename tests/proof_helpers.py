###############################################################################
# Copyright (c) 2026 European Commission
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
"""Test helpers to build real OpenID4VCI proofs (proof JWTs and c_nonces)."""

from __future__ import annotations

import json
import time
from functools import lru_cache
from typing import Any, Dict, Optional, Tuple

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto import jwk

FRONTEND_URL = "https://frontend.test"


@lru_cache(maxsize=1)
def nonce_key_pem() -> bytes:
    """Returns the RSA nonce key PEM (generated once per test run)."""
    return jwk.JWK.generate(kty="RSA", size=2048).export_to_pem(private_key=True, password=None)


def proof_config(service_url: str = "https://backend.test", frontend_url: str = FRONTEND_URL) -> Dict[str, Any]:
    """Returns the configuration entries needed to create and verify proofs.

    Args:
        service_url: Backend URL (``c_nonce`` issuer).
        frontend_url: Credential issuer identifier (proof ``aud``).

    Returns:
        ``service_url``, ``keys.nonce_key`` and a one-frontend ``frontend`` block.
    """
    return {
        "service_url": service_url,
        "keys": {"nonce_key": nonce_key_pem()},
        "frontend": {"default": "fe1", "frontends_config": {"fe1": {"url": frontend_url}}},
    }


def p256_jwk() -> Tuple[ec.EllipticCurvePrivateKey, Dict[str, Any]]:
    """Returns a new P-256 key pair as (private key, public JWK)."""
    key = ec.generate_private_key(ec.SECP256R1())
    return key, json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))


def c_nonce() -> str:
    """Returns a fresh c_nonce from the issuer (needs :func:`proof_config` applied)."""
    from app.services.credential_issuance import create_c_nonce

    return create_c_nonce()


def proof_jwt(
    key: Optional[ec.EllipticCurvePrivateKey] = None,
    *,
    aud: Any = FRONTEND_URL,
    nonce: Any = "fresh",
    iat: Optional[int] = None,
    typ: str = "openid4vci-proof+jwt",
    header_extra: Optional[Dict[str, Any]] = None,
    include_jwk: bool = True,
    algorithm: str = "ES256",
) -> Tuple[str, ec.EllipticCurvePrivateKey]:
    """Builds a signed proof JWT.

    Args:
        key: Signing key (a new P-256 key when omitted).
        aud: ``aud`` claim (omitted when ``None``).
        nonce: ``nonce`` claim; ``"fresh"`` requests a real c_nonce, ``None`` omits it.
        iat: ``iat`` claim (now when omitted).
        typ: ``typ`` header.
        header_extra: Extra header entries.
        include_jwk: Put the public key in the ``jwk`` header.
        algorithm: Signing algorithm (must match the key's curve).

    Returns:
        (proof JWT, signing key).
    """
    if key is None:
        key = ec.generate_private_key(ec.SECP256R1())
    claims: Dict[str, Any] = {"iat": int(time.time()) if iat is None else iat}
    if aud is not None:
        claims["aud"] = aud
    if nonce is not None:
        claims["nonce"] = c_nonce() if nonce == "fresh" else nonce
    headers: Dict[str, Any] = {"typ": typ, **(header_extra or {})}
    if include_jwk:
        headers["jwk"] = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    return jwt.encode(claims, key, algorithm=algorithm, headers=headers), key
