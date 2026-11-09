# coding: latin-1
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
"""DPoP proofs at the resource endpoints (RFC 9449 section 7).

When token introspection reports ``cnf.jkt``, the access token is bound to a
wallet key: the request must use the ``DPoP`` authorization scheme and carry
a ``DPoP`` proof signed by that key for this request (``htm``, ``htu``,
``ath``), fresh (``iat``) and used once (``jti``).
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from typing import Dict, Iterable, Optional

import jwt

from app.core.config import CONFIGURATION

#: Asymmetric algorithms accepted for DPoP proofs.
DPOP_ALGORITHMS = ["ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "EdDSA"]
MAX_PROOF_AGE = 300
MAX_CLOCK_SKEW = 60
_PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "k")
_THUMBPRINT_MEMBERS = {"EC": ("crv", "kty", "x", "y"), "RSA": ("e", "kty", "n"), "OKP": ("crv", "kty", "x")}

_seen: Dict[str, float] = {}
_seen_lock = threading.Lock()


class DPoPError(ValueError):
    """Raised when a request does not prove possession of the bound key."""


class DPoPSchemeError(DPoPError):
    """Raised when a DPoP-bound token is presented with another scheme (RFC 9449 section 7.2)."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwk_thumbprint(jwk: Dict[str, str]) -> str:
    """Computes the RFC 7638 SHA-256 thumbprint of a public JWK.

    Args:
        jwk: Public JWK (EC, RSA or OKP).

    Returns:
        The base64url thumbprint.

    Raises:
        DPoPError: For an unsupported key type.
    """
    members = _THUMBPRINT_MEMBERS.get(jwk.get("kty"))
    if not members or any(m not in jwk for m in members):
        raise DPoPError("Unsupported DPoP key")
    canonical = json.dumps({m: jwk[m] for m in members}, separators=(",", ":"), sort_keys=True)
    return _b64url(hashlib.sha256(canonical.encode()).digest())


def _remember_jti(key: str) -> bool:
    now = time.time()
    with _seen_lock:
        for k in [k for k, exp in _seen.items() if exp < now]:
            del _seen[k]
        if key in _seen:
            return False
        _seen[key] = now + MAX_PROOF_AGE + MAX_CLOCK_SKEW
        return True


def expected_htu(path: str, request_url: str) -> Iterable[str]:
    """URLs a proof may address for a request.

    Args:
        path: Request path, e.g. ``/credential``.
        request_url: URL the request reached (may be internal behind a proxy).

    Returns:
        The public URL under ``service_url`` and the request URL, without query.
    """
    public = CONFIGURATION["service_url"].rstrip("/") + path
    return {public, request_url.split("?", 1)[0]}


def verify_dpop_request(
    authorization: str, proof: Optional[str], access_token: str, jkt: str, method: str, htu: Iterable[str]
) -> None:
    """Checks that a request proves possession of the token's bound key.

    Args:
        authorization: ``Authorization`` header value.
        proof: ``DPoP`` header value.
        access_token: The access token.
        jkt: Thumbprint bound to the token (introspection ``cnf.jkt``).
        method: HTTP method.
        htu: Accepted target URLs (:func:`expected_htu`).

    Raises:
        DPoPSchemeError: If the scheme is not DPoP.
        DPoPError: If the proof is missing or invalid.
    """
    if not authorization.lower().startswith("dpop "):
        raise DPoPSchemeError("DPoP-bound token used with another authorization scheme")
    if not proof:
        raise DPoPError("Missing DPoP proof")
    try:
        # A DPoP proof carries its own key (jwk header); the signature is
        # verified with it below, after checking it is the token's bound key.
        header = jwt.get_unverified_header(proof)  # NOSONAR
    except jwt.PyJWTError as e:
        raise DPoPError("Malformed DPoP proof") from e
    if header.get("typ") != "dpop+jwt" or header.get("alg") not in DPOP_ALGORITHMS:
        raise DPoPError("DPoP proof typ or alg not accepted")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict) or any(m in jwk for m in _PRIVATE_JWK_MEMBERS):
        raise DPoPError("DPoP proof must carry a public jwk")
    if jwk_thumbprint(jwk) != jkt:
        raise DPoPError("DPoP proof key is not the key bound to the token")
    try:
        key = jwt.PyJWK.from_dict(jwk).key
        # iat is checked below against the MAX_PROOF_AGE / MAX_CLOCK_SKEW window;
        # PyJWT's own check allows no skew and would reject proofs first.
        claims = jwt.decode(
            proof,
            key,
            algorithms=[header["alg"]],
            options={"require": ["jti", "htm", "htu", "iat", "ath"], "verify_iat": False},
        )
    except jwt.PyJWTError as e:
        raise DPoPError(f"DPoP proof invalid: {e}") from e

    if claims["htm"] != method:
        raise DPoPError("DPoP proof htm does not match the request")
    if str(claims["htu"]).split("?", 1)[0] not in set(htu):
        raise DPoPError("DPoP proof htu does not match the request")
    now = time.time()
    if not isinstance(claims["iat"], (int, float)) or not now - MAX_PROOF_AGE <= claims["iat"] <= now + MAX_CLOCK_SKEW:
        raise DPoPError("DPoP proof iat outside the accepted window")
    if claims["ath"] != _b64url(hashlib.sha256(access_token.encode()).digest()):
        raise DPoPError("DPoP proof ath does not match the access token")
    if not _remember_jti(f"{jkt}:{claims['jti']}"):
        raise DPoPError("DPoP proof jti already used")
