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
"""Credential endpoint business logic (OpenID4VCI).

Turns a validated credential request into a call to the credential
formatters: extracts holder keys from the proofs, verifies key attestations
(and their revocation status), caps the batch size and computes the expiry
ceiling imposed by the wallet / key attestations (TS3 2.2.2.1, 2.4.3).

By default each ``c_nonce`` is accepted by one credential request only
(:mod:`app.repositories.nonce_store`); ``proof_validation.single_use_nonce:
false`` lets a wallet reuse a nonce until it expires (OpenID4VCI 1.0 section 13.8
leaves the nonce lifetime to the issuer). A deferred request keeps the holder
keys proven by the first request (:class:`ProvenKeys`) instead of verifying
its proofs again.
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto import jwe, jwk

from app.core.config import CONFIGURATION
from app.core.log_utils import safe
from app.core.errors import CertificateVerificationError
from app.core.state import oidc_metadata, session_manager
from app.repositories.nonce_store import used_nonces
from app.services.auth_server import StatusCheckError, check_status_list_revocation
from app.services.dynamic_formatter import issue_credentials_for_session
from app.services.frontend_metadata import issuer_metadata_template
from app.services.trust import (
    KEY_ATTESTATION_CONTEXT,
    PURPOSE_KEY_ATTESTATION,
    trust_context,
    trust_use_case,
    verify_jwt_with_x5c,
)
from app.utils.did import jwk_from_did_url
from app.utils.encoding import b64url_decode

logger = logging.getLogger(__name__)

DEFERRED_ONLY_CONFIGURATION = "eu.europa.ec.eudi.pid_mdoc_deferred"
NONCE_LIFETIME_SECONDS = 3600


#: OpenID4VCI JWT proof type header. TS3 2.6: proofs and key attestations are
#: signed with ES256, ES384 or ES512, each only on its own curve.
PROOF_JWT_TYP = "openid4vci-proof+jwt"
ALGORITHM_CURVES = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}
PROOF_ALGORITHMS = tuple(ALGORITHM_CURVES)
_HOLDER_KEY_CURVES = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}
#: Accepted clock skew for ``iat`` and maximum proof age.
PROOF_IAT_LEEWAY_SECONDS = 60
PROOF_MAX_AGE_SECONDS = 3600
#: Key attestation ``typ`` header (checked when present) and default maximum
#: age (``proof_validation.key_attestation_max_age_seconds``).
KEY_ATTESTATION_TYP = "key-attestation+jwt"
KEY_ATTESTATION_MAX_AGE_SECONDS = 24 * 3600


class InvalidProofError(Exception):
    """Raised when a proof (JWT or key attestation) is not acceptable."""


class InvalidNonceError(InvalidProofError):
    """Raised when a proof's ``c_nonce`` is not acceptable (OpenID4VCI ``invalid_nonce``)."""


class TooManyProofsError(Exception):
    """Raised when a request carries more proofs than the batch size allows."""


class InvalidEncryptionParametersError(ValueError):
    """Raised when ``credential_response_encryption`` is malformed or not supported."""


@dataclass
class ProvenKeys:
    """Holder keys proven by a credential request, kept for deferred issuance.

    Attributes:
        keys: Holder keys in the formatter's ``proofs`` format.
        ka_exps: ``key_storage_status.exp`` of the verified key attestations.
        verified: Whether the keys come from verified proofs.
    """

    keys: List[Dict[str, Any]] = field(default_factory=list)
    ka_exps: List[int] = field(default_factory=list)
    verified: bool = False


class CredentialValidityError(Exception):
    """Raised when the WIA / KA validity ceiling has already passed."""


class KeyAttestationStatusError(Exception):
    """Raised when a key attestation's status rules it out (revoked or unverifiable)."""


class KARevokedError(KeyAttestationStatusError):
    """Raised when a key attestation is revoked."""


# ---------------------------------------------------------------------------
# Holder keys
# ---------------------------------------------------------------------------


def pKfromJWK(jwk_dict: Dict[str, Any]) -> Any:
    """Converts a P-256 / P-384 / P-521 JWK into the base64url PEM device key format.

    Args:
        jwk_dict: Public JWK.

    Returns:
        Base64url encoded PEM ``SubjectPublicKeyInfo``, or an
        ``invalid_proof`` error dict when the curve is not supported.
    """
    curve = _HOLDER_KEY_CURVES.get(jwk_dict.get("crv"))
    if curve is None:
        return {
            "error": "invalid_proof",
            "error_description": "Credential Issuer only supports P-256, P-384 and P-521 curves",
        }

    public_key = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(b64url_decode(jwk_dict["x"]), "big"),
        y=int.from_bytes(b64url_decode(jwk_dict["y"]), "big"),
        curve=curve(),
    ).public_key()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.urlsafe_b64encode(public_key_pem).decode("utf-8")


def _proof_audiences(session_id: str) -> List[str]:
    """Returns the credential issuer identifiers a proof may be addressed to.

    Args:
        session_id: Issuance session.

    Returns:
        The URL of the session's frontend when known, otherwise the URLs of
        all configured frontends (each with and without a trailing slash).
    """
    frontends = (CONFIGURATION.get("frontend") or {}).get("frontends_config") or {}
    current = session_manager.get_session(session_id=session_id)
    frontend_id = getattr(current, "frontend_id", None) if current else None
    if frontend_id in frontends:
        urls = [frontends[frontend_id]["url"]]
    else:
        urls = [cfg["url"] for cfg in frontends.values() if cfg.get("url")]
    return [variant for url in urls for variant in (url.rstrip("/"), url.rstrip("/") + "/")]


def _nonce_required() -> bool:
    """Tells whether proofs must carry a valid ``c_nonce``.

    Returns:
        ``proof_validation.require_nonce`` from the configuration (default ``True``).
    """
    return bool((CONFIGURATION.get("proof_validation") or {}).get("require_nonce", True))


def _nonce_single_use() -> bool:
    """Tells whether a ``c_nonce`` is accepted by one credential request only.

    Returns:
        ``proof_validation.single_use_nonce`` from the configuration (default
        ``True``). When ``False``, a valid nonce can be reused until it expires.
    """
    return bool((CONFIGURATION.get("proof_validation") or {}).get("single_use_nonce", True))


def verify_c_nonce(c_nonce: Any, nonces: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
    """Checks that a ``c_nonce`` was issued by :func:`create_c_nonce` and is still valid.

    The nonce is a JWE only this issuer can decrypt. Its ``jti`` (inside the
    encrypted, authenticated payload) identifies it for the single-use check,
    which the caller makes once all proofs of a request are verified
    (:func:`_consume_nonces`).

    OpenID4VCI 1.0 section 8.3.1.2: a proof without a ``c_nonce`` is an
    ``invalid_proof``; a proof with an invalid one is an ``invalid_nonce``.

    Args:
        c_nonce: Nonce from a proof.
        nonces: When given, receives ``jti -> exp`` of the nonce.

    Returns:
        The nonce claims.

    Raises:
        InvalidProofError: If the nonce is missing.
        InvalidNonceError: If the nonce cannot be decrypted, was not issued
            for this credential endpoint, has no ``jti`` or has expired.
    """
    if c_nonce is None or c_nonce == "":
        raise InvalidProofError("Proof has no c_nonce")
    if not isinstance(c_nonce, str):
        raise InvalidNonceError("c_nonce is not valid")
    try:
        token = jwe.JWE()
        token.deserialize(c_nonce, key=jwk.JWK.from_pem(CONFIGURATION["keys"]["nonce_key"]))
        claims = json.loads(token.payload)
    except Exception as e:
        raise InvalidNonceError("c_nonce is not valid") from e

    service_url = CONFIGURATION["service_url"]
    if claims.get("iss") != service_url or f"{service_url}/credential" not in (claims.get("aud") or []):
        raise InvalidNonceError("c_nonce was not issued for this credential endpoint")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] < time.time():
        raise InvalidNonceError("c_nonce has expired")
    if not isinstance(claims.get("jti"), str) or not claims["jti"]:
        raise InvalidNonceError("c_nonce has no identifier")
    if nonces is not None:
        nonces[claims["jti"]] = claims["exp"]
    return claims


def _consume_nonces(nonces: Dict[str, float], session_id: str) -> None:
    """Marks the nonces of a verified request as used.

    Does nothing when ``proof_validation.single_use_nonce`` is ``false``: the
    store is then not consulted and a nonce stays usable until it expires.

    Args:
        nonces: ``jti -> exp`` of every nonce the request's proofs carry.
        session_id: Issuance session (for logging).

    Raises:
        InvalidNonceError: If one of them was already used by an earlier
            request (nothing is recorded then).
    """
    if not _nonce_single_use():
        return
    if nonces and not used_nonces.consume_all(nonces):
        logger.warning(f", Session ID: {session_id}, Proof rejected: c_nonce already used")
        raise InvalidNonceError("c_nonce has already been used")


def _public_key_from_jwk(jwk_dict: Any) -> Any:
    """Loads a public JWK as a PyJWT verification key.

    Args:
        jwk_dict: JWK from a proof header or a key attestation.

    Returns:
        The public key.

    Raises:
        InvalidProofError: If the JWK is missing, private or unusable.
    """
    if not isinstance(jwk_dict, dict):
        raise InvalidProofError("Proof has no usable jwk")
    if "d" in jwk_dict:
        raise InvalidProofError("Proof jwk must not contain private key material")
    try:
        return jwt.PyJWK(jwk_dict).key
    except Exception as e:
        raise InvalidProofError("Proof jwk is not a valid public key") from e


def verify_proof_jwt(
    proof_jwt: str,
    session_id: str,
    signing_jwks: Optional[List[Dict[str, Any]]] = None,
    nonces: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """Verifies an OpenID4VCI JWT proof of possession.

    Checks ``typ`` (``openid4vci-proof+jwt``), ``alg``, the signature (with
    the ``jwk`` header, or one of ``signing_jwks`` for proofs backed by a key
    attestation), ``aud`` (the credential issuer identifier), ``iat``
    freshness and, unless disabled, the ``nonce`` (a valid ``c_nonce``).

    Args:
        proof_jwt: Compact proof JWT.
        session_id: Issuance session (selects the expected ``aud``).
        signing_jwks: Keys allowed to sign the proof instead of the ``jwk``
            header (the attested keys of a key attestation).
        nonces: When given, receives ``jti -> exp`` of the proof's ``c_nonce``.

    Returns:
        The verified proof claims.

    Raises:
        InvalidProofError: If any check fails.
    """
    try:
        # The proof carries its own key (jwk header): typ / alg / key are read
        # first, then the signature is verified with that key below.
        header = jwt.get_unverified_header(proof_jwt)  # NOSONAR
    except jwt.DecodeError as e:
        raise InvalidProofError("Proof JWT is malformed") from e

    if header.get("typ") != PROOF_JWT_TYP:
        raise InvalidProofError(f"Proof JWT typ must be {PROOF_JWT_TYP}")
    alg = header.get("alg")
    if alg not in PROOF_ALGORITHMS:
        raise InvalidProofError("Proof JWT alg is not supported")

    candidates = signing_jwks if signing_jwks is not None else [header.get("jwk")]
    # TS3 2.6: each algorithm only on its own curve (ES256 / P-256, ...).
    candidates = [c for c in candidates if not isinstance(c, dict) or c.get("crv") == ALGORITHM_CURVES[alg]]
    if not candidates:
        raise InvalidProofError(f"Proof JWT alg {alg} requires a {ALGORITHM_CURVES[alg]} key")
    audiences = _proof_audiences(session_id)
    claims: Optional[Dict[str, Any]] = None
    for candidate in candidates:
        try:
            claims = jwt.decode(
                proof_jwt,
                key=_public_key_from_jwk(candidate),
                algorithms=[alg],
                audience=audiences,
                options={"require": ["aud", "iat"]},
                leeway=PROOF_IAT_LEEWAY_SECONDS,
            )
            break
        except jwt.InvalidSignatureError:
            continue
        except jwt.InvalidTokenError as e:
            raise InvalidProofError(f"Proof JWT is not valid: {e}") from e
    if claims is None:
        raise InvalidProofError("Proof JWT signature is not valid")

    if claims["iat"] < time.time() - PROOF_MAX_AGE_SECONDS:
        raise InvalidProofError("Proof JWT is too old")
    if _nonce_required():
        verify_c_nonce(claims.get("nonce"), nonces)

    logger.debug(f", Session ID: {session_id}, Proof JWT verified (aud={safe(claims.get('aud'), 100)})")
    return claims


def _holder_key(jwk_dict: Dict[str, Any]) -> str:
    """Converts a verified P-256 / P-384 / P-521 JWK to the device key format.

    Args:
        jwk_dict: Public JWK.

    Returns:
        Base64url encoded PEM public key.

    Raises:
        InvalidProofError: If the key is on another curve.
    """
    device_key = pKfromJWK(jwk_dict)
    if not isinstance(device_key, str):
        raise InvalidProofError("Credential Issuer only supports P-256, P-384 and P-521 holder keys")
    return device_key


# ---------------------------------------------------------------------------
# Key attestations
# ---------------------------------------------------------------------------


def _key_attestation_max_age() -> int:
    """Returns the maximum key attestation age in seconds.

    Returns:
        ``proof_validation.key_attestation_max_age_seconds`` (default 24 h).
    """
    configured = (CONFIGURATION.get("proof_validation") or {}).get("key_attestation_max_age_seconds")
    return int(configured) if configured else KEY_ATTESTATION_MAX_AGE_SECONDS


def _key_storage_status_list(claims: Dict[str, Any]) -> Dict[str, Any]:
    """Returns the status list reference of a key attestation's ``key_storage_status``.

    TS3 2.3.2 / 2.4.1: every key attestation carries ``key_storage_status``
    with a ``status`` status list reference and a numeric ``exp``.

    Args:
        claims: Key attestation claims.

    Returns:
        The ``key_storage_status.status.status_list`` object.

    Raises:
        ValueError: If ``key_storage_status`` is missing or malformed.
    """
    key_storage_status = claims.get("key_storage_status")
    if not isinstance(key_storage_status, dict):
        raise ValueError("Key attestation has no key_storage_status")
    exp = key_storage_status.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        raise ValueError("Key attestation key_storage_status.exp is missing or not a number")
    status = key_storage_status.get("status")
    status_list = status.get("status_list") if isinstance(status, dict) else None
    if (
        not isinstance(status_list, dict)
        or isinstance(status_list.get("idx"), bool)
        or not isinstance(status_list.get("idx"), int)
        or not isinstance(status_list.get("uri"), str)
    ):
        raise ValueError("Key attestation key_storage_status.status is malformed")
    return status_list


def decode_verify_attestation(jwt_raw: str) -> Dict[str, Any]:
    """Verifies a key attestation JWT and checks its revocation status.

    Args:
        jwt_raw: Key attestation JWT.

    Returns:
        The attestation claims.

    The signing chain is trusted via the trust validator (when enabled) or
    the local trusted CAs; see :func:`app.services.trust.verify_x5c_chain`.
    It must be signed with ES256, ES384 or ES512 (TS3 2.6). ``iat`` and
    ``exp`` are required, ``iat`` may be at most
    :func:`_key_attestation_max_age` old, ``typ`` must be
    :data:`KEY_ATTESTATION_TYP` when present, and ``key_storage_status``
    must be well-formed (:func:`_key_storage_status_list`).

    Raises:
        KARevokedError: If the attestation's status list entry is revoked.
        KeyAttestationStatusError: If its status cannot be verified.
        ValueError, CertificateVerificationError, jwt.PyJWTError:
            If verification fails.
    """
    claims = verify_jwt_with_x5c(
        jwt_raw=jwt_raw,
        verification_context=trust_context("key_attestation", KEY_ATTESTATION_CONTEXT),
        use_case=trust_use_case("key_attestation"),
        purpose=PURPOSE_KEY_ATTESTATION,
        allowed_algorithms=list(PROOF_ALGORITHMS),
        required_claims=("iat", "exp"),
        max_age_seconds=_key_attestation_max_age(),
        expected_typ=KEY_ATTESTATION_TYP,
    )

    status_list = _key_storage_status_list(claims)
    if CONFIGURATION["status_validator"]["enabled"]:
        try:
            revoked = check_status_list_revocation(
                url=CONFIGURATION["status_validator"]["url"],
                status_idx=status_list["idx"],
                status_uri=status_list["uri"],
            )
        except StatusCheckError as e:
            # Fail closed: an attestation whose status cannot be checked is not accepted.
            raise KeyAttestationStatusError(f"Key Attestation status could not be verified: {e}") from e
        if revoked:
            raise KARevokedError("Key Attestation is revoked")
    return claims


def _register_attested_keys(
    claims: Dict[str, Any], session_id: str, pub_keys: List[Dict[str, Any]], ka_exps: List[int]
) -> None:
    """Records a verified key attestation and its attested keys.

    The KA status is appended to the session's client status, each attested
    key is added under it and to ``pub_keys``, and the KA expiry is
    collected into ``ka_exps``.

    Args:
        claims: Verified attestation claims.
        session_id: Issuance session.
        pub_keys: Holder keys collected so far (mutated).
        ka_exps: KA ``key_storage_status.exp`` values (mutated).
    """
    key_storage_status = claims.get("key_storage_status")
    if key_storage_status and key_storage_status.get("exp") is not None:
        ka_exps.append(key_storage_status["exp"])

    ka_index = session_manager.add_key_storage_status(
        session_id=session_id,
        status=key_storage_status.get("status") if key_storage_status else None,
    )

    for attested_jwk in claims["attested_keys"]:
        device_key = _holder_key(attested_jwk)
        pub_keys.append({"attestation": device_key})
        if ka_index is not None:
            session_manager.add_key_to_key_storage_status(
                session_id=session_id, key_storage_status_index=ka_index, key=device_key
            )


def _verified_attestation(
    attestation: str,
    session_id: str,
    origin: str,
    require_nonce: bool,
    nonces: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """Verifies a key attestation (signature, trust, revocation, optionally nonce).

    Args:
        attestation: Key attestation JWT.
        session_id: Issuance session.
        origin: Where the attestation came from (for logging).
        require_nonce: Whether the attestation must carry a valid ``c_nonce``
            (when used directly as the proof).
        nonces: When given, receives ``jti -> exp`` of the attestation's ``c_nonce``.

    Returns:
        The attestation claims.

    Raises:
        InvalidProofError: If the attestation is revoked, untrusted, invalid
            or lacks a valid nonce.
    """
    try:
        claims = decode_verify_attestation(attestation)
    except KeyAttestationStatusError as e:
        logger.warning(f", Session ID: {session_id}, Key attestation rejected ({origin}): {safe(e)}")
        raise InvalidProofError(str(e)) from e
    except (CertificateVerificationError, ValueError, jwt.PyJWTError) as e:
        logger.warning(f", Session ID: {session_id}, Key attestation rejected ({origin}): {safe(e)}")
        raise InvalidProofError("Key attestation is not valid") from e
    if not isinstance(claims.get("attested_keys"), list) or not claims["attested_keys"]:
        raise InvalidProofError("Key attestation has no attested_keys")
    if require_nonce and _nonce_required():
        verify_c_nonce(claims.get("nonce"), nonces)
    return claims


# ---------------------------------------------------------------------------
# Batch size / validity
# ---------------------------------------------------------------------------


def _credential_config(credential_configuration_id: str) -> Dict[str, Any]:
    """Returns a credential configuration, or ``{}`` if unknown.

    Args:
        credential_configuration_id: Configuration id.

    Returns:
        The configuration.
    """
    return oidc_metadata["credential_configurations_supported"].get(credential_configuration_id, {})


def get_batch_size(credential_configuration_id: str) -> Optional[int]:
    """Returns the ``batch_size`` of the configuration's ``once_only`` reuse policy.

    Args:
        credential_configuration_id: Configuration id.

    Returns:
        The batch size, or ``None`` when not configured.
    """
    options = (
        _credential_config(credential_configuration_id)
        .get("credential_metadata", {})
        .get("credential_reuse_policy", {})
        .get("options", [])
    )
    return next((o.get("batch_size") for o in options if "once_only" in o.get("details", [])), None)


def max_proofs(credential_configuration_id: str) -> int:
    """Returns how many proofs one credential request may carry.

    Args:
        credential_configuration_id: Configuration id.

    Returns:
        The configuration's :func:`get_batch_size`, else the issuer's
        ``batch_credential_issuance.batch_size``, else 1.
    """
    batch_size = get_batch_size(credential_configuration_id)
    if not batch_size:
        batch_size = (issuer_metadata_template().get("batch_credential_issuance") or {}).get("batch_size")
    return int(batch_size) if batch_size else 1


def _proof_count(credential_request: Dict[str, Any]) -> int:
    """Counts the proofs of a credential request without decoding them.

    Args:
        credential_request: Validated credential request.

    Returns:
        1 for a single ``proof``, else the number of ``proofs`` entries.
    """
    if credential_request.get("proof") is not None and "proofs" not in credential_request:
        return 1
    proofs = credential_request.get("proofs")
    if not isinstance(proofs, dict):
        return 0
    return sum(len(values) if isinstance(values, list) else 1 for values in proofs.values())


def get_custom_validity_seconds(credential_configuration_id: str) -> Optional[int]:
    """Returns the configured credential validity in seconds.

    Args:
        credential_configuration_id: Configuration id.

    Returns:
        ``issuer_config.validity`` (days) converted to seconds, or ``None``.
    """
    validity_days = _credential_config(credential_configuration_id).get("issuer_config", {}).get("validity")
    return validity_days * 24 * 60 * 60 if validity_days is not None else None


def compute_max_credential_exp(
    wia_client_status_exp: Optional[int],
    ka_key_storage_status_exp: Optional[int],
    custom_validity_seconds: Optional[int] = None,
) -> Optional[int]:
    """Computes the latest allowed credential expiry.

    TS3 2.4.3: the technical validity of a PID SHALL end before
    ``client_status.exp`` (WIA) and ``key_storage_status.exp`` (KA). When a
    custom validity is configured it is used, capped by that ceiling.

    Args:
        wia_client_status_exp: WIA expiry (epoch seconds).
        ka_key_storage_status_exp: Earliest KA expiry (epoch seconds).
        custom_validity_seconds: Configured credential lifetime.

    Returns:
        The maximum expiry (epoch seconds), or ``None`` for no constraint.

    Raises:
        CredentialValidityError: If the ceiling is already in the past.
    """
    now = int(time.time())
    candidates = [c for c in (wia_client_status_exp, ka_key_storage_status_exp) if c is not None]
    hard_ceiling = min(candidates) if candidates else None

    if hard_ceiling is not None and hard_ceiling <= now:
        raise CredentialValidityError(
            "WIA/KA revocation maintenance period has already expired or expires immediately"
        )

    if custom_validity_seconds is not None:
        proposed = now + custom_validity_seconds
        if hard_ceiling is not None and proposed >= hard_ceiling:
            proposed = hard_ceiling - 1
        return proposed

    return hard_ceiling - 1 if hard_ceiling is not None else None


# ---------------------------------------------------------------------------
# Credential generation
# ---------------------------------------------------------------------------


def _collect_jwt_proof(
    proof_jwt: str,
    session_id: str,
    pub_keys: List[Dict[str, Any]],
    ka_exps: List[int],
    nonces: Optional[Dict[str, float]] = None,
) -> None:
    """Verifies one JWT proof and records the holder key(s) it proves.

    A proof with a ``key_attestation`` header must be signed by one of the
    attested keys; all attested keys are then issued to (its ``kid``, if any,
    names one of them). Otherwise the proof is signed by its ``jwk`` header
    key, or by the key of its ``kid`` DID URL (``did:jwk`` / ``did:key``),
    which becomes the holder key. ``jwk``, ``kid`` and ``x5c`` are mutually
    exclusive (OpenID4VCI 1.0 appendix F.1).

    Args:
        proof_jwt: Compact proof JWT.
        session_id: Issuance session.
        pub_keys: Holder keys (mutated).
        ka_exps: KA expiry values (mutated).
        nonces: Receives the proof's ``c_nonce`` (see :func:`verify_c_nonce`).

    Raises:
        InvalidProofError: If the proof or its key attestation is invalid.
    """
    try:
        # Only selects the key source (key_attestation, kid or jwk); verify_proof_jwt
        # verifies the signature before any key is used.
        header = jwt.get_unverified_header(proof_jwt)  # NOSONAR
    except jwt.DecodeError as e:
        raise InvalidProofError("Proof JWT is malformed") from e

    if sum(name in header for name in ("jwk", "kid", "x5c")) > 1:
        raise InvalidProofError("Proof JWT must not combine jwk, kid and x5c headers")

    if "key_attestation" in header:
        claims = _verified_attestation(header["key_attestation"], session_id, "jwt proof header", require_nonce=False)
        verify_proof_jwt(proof_jwt, session_id, signing_jwks=claims["attested_keys"], nonces=nonces)
        _register_attested_keys(claims, session_id, pub_keys, ka_exps)
        return

    if "kid" in header:
        try:
            holder_jwk = jwk_from_did_url(header["kid"])
        except ValueError as e:
            raise InvalidProofError(str(e)) from e
        # The proof must be signed by the DID key, which is then bound.
        verify_proof_jwt(proof_jwt, session_id, signing_jwks=[holder_jwk], nonces=nonces)
        pub_keys.append({"jwt": _holder_key(holder_jwk)})
        return

    verify_proof_jwt(proof_jwt, session_id, nonces=nonces)
    pub_keys.append({"jwt": _holder_key(header["jwk"])})


def _collect_typed_proofs(
    proof_type: Any,
    proof_values: List[Any],
    shape: Optional[str],
    session_id: str,
    pub_keys: List[Dict[str, Any]],
    ka_exps: List[int],
    nonces: Optional[Dict[str, float]],
) -> None:
    """Verifies the proofs of one proof type and collects their holder keys.

    Args:
        proof_type: ``jwt`` or ``attestation``.
        proof_values: The proofs of that type.
        shape: ``"single"`` for the legacy ``proof`` parameter (for logging).
        session_id: Issuance session.
        pub_keys: Holder keys (mutated).
        ka_exps: KA expiry values (mutated).
        nonces: Receives the ``c_nonce`` of every proof.

    Raises:
        InvalidProofError: If a proof is invalid or of an unsupported type.
    """
    match proof_type:
        case "jwt":
            for proof_jwt in proof_values:
                _collect_jwt_proof(proof_jwt, session_id, pub_keys, ka_exps, nonces)
        case "attestation":
            label = "single attestation proof" if shape == "single" else "attestation proof"
            for attestation in proof_values:
                claims = _verified_attestation(attestation, session_id, label, True, nonces)
                _register_attested_keys(claims, session_id, pub_keys, ka_exps)
        case _:
            raise InvalidProofError("Unsupported proof type")


def _collect_proof_keys(
    credential_request: Dict[str, Any],
    session_id: str,
    pub_keys: List[Dict[str, Any]],
    ka_exps: List[int],
    nonces: Optional[Dict[str, float]] = None,
) -> None:
    """Verifies the request's proof(s) and collects the proven holder keys.

    The number of proofs is checked against :func:`max_proofs` first, before
    any proof is decoded, any signature checked or any trust / status
    service called.

    Args:
        credential_request: Validated credential request.
        session_id: Issuance session.
        pub_keys: Holder keys (mutated).
        ka_exps: KA expiry values (mutated).
        nonces: Receives the ``c_nonce`` of every proof.

    Raises:
        TooManyProofsError: If the request has more proofs than allowed.
        InvalidProofError: If any proof is invalid or of an unsupported type.
    """
    allowed = max_proofs(credential_request["credential_configuration_id"])
    if _proof_count(credential_request) > allowed:
        raise TooManyProofsError(f"At most {allowed} proof(s) per request")

    proof = credential_request.get("proof")

    if proof is not None and "proofs" not in credential_request:
        proof_type = proof.get("proof_type")
        _collect_typed_proofs(proof_type, [proof.get(proof_type)], "single", session_id, pub_keys, ka_exps, nonces)
    else:
        for proof_type, proof_values in (credential_request.get("proofs") or {}).items():
            if not isinstance(proof_values, list) or not proof_values:
                raise InvalidProofError(f"proofs.{safe(proof_type, 30)} must be a non-empty list")
            _collect_typed_proofs(proof_type, proof_values, None, session_id, pub_keys, ka_exps, nonces)

    # TS3 2.2.2.1: a key attestation may attest more keys than the batch size.
    batch_size = get_batch_size(credential_request["credential_configuration_id"])
    if batch_size and len(pub_keys) > batch_size:
        logger.info(
            f", Session ID: {session_id}, Proofs contained {len(pub_keys)} keys, truncating to batch_size {batch_size}"
        )
        del pub_keys[batch_size:]


def _prove_holder_keys(
    credential_request: Dict[str, Any], session_id: str, holder_keys: Optional[ProvenKeys]
) -> ProvenKeys:
    """Returns the holder keys of a request, verifying its proofs if needed.

    Args:
        credential_request: Validated credential request.
        session_id: Issuance session.
        holder_keys: Keys proven by an earlier request (deferred issuance),
            reused as they are when ``verified``; otherwise filled in.

    Returns:
        The proven keys.

    Raises:
        TooManyProofsError: If the request has more proofs than allowed.
        InvalidProofError: If a proof is invalid or no key is proven.
    """
    if holder_keys is not None and holder_keys.verified:
        logger.debug(f", Session ID: {session_id}, Reusing {len(holder_keys.keys)} holder key(s) proven earlier")
        return holder_keys

    proven = holder_keys if holder_keys is not None else ProvenKeys()
    nonces: Dict[str, float] = {}
    pub_keys: List[Dict[str, Any]] = []
    ka_exps: List[int] = []
    _collect_proof_keys(credential_request, session_id, pub_keys, ka_exps, nonces)
    if not pub_keys:
        raise InvalidProofError("No valid proof")
    _consume_nonces(nonces, session_id)
    proven.keys, proven.ka_exps, proven.verified = pub_keys, ka_exps, True
    return proven


def generate_credentials(
    credential_request: Dict[str, Any],
    session_id: str,
    wia_client_status: Optional[Dict[str, Any]] = None,
    holder_keys: Optional[ProvenKeys] = None,
) -> Any:
    """Issues the credential(s) for a validated credential request.

    Every proof is verified (:func:`verify_proof_jwt` / key attestations),
    its ``c_nonce`` is consumed (unless nonces are reusable), and the proven
    holder keys are collected;
    the expiry ceiling is stored in the session, and the credentials are
    formatted and signed with the session's user data
    (:func:`app.services.dynamic_formatter.issue_credentials_for_session`).

    Args:
        credential_request: Validated credential request.
        session_id: Issuance session.
        wia_client_status: ``client_status`` claim of the access token.
        holder_keys: Filled in with the proven keys, so that a deferred
            request can reuse them; when already ``verified`` (the deferred
            request itself) the proofs are not verified again.

    Returns:
        ``{"credentials": [...]}`` or an error dict: ``invalid_proof`` when a
        proof is missing / invalid (signature, ``typ``, ``aud``, ``iat``, key
        attestation) or has no ``c_nonce``, ``invalid_nonce`` for an unknown,
        undecryptable, expired or (when single use) already used ``c_nonce``,
        ``invalid_credential_request`` for too many proofs,
        ``credential_request_denied`` when signing fails.
    """
    configuration_id = credential_request["credential_configuration_id"]

    try:
        proven = _prove_holder_keys(credential_request, session_id, holder_keys)
    except TooManyProofsError as e:
        logger.warning(f", Session ID: {session_id}, Credential request rejected: {safe(e)}")
        return {"error": "invalid_credential_request", "error_description": str(e)}
    except InvalidNonceError as e:
        logger.warning(f", Session ID: {session_id}, Invalid nonce: {safe(e)}")
        return {"error": "invalid_nonce", "error_description": str(e)}
    except InvalidProofError as e:
        logger.warning(f", Session ID: {session_id}, Invalid proof: {safe(e)}")
        return {"error": "invalid_proof", "error_description": str(e)}
    pub_keys, ka_exps = proven.keys, proven.ka_exps

    formatter_request: Dict[str, Any] = {"credential_configuration_id": configuration_id, "proofs": pub_keys}

    if len(pub_keys) > 1:
        session_manager.update_is_batch_credential(session_id=session_id, is_batch_credential=True)

    # TS3 2.4.3: credential validity SHALL end before client_status.exp (WIA)
    # and key_storage_status.exp (KA).
    try:
        max_exp = compute_max_credential_exp(
            wia_client_status_exp=wia_client_status.get("exp") if wia_client_status else None,
            ka_key_storage_status_exp=min(ka_exps) if ka_exps else None,
            custom_validity_seconds=get_custom_validity_seconds(configuration_id),
        )
    except CredentialValidityError as e:
        logger.exception(f", Session ID: {session_id}, {safe(e)}")
        return {"error": "invalid_proof", "error_description": str(e)}

    logger.debug(
        f", Session ID: {session_id}, {len(pub_keys)} holder key(s) from proofs, "
        f"{len(ka_exps)} key attestation expiry value(s), max credential exp={max_exp}"
    )
    if max_exp is not None:
        session_manager.update_max_credential_exp(session_id=session_id, max_credential_exp=max_exp)

    try:
        return issue_credentials_for_session(session_id, formatter_request)
    except Exception:
        logger.exception(f", Session ID: {session_id}, credential creation failed")
        return {"error": "credential_request_denied", "error_description": "The credential could not be issued"}


# ---------------------------------------------------------------------------
# Encryption / nonces
# ---------------------------------------------------------------------------


def decrypt_jwe_credential_request(jwt_token: str) -> Dict[str, Any]:
    """Decrypts a JWE credential request with the issuer encryption key.

    Args:
        jwt_token: Compact JWE (5 parts).

    Returns:
        The decrypted credential request.

    Raises:
        ValueError: If the token is not a JWE, cannot be decrypted, or the
            payload is not JSON.
    """
    if jwt_token.count(".") != 4:
        raise ValueError("Invalid JWE format - expected 5 parts")

    try:
        private_key = jwk.JWK.from_pem(CONFIGURATION["keys"]["credential_encryption_key"])
        jwe_token = jwe.JWE()
        jwe_token.deserialize(jwt_token)
        jwe_token.decrypt(private_key)
        payload = jwe_token.payload.decode("utf-8")
        logger.debug("Decrypted JWE credential request")
        return json.loads(payload)
    except FileNotFoundError as e:
        logger.exception("Private key file not found")
        raise ValueError("Private key file not found") from e
    except json.JSONDecodeError as e:
        logger.exception(f"Failed to parse decrypted payload as JSON: {safe(str(e))}")
        raise ValueError(f"Decrypted payload is not valid JSON: {str(e)}") from e
    except Exception as e:
        logger.exception(f"Failed to decrypt JWE: {safe(str(e))}")
        raise ValueError(f"Failed to decrypt JWE: {str(e)}") from e


def check_response_encryption(encryption: Any) -> None:
    """Validates ``credential_response_encryption`` before anything is signed.

    The values must be those the issuer metadata advertises
    (``credential_response_encryption.alg_values_supported`` /
    ``enc_values_supported``), so a request is refused before credentials
    are created, not after.

    Args:
        encryption: The request's ``credential_response_encryption`` value.

    Raises:
        InvalidEncryptionParametersError: If it is not an object with a public
            ``jwk`` object, a supported ``enc`` and a supported ``alg`` (from
            the object or the ``jwk``).
    """
    advertised = issuer_metadata_template().get("credential_response_encryption") or {}
    if not isinstance(encryption, dict):
        raise InvalidEncryptionParametersError("credential_response_encryption must be an object")
    key = encryption.get("jwk")
    if not isinstance(key, dict) or "d" in key:
        raise InvalidEncryptionParametersError("jwk must be a public JWK object")
    enc = encryption.get("enc")
    if not isinstance(enc, str) or enc not in advertised.get("enc_values_supported", []):
        raise InvalidEncryptionParametersError("enc is not supported")
    alg = encryption.get("alg") or key.get("alg")
    if not isinstance(alg, str) or alg not in advertised.get("alg_values_supported", []):
        raise InvalidEncryptionParametersError("alg is not supported")
    try:
        # Loading the key into cryptography checks it (EC point on the curve, RSA parameters).
        jwk.JWK(**key).export_to_pem()
    except Exception as e:
        raise InvalidEncryptionParametersError("jwk is not a valid key") from e


def encrypt_jwe(payload: Dict[str, Any], key: jwk.JWK, alg: str, enc: str, **header: Any) -> str:
    """Encrypts a JSON payload as a compact JWE.

    Args:
        payload: JSON-serializable payload.
        key: Recipient key (public, or private whose public part is used).
        alg: Key management algorithm (e.g. ``ECDH-ES``, ``RSA-OAEP``).
        enc: Content encryption algorithm (e.g. ``A256GCM``).
        **header: Extra protected header parameters (e.g. ``kid``, ``typ``).

    Returns:
        The compact serialization.

    Raises:
        jwcrypto.common.JWException: If the key / algorithms are unusable.
    """
    protected = {"alg": alg, "enc": enc, **{k: v for k, v in header.items() if v is not None}}
    token = jwe.JWE(json.dumps(payload).encode("utf-8"), protected=json.dumps(protected))
    token.add_recipient(key)
    return token.serialize(compact=True)


def create_c_nonce() -> str:
    """Creates an encrypted ``c_nonce`` JWT bound to the credential endpoint.

    The payload is encrypted to the issuer's own ``nonce_key`` (RSA-OAEP,
    A256GCM), so only the issuer can read it back. Its random ``jti`` lets
    the issuer make the nonce single-use (:func:`_consume_nonces`).

    Returns:
        The compact JWE.
    """
    service_url = CONFIGURATION["service_url"]
    now = int(time.time())
    payload = {
        "iss": service_url,
        "jti": secrets.token_urlsafe(16),
        "iat": now,
        "exp": now + NONCE_LIFETIME_SECONDS,
        "source_endpoint": f"{service_url}/nonce",
        "aud": [f"{service_url}/credential"],
    }
    nonce_key = jwk.JWK.from_pem(CONFIGURATION["keys"]["nonce_key"])
    return encrypt_jwe(payload, nonce_key, alg="RSA-OAEP", enc="A256GCM", typ="cnonce+jwt")
