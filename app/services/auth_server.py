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
"""Client for the OAuth authorization server and the status-list validator."""

from __future__ import annotations

import json
import logging
import threading
from typing import Any, Dict, List, Optional

import jwt
import requests

from app.core.config import CONFIGURATION
from app.core.log_utils import safe
from app.utils.http import DEFAULT_TIMEOUT

logger = logging.getLogger(__name__)

_FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}

#: Status-list validator context for wallet / key storage status lists.
WALLET_STATUS_CONTEXT = "WalletOrKeyStorageStatus"

#: ``aud`` of the session token the authorization server hands to ``/auth_choice``.
SESSION_TOKEN_AUDIENCE = "eudiw-issuer-backend"
SESSION_TOKEN_ALGORITHMS = ["ES256"]
#: Algorithms of the authorization server's signed access tokens.
ACCESS_TOKEN_ALGORITHMS = ["ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]

_jwk_clients: Dict[str, jwt.PyJWKClient] = {}
_jwk_clients_lock = threading.Lock()


class SessionTokenError(ValueError):
    """Raised when the session token from the authorization server is invalid."""


def authorization_server_url() -> str:
    """Returns the base URL used to reach the authorization server.

    The ``internal_url`` (e.g. inside a container network) takes precedence
    over the public ``base_url``.

    Returns:
        Base URL without trailing slash.
    """
    auth_server = CONFIGURATION["authorization_server"]
    return auth_server.get("internal_url") or auth_server["base_url"]


def introspect(bearer_token: str) -> requests.Response:
    """Calls the authorization server's token introspection endpoint.

    Args:
        bearer_token: Access token to introspect.

    Returns:
        The HTTP response.

    Raises:
        requests.RequestException: On network errors.
    """
    api_key = CONFIGURATION["authorization_server"].get("api_key")
    return requests.request(
        "POST",
        f"{authorization_server_url()}/introspection",
        headers={**_FORM_HEADERS, "X-Api-Key": str(api_key or "")},
        data={"token": bearer_token},
        timeout=DEFAULT_TIMEOUT,
    )


def generate_preauth_code(scope: str, frontend_id: str) -> Dict[str, Any]:
    """Asks the authorization server for a pre-authorized code.

    Args:
        scope: Space separated credential configuration ids.
        frontend_id: Frontend whose offer it is: the wallet redeems the code
            at that frontend's issuer.

    Returns:
        JSON with ``preauth_code``, ``session_id`` and ``tx_code``.

    Raises:
        requests.RequestException: On network errors.
    """
    api_key = CONFIGURATION["authorization_server"].get("api_key")
    response = requests.request(
        "POST",
        f"{authorization_server_url()}/preauth_generate",
        headers={**_FORM_HEADERS, "X-Api-Key": str(api_key or "")},
        data={"scope": scope, "frontend_id": frontend_id},
        timeout=DEFAULT_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def _jwks_uri() -> str:
    """Returns where the authorization server publishes its signing keys.

    Returns:
        ``authorization_server.jwks_uri``, by default ``<base>/static/jwks.json``.
    """
    return CONFIGURATION["authorization_server"].get("jwks_uri") or f"{authorization_server_url()}/static/jwks.json"


def _verification_keys(token: str) -> List[Any]:
    """Lists the authorization server keys that may have signed ``token``.

    Keys come from ``authorization_server.jwks_path`` (a local JWKS file: every
    signing key is a candidate) when set, otherwise from the cached JWKS at
    :func:`_jwks_uri` (the key named by the token's ``kid``).

    Args:
        token: Compact JWT.

    Returns:
        Candidate verification keys.
    """
    jwks_path = CONFIGURATION["authorization_server"].get("jwks_path")
    if jwks_path:
        with open(jwks_path, encoding="utf-8") as f:
            key_set = jwt.PyJWKSet.from_dict(json.load(f))
        return [k.key for k in key_set.keys if k.public_key_use in (None, "sig")]
    uri = _jwks_uri()
    with _jwk_clients_lock:
        client = _jwk_clients.get(uri)
        if client is None:
            client = _jwk_clients[uri] = jwt.PyJWKClient(uri, cache_keys=True, lifespan=300, timeout=10)
    return [client.get_signing_key_from_jwt(token).key]


def decode_authorization_server_jwt(token: str, algorithms: List[str], **decode_args: Any) -> Dict[str, Any]:
    """Verifies a JWT signed by the authorization server and returns its claims.

    Args:
        token: Compact JWT.
        algorithms: Accepted signature algorithms.
        **decode_args: Further :func:`jwt.decode` arguments (audience, issuer, options...).

    Returns:
        The verified claims.

    Raises:
        jwt.PyJWTError: If no authorization server key verifies the token or
            a claim check fails.
    """
    last_error: Exception = jwt.InvalidSignatureError("No authorization server key")
    for key in _verification_keys(token):
        try:
            return jwt.decode(token, key, algorithms=algorithms, **decode_args)
        except jwt.InvalidSignatureError as e:
            last_error = e
        except jwt.InvalidAlgorithmError as e:
            last_error = e
    raise last_error


def verify_session_token(token: Optional[str]) -> Dict[str, Any]:
    """Verifies the signed session hand-off from the authorization server.

    Args:
        token: ``session_token`` query parameter of ``/auth_choice``.

    Returns:
        The claims: ``session_id`` and optionally ``scope``,
        ``authorization_details`` and ``frontend_id``.

    Raises:
        SessionTokenError: If the token is missing, not signed by the
            authorization server, expired or for another audience.
    """
    if not token:
        raise SessionTokenError("Missing session_token")
    issuer = CONFIGURATION["authorization_server"].get("issuer")
    try:
        claims = decode_authorization_server_jwt(
            token,
            SESSION_TOKEN_ALGORITHMS,
            audience=SESSION_TOKEN_AUDIENCE,
            issuer=issuer,
            leeway=30,
            options={"require": ["exp", "iat", "session_id"] + (["iss"] if issuer else [])},
        )
    except (jwt.PyJWTError, OSError, ValueError) as e:
        raise SessionTokenError(f"Invalid session_token: {e}") from e
    if not isinstance(claims.get("session_id"), str) or not claims["session_id"]:
        raise SessionTokenError("Invalid session_token: no session_id")
    return claims


def authorization_details_claim(value: Any) -> List[Any]:
    """Normalizes the ``authorization_details`` claim of a session token.

    The authorization server forwards the wallet's value, which is a JSON
    list or a (possibly double-encoded) JSON string.

    Args:
        value: Claim value.

    Returns:
        The authorization details list.

    Raises:
        SessionTokenError: If the value is not a list once decoded.
    """
    for _ in range(3):
        if not isinstance(value, str):
            break
        try:
            value = json.loads(value)
        except json.JSONDecodeError as e:
            raise SessionTokenError("Invalid authorization_details") from e
    if value is None:
        return []
    if not isinstance(value, list):
        raise SessionTokenError("Invalid authorization_details")
    return value


class StatusCheckError(Exception):
    """Raised when the status-list validator cannot give a verdict.

    Covers network errors, ``400`` (bad request / index out of range),
    ``403`` (status list token signer rejected by the trust validator),
    ``502`` (status list unreachable or its JWT invalid) and malformed answers.
    """


def status_validation_context() -> str:
    """Returns the ``validation_context`` sent to the status-list validator.

    WIA (``client_status``) and key attestation (``key_storage_status``)
    status lists are signed by the wallet provider, hence the default
    ``WalletOrKeyStorageStatus`` (overridable with
    ``status_validator.validation_context``).

    Returns:
        The validation context.
    """
    return (CONFIGURATION.get("status_validator") or {}).get("validation_context", WALLET_STATUS_CONTEXT)


def check_status_list_revocation(
    url: str,
    status_idx: int,
    status_uri: str,
    timeout: int = 10,
    validation_context: Optional[str] = None,
) -> bool:
    """Checks a WIA / KA status list entry with the status-list validator.

    Uses the validator's single-check mode (``POST /status`` with ``idx``,
    ``uri`` and ``validation_context``).

    Args:
        url: Validator ``/status`` endpoint.
        status_idx: Status list index.
        status_uri: Status list token URI.
        timeout: Request timeout in seconds.
        validation_context: Trust validator context for the status list
            signer; defaults to :func:`status_validation_context`.

    Returns:
        ``True`` if the entry is revoked (``valid`` is ``False``),
        ``False`` if it is valid.

    Raises:
        StatusCheckError: If the validator is unreachable, answers an error
            (its ``error`` message is included) or returns no ``valid`` flag.
    """
    try:
        response = requests.post(
            url,
            json={
                "idx": status_idx,
                "uri": status_uri,
                "validation_context": validation_context or status_validation_context(),
            },
            headers={"accept": "application/json", "Content-Type": "application/json"},
            timeout=timeout,
        )
    except requests.RequestException as e:
        raise StatusCheckError(f"Status validator unreachable: {e}") from e

    try:
        data = response.json()
    except ValueError:
        data = {}

    if response.status_code != 200:
        raise StatusCheckError(f"Status validator HTTP {response.status_code}: {data.get('error', response.text)}")

    logger.debug(f"Status validator response for {safe(status_uri, 300)} idx={status_idx}: {safe(data, 300)}")
    valid = data.get("valid")
    if not isinstance(valid, bool):
        raise StatusCheckError(f"Status validator returned no 'valid' flag: {data}")
    return valid is False
