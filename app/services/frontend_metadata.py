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
"""Per-frontend issuer metadata (unsigned and signed).

Each frontend (``frontend.frontends_config.<frontend_id>``) publishes its own
credential issuer metadata. This module builds it from the frontend
templates in ``metadata_config/`` and the backend's public metadata
(:data:`app.core.state.oidc_metadata_clean`), exactly as the frontend used to
do at start-up:

* ``credential_configurations_supported`` and ``credential_request_encryption``
  come from the backend metadata, the former optionally filtered by the
  frontend's ``credentials_supported`` list;
* template URLs point to the backend (``service_url``);
* ``credential_issuer`` and the display logo point to the frontend's own URL;
* ``authorization_servers`` names the frontend's own issuer at the
  authorization server, ``<authorization_server.base_url>/<frontend_id>``
  (OpenID4VCI 1.0 section 12.2.4): wallets read that server's metadata
  there, and the path tells it which frontend a request belongs to;
* ``issuer_info`` carries the frontend's own registration certificate;
* the SD-JWT VC issuer metadata (``/.well-known/jwt-vc-issuer``) has the
  frontend URL as ``issuer`` (the ``iss`` of the SD-JWT VCs it issues) and
  the public keys of the country ``_default`` certificates that sign them.

Per-frontend configuration keys:
    url (required): Public URL of the frontend (the credential issuer identifier).
    credentials_supported (optional): List of configuration ids, or ``"*"`` /
        absent for all.
    registration_certificate_path (optional): Text file holding the
        frontend's registration certificate (``rc-wrp+jwt``), published as
        ``issuer_info`` in the unsigned and signed metadata.
"""

from __future__ import annotations

import copy
import json
import logging
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, Optional

from app.core.config import CONFIGURATION
from app.core.state import oidc_metadata_clean
from app.services.metadata import METADATA_DIR, replace_domain, sign_issuer_metadata
from app.utils.crypto import ec_signing_jwk_from_cert
from app.utils.frontend import frontend_config

logger = logging.getLogger(__name__)

TEMPLATE_DIR = METADATA_DIR
_COPIED_BACKEND_FIELDS = ("credential_request_encryption",)


class UnknownFrontendError(KeyError):
    """Raised when a frontend id is not configured."""


@dataclass(frozen=True)
class FrontendMetadata:
    """The metadata documents a frontend publishes.

    Attributes:
        openid_credential_issuer: ``/.well-known/openid-credential-issuer``.
        jwt_vc_issuer: ``/.well-known/jwt-vc-issuer`` (SD-JWT VC issuer metadata).
    """

    openid_credential_issuer: Dict[str, Any]
    jwt_vc_issuer: Dict[str, Any]

    def to_dict(self) -> Dict[str, Dict[str, Any]]:
        """Returns the documents keyed by attribute name."""
        return asdict(self)


@lru_cache(maxsize=None)
def _load_template(name: str, template_dir: Path = TEMPLATE_DIR) -> Dict[str, Any]:
    """Loads (once) a frontend metadata template.

    Args:
        name: File name in ``template_dir``.
        template_dir: Template directory.

    Returns:
        The parsed template (never mutate; it is cached).
    """
    with open(template_dir / name, encoding="utf-8") as f:
        return json.load(f)


def _template(name: str) -> Dict[str, Any]:
    """Returns a private copy of a frontend template.

    Args:
        name: Template file name.

    Returns:
        A deep copy safe to modify.
    """
    return copy.deepcopy(_load_template(name))


def issuer_metadata_template() -> Dict[str, Any]:
    """Returns the credential issuer metadata template shared by all frontends.

    Returns:
        A private copy of ``metadata_config.json`` (``batch_credential_issuance``,
        ``credential_response_encryption``...).
    """
    return _template("metadata_config.json")


def _frontend(frontend_id: str) -> Dict[str, Any]:
    """Returns the configuration of a frontend.

    Args:
        frontend_id: Frontend identifier.

    Returns:
        ``frontend.frontends_config[frontend_id]``.

    Raises:
        UnknownFrontendError: If the frontend is not configured.
    """
    if not frontend_id or frontend_id not in CONFIGURATION.get("frontend", {}).get("frontends_config", {}):
        raise UnknownFrontendError(frontend_id)
    return frontend_config(frontend_id)


def _supported_credentials(allowed: Optional[Any]) -> Dict[str, Any]:
    """Returns the backend credential configurations, filtered for a frontend.

    Args:
        allowed: The frontend's ``credentials_supported`` (list, ``"*"`` or ``None``).

    Returns:
        A copy of the (filtered) ``credential_configurations_supported``.
    """
    credentials = copy.deepcopy(oidc_metadata_clean.get("credential_configurations_supported", {}))
    allowed_ids = _allowed_ids(allowed)
    if allowed_ids is None:
        return credentials
    return {cid: cfg for cid, cfg in credentials.items() if cid in allowed_ids}


def _allowed_ids(allowed: Optional[Any]) -> Optional[FrozenSet[str]]:
    """Normalizes a frontend's ``credentials_supported`` setting.

    Args:
        allowed: The frontend's ``credentials_supported`` (list, ``"*"`` or ``None``).

    Returns:
        The allowed configuration ids, or ``None`` for all.
    """
    if not allowed or allowed == "*" or allowed == ["*"]:
        return None
    return frozenset(allowed)


def frontend_publishes(frontend_id: Optional[str]) -> Callable[[str], bool]:
    """Tells which backend credential configurations a frontend publishes.

    Applies the same filter as the frontend's (unsigned and signed)
    ``credential_configurations_supported``.

    Args:
        frontend_id: Frontend identifier; the default frontend when falsy.

    Returns:
        A predicate on configuration ids; ``True`` when the frontend's
        metadata lists that (backend-supported) configuration.

    Raises:
        UnknownFrontendError: If the frontend is not configured.
    """
    allowed_ids = _allowed_ids(_frontend(frontend_id or CONFIGURATION["frontend"]["default"]).get("credentials_supported"))
    return lambda cid: allowed_ids is None or cid in allowed_ids


def _sd_jwt_signing_jwks() -> Dict[str, Any]:
    """Returns the JWKS of the keys that sign SD-JWT VCs.

    SD-JWT VCs are signed with the ``_default`` key of the issuing country
    (:func:`app.services.formatters.sdjwtFormatter`), whatever the frontend,
    so every country's ``_default`` certificate is published. Certificates
    shared between countries are listed once.

    Returns:
        ``{"keys": [...]}`` (see :func:`app.utils.crypto.ec_signing_jwk_from_cert`).
    """
    keys = []
    seen = set()
    for country_code, country in (CONFIGURATION.get("countries") or {}).items():
        cert_der = (country.get("keys") or {}).get("_default", {}).get("certificate")
        if not cert_der:
            continue
        try:
            jwk = ec_signing_jwk_from_cert(cert_der)
        except ValueError as e:
            logger.warning("jwt-vc-issuer: skipping the %s signing certificate: %s", country_code, e)
            continue
        if jwk["kid"] not in seen:
            seen.add(jwk["kid"])
            keys.append(jwk)
    return {"keys": keys}


def authorization_server_issuer(frontend_id: str) -> str:
    """The frontend's issuer at the authorization server.

    Args:
        frontend_id: Frontend identifier.

    Returns:
        ``<authorization_server.base_url>/<frontend_id>``.
    """
    return f"{CONFIGURATION['authorization_server']['base_url'].rstrip('/')}/{frontend_id}"


def build_frontend_metadata(frontend_id: str) -> FrontendMetadata:
    """Builds the unsigned metadata documents of a frontend.

    Args:
        frontend_id: Frontend identifier.

    Returns:
        The frontend's metadata documents.

    Raises:
        UnknownFrontendError: If the frontend is not configured.
    """
    frontend = _frontend(frontend_id)
    frontend_url = frontend["url"]
    backend_url = CONFIGURATION["service_url"]

    issuer_metadata = _template("metadata_config.json")
    issuer_metadata["credential_configurations_supported"] = _supported_credentials(
        frontend.get("credentials_supported")
    )
    for field in _COPIED_BACKEND_FIELDS:
        if field in oidc_metadata_clean:
            issuer_metadata[field] = copy.deepcopy(oidc_metadata_clean[field])

    template_domain = issuer_metadata["credential_issuer"]
    issuer_metadata = replace_domain(issuer_metadata, template_domain, backend_url)

    issuer_metadata["credential_issuer"] = frontend_url
    issuer_metadata["authorization_servers"] = [authorization_server_issuer(frontend_id)]
    issuer_metadata["display"][0]["logo"]["uri"] = f"{frontend_url}/ic-logo.png"
    if frontend.get("registration_certificate"):
        issuer_metadata["issuer_info"] = [
            {"format": "registration_cert", "data": frontend["registration_certificate"]}
        ]

    return FrontendMetadata(
        openid_credential_issuer=issuer_metadata,
        # Must be identical to the iss of the SD-JWT VCs (formatters.credential_issuer_url).
        jwt_vc_issuer={"issuer": frontend_url, "jwks": _sd_jwt_signing_jwks()},
    )


def sign_frontend_metadata(frontend_id: str) -> str:
    """Builds and signs the credential issuer metadata of a frontend.

    The JWT is signed with the frontend's metadata signing key; ``iss`` and
    ``sub`` are the frontend URL (OpenID4VCI 12.2.3).

    Args:
        frontend_id: Frontend identifier.

    Returns:
        The signed metadata JWT.

    Raises:
        UnknownFrontendError: If the frontend is not configured.
        MetadataSigningError: If the key / certificate cannot be loaded.
    """
    metadata = build_frontend_metadata(frontend_id).openid_credential_issuer
    return sign_issuer_metadata(metadata, frontend_id, iss=frontend_config(frontend_id)["url"])
