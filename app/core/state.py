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
"""Process-wide shared state.

The dictionaries below are created once and **mutated in place** by
:mod:`app.services.metadata` at start-up. Because they are never rebound,
``from app.core.state import oidc_metadata`` is safe in any module regardless
of import order.

Attributes:
    oidc_metadata: ``{"credential_configurations_supported": ...}`` with the
        full configurations, including issuer-only keys (``issuer_config``...).
    oidc_metadata_clean: Public view: configurations without issuer-only keys
        plus ``credential_request_encryption``. Source of the per-frontend
        metadata.
    trusted_CAs: Trusted CAs, keyed by the CA certificate subject (i.e. the
        issuer name of the certificates they sign).
    trusted_CAs_by_purpose: Purpose (``key_attestation``, ``offer_request``,
        ``pid_signer``) -> CA store like :data:`trusted_CAs`, only for the
        purposes with their own ``trusted_CAs_paths`` folder; the others use
        :data:`trusted_CAs`.
    session_manager: Singleton in-memory session store.
"""

from __future__ import annotations

from typing import Any

from app.core.config import CONFIGURATION
from app.repositories.session_store import SessionManager

oidc_metadata: dict[str, Any] = {}
oidc_metadata_clean: dict[str, Any] = {}
trusted_CAs: dict[Any, dict[str, Any]] = {}
trusted_CAs_by_purpose: dict[str, dict[Any, dict[str, Any]]] = {}

session_manager = SessionManager(default_expiry_minutes=CONFIGURATION["expiry"]["session"])


def replace_contents(target: dict[Any, Any], new: dict[Any, Any]) -> None:
    """Replaces the contents of a shared dictionary without rebinding it.

    Args:
        target: The shared dictionary to update.
        new: The new contents.
    """
    target.clear()
    target.update(new)
