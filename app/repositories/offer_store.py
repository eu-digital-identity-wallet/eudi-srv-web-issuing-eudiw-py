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
"""In-memory stores for short-lived credential offer and revocation requests.

Entries are dictionaries holding at least an ``expires`` :class:`datetime`
and are purged by :func:`purge_expired`, which the scheduler runs every
``expiry.cleanup_interval`` minutes.

Attributes:
    credential_offer_references: Credential offers referenced by
        ``credential_offer_uri`` (``reference_id -> {credential_offer, expires}``).
    revocation_requests: Pending revocation requests
        (``revocation_identifier -> {status_lists, expires}``).
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict

from app.core.state import session_manager

logger = logging.getLogger(__name__)

credential_offer_references: Dict[str, Dict[str, Any]] = {}
revocation_requests: Dict[str, Dict[str, Any]] = {}


def _purge_expired(store: Dict[str, Dict[str, Any]], label: str) -> None:
    """Removes entries whose ``expires`` timestamp is in the past.

    Args:
        store: Dictionary to purge in place.
        label: Entry kind, used in log messages.
    """
    now = datetime.now()
    # list() snapshots the items so request threads may insert meanwhile.
    for entry_id in [k for k, v in list(store.items()) if now > v["expires"]]:
        logger.debug(f"Removing expired {label} reference id: {entry_id}")
        store.pop(entry_id, None)


def purge_expired() -> None:
    """Purges expired offers, revocation requests and sessions."""
    _purge_expired(credential_offer_references, "credential")
    _purge_expired(revocation_requests, "revocation")
    session_manager.clean_expired_sessions()
