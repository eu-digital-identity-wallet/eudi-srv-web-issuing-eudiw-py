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
"""Thread-safe, in-memory record of consumed ``c_nonce`` values.

By default a ``c_nonce`` is accepted by one credential request only
(``proof_validation.single_use_nonce: false`` turns this off and the store is
not consulted). The nonce's ``jti`` is recorded until the nonce expires,
after which the nonce is rejected anyway and the record can go. Like the
session store, the record lives in the process: deployments with several
workers need sticky routing.

Attributes:
    used_nonces: The process-wide store.
"""

from __future__ import annotations

import threading
import time
from typing import Dict, Mapping


class UsedNonceStore:
    """Remembers consumed nonce identifiers until they expire."""

    def __init__(self) -> None:
        self._expiry_by_id: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _purge_expired(self, now: float) -> None:
        """Drops records of nonces that have expired. Call with the lock held.

        Args:
            now: Current epoch seconds.
        """
        for nonce_id in [k for k, exp in self._expiry_by_id.items() if exp < now]:
            del self._expiry_by_id[nonce_id]

    def consume_all(self, nonces: Mapping[str, float]) -> bool:
        """Marks nonces as used, all or none.

        Args:
            nonces: Nonce identifier (``jti``) -> expiry (epoch seconds).

        Returns:
            ``True`` when none of them was used before (all are now
            recorded), ``False`` when one was (nothing is recorded).
        """
        with self._lock:
            now = time.time()
            self._purge_expired(now)
            if any(nonce_id in self._expiry_by_id for nonce_id in nonces):
                return False
            self._expiry_by_id.update(nonces)
            return True

    def clear(self) -> None:
        """Forgets every record (tests)."""
        with self._lock:
            self._expiry_by_id.clear()

    def __len__(self) -> int:
        """Returns the number of recorded nonces (expired ones included until purged)."""
        with self._lock:
            return len(self._expiry_by_id)


used_nonces = UsedNonceStore()
