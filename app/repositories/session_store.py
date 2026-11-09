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
"""Thread-safe, in-memory store for issuance sessions.

A :class:`Session` holds everything the issuer learns during one issuance
flow (country, authorization details, user data, deferred transactions,
client/key attestation status, ...). :class:`SessionManager` stores them in a
primary dictionary plus secondary indexes (pre-authorized code, its
reference, transaction id, notification id), each guarded by its own lock.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional
from app.core.log_utils import safe

logger = logging.getLogger(__name__)

# Session attributes that are always present in ``to_dict`` output.
_ALWAYS_SERIALIZED = ("session_id", "expiry_time", "is_batch_credential")
# Attributes never printed by ``repr`` (codes, tokens, personal data).
_MASKED_IN_REPR = frozenset(
    {
        "pre_authorized_code",
        "pre_authorized_code_ref",
        "tx_code",
        "jws_token",
        "user_data",
        "verified_attributes",
        "oid4vp_nonce",
        "client_status",
        "deferred_holder_keys",
    }
)
# Attributes that are serialized / shown only when non-empty (or true).
_SERIALIZED_WHEN_TRUTHY = ("transaction_id", "notification_ids", "deferred_holder_keys", "credential_issued")


@dataclass(repr=False)
class Session:
    """A single issuance request session.

    Attributes:
        session_id: Unique identifier for this request session.
        expiry_time: UTC datetime at which the session expires.
        country: Country code chosen for the session.
        pre_authorized_code: Pre-authorized code for issuance.
        pre_authorized_code_ref: Reference for the pre-authorized code.
        jws_token: JWS token for the session.
        frontend_id: Identifier of the frontend application.
        scope: Requested OAuth scope.
        authorization_details: Authorization details requested.
        credentials_requested: Credentials requested.
        user_data: User-specific data collected during the flow.
        tx_code: Numeric transaction code (pre-authorized flow).
        transaction_id: Deferred issuance transaction ids -> credential request.
        notification_ids: Notification ids issued in this session.
        is_batch_credential: Whether the session is for a batch credential.
        oid4vp_transaction_id: Same-device OID4VP transaction id.
        oid4vp_cross_device_id: Cross-device (QR code) OID4VP transaction id.
        oid4vp_nonce: Nonce of this session's OID4VP presentation request.
        max_credential_exp: TS3 2.4.3 credential expiry ceiling (epoch seconds).
        client_status: WIA / key attestation status tree.
        verified_attributes: Attributes read from a verified PID presentation;
            the attribute form cannot change them.
        deferred_holder_keys: Deferred transaction id -> holder keys proven by
            the credential request that created it (reused, not re-verified:
            its ``c_nonce`` is spent).
        credential_issued: Whether a credential was issued in this session.
    """

    session_id: str
    expiry_time: datetime
    country: Optional[str] = None
    pre_authorized_code: Optional[str] = None
    pre_authorized_code_ref: Optional[str] = None
    jws_token: Optional[str] = None
    frontend_id: Optional[str] = None
    scope: Optional[str] = None
    authorization_details: Optional[List[Dict]] = None
    credentials_requested: Optional[List[Dict]] = None
    user_data: Optional[Dict] = None
    tx_code: Optional[int] = None
    transaction_id: Dict[str, Dict] = field(default_factory=dict)
    notification_ids: List[str] = field(default_factory=list)
    is_batch_credential: bool = False
    oid4vp_transaction_id: Optional[str] = None
    oid4vp_cross_device_id: Optional[str] = None
    oid4vp_nonce: Optional[str] = None
    max_credential_exp: Optional[int] = None
    client_status: Optional[Dict] = None
    verified_attributes: Optional[Dict[str, Any]] = None
    deferred_holder_keys: Dict[str, Any] = field(default_factory=dict)
    credential_issued: bool = False

    def __post_init__(self) -> None:
        """Normalizes ``None`` collections passed explicitly by callers."""
        if self.transaction_id is None:
            self.transaction_id = {}
        if self.notification_ids is None:
            self.notification_ids = []
        if self.deferred_holder_keys is None:
            self.deferred_holder_keys = {}

    def _optional_items(self) -> List[tuple[str, Any]]:
        """Lists the optional attributes that carry a value.

        Returns:
            ``(name, value)`` pairs in declaration order, skipping ``None``
            values and empty collections.
        """
        items = []
        for f in fields(self):
            if f.name in _ALWAYS_SERIALIZED:
                continue
            value = getattr(self, f.name)
            if f.name in _SERIALIZED_WHEN_TRUTHY and not value:
                continue
            if value is not None:
                items.append((f.name, value))
        return items

    def to_dict(self) -> Dict[str, Any]:
        """Converts the session into a JSON-friendly dictionary.

        Returns:
            Mandatory attributes plus every optional attribute that is set.
        """
        data: Dict[str, Any] = {
            "session_id": self.session_id,
            "expiry_time": self.expiry_time.isoformat(),
            "is_batch_credential": self.is_batch_credential,
        }
        data.update(self._optional_items())
        return data

    def __repr__(self) -> str:
        """Returns a readable representation including the truthy optional fields.

        Secrets and personal data are shown as ``<set>`` only.
        """
        optional_parts = [
            f"{name}=<set>" if name in _MASKED_IN_REPR else f"{name}='{value}'"
            for name, value in self._optional_items()
            if value
        ]
        return (
            f"Session(session_id='{self.session_id}', "
            f"is_batch_credential={self.is_batch_credential}, "
            f"expiry_time='{self.expiry_time.isoformat()}'"
            f"{', ' + ', '.join(optional_parts) if optional_parts else ''})"
        )


class SessionManager:
    """Manages :class:`Session` objects with fine-grained locking.

    Multiple threads can safely read and write to different parts of the
    store concurrently without corrupting data.

    Args:
        default_expiry_minutes: Lifetime given to new sessions.
    """

    def __init__(self, default_expiry_minutes: int = 15) -> None:
        self._sessions: Dict[str, Session] = {}
        self._sessions_by_preauth_code: Dict[str, Session] = {}
        self._sessions_by_preauth_code_ref: Dict[str, Session] = {}
        self._sessions_by_transaction_id: Dict[str, Session] = {}
        self._sessions_by_notification_id: Dict[str, Session] = {}

        self.default_expiry_minutes = default_expiry_minutes

        self._sessions_lock = threading.RLock()
        self._sessions_by_preauth_code_lock = threading.RLock()
        self._sessions_by_preauth_code_ref_lock = threading.RLock()
        self._sessions_by_transaction_id_lock = threading.RLock()
        self._sessions_by_notification_id_lock = threading.RLock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _all_locks(self) -> List[threading.RLock]:
        """Returns every lock in a fixed acquisition order (avoids deadlocks)."""
        return [
            self._sessions_lock,
            self._sessions_by_preauth_code_lock,
            self._sessions_by_preauth_code_ref_lock,
            self._sessions_by_transaction_id_lock,
            self._sessions_by_notification_id_lock,
        ]

    def _set_attribute(self, session_id: str, name: str, value: Any, *, log_value: bool = True) -> None:
        """Sets a single attribute on a stored session under the main lock.

        Args:
            session_id: Target session.
            name: Attribute name on :class:`Session`.
            value: New value.
            log_value: Whether the value may be written to the log.
        """
        with self._sessions_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj is None:
                logger.warning(
                    f"Attempted to update {name} for non-existent session_id: {session_id}"
                )
                return
            setattr(session_obj, name, value)
            suffix = f" to: {safe(value, 100)}" if log_value else ""
            logger.debug(f"Updated {name} for session_id {session_id}{suffix}")

    def _set_indexed_attribute(
        self,
        session_id: str,
        name: str,
        value: str,
        index: Dict[str, Session],
        index_lock: threading.RLock,
    ) -> None:
        """Sets an attribute that is also a secondary lookup key.

        The previous index entry (if any) is removed before the new one is
        registered.

        Args:
            session_id: Target session.
            name: Attribute name on :class:`Session`.
            value: New value, also used as index key.
            index: Secondary index dictionary.
            index_lock: Lock protecting ``index``.
        """
        with self._sessions_lock, index_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj is None:
                logger.warning(
                    f"Attempted to update {name} for non-existent session_id: {session_id}"
                )
                return
            old_value = getattr(session_obj, name)
            if old_value and old_value in index:
                del index[old_value]
            setattr(session_obj, name, value)
            index[value] = session_obj
            logger.debug(f"Updated {name} for session_id {session_id}")

    def _get_live(
        self, index: Dict[str, Session], lock: threading.RLock, key: str, label: str
    ) -> Optional[Session]:
        """Looks a session up in an index, evicting it if expired.

        Args:
            index: Dictionary to look in.
            lock: Lock protecting ``index``.
            key: Lookup key.
            label: Key name used in log messages.

        Returns:
            The session, or ``None`` if missing or expired.
        """
        with lock:
            session_obj = index.get(key)
            if session_obj is None:
                return None
            if not self.is_expired(session_obj):
                return session_obj
            # Only session ids are logged: other index keys (pre-authorized codes) are secrets.
            shown = f" {key}" if label == "session_id" else ""
            logger.debug(f"Session with {label}{shown} found but has expired. Removing.")
            self._remove_session_from_all_managers(session_obj)
        return None

    def _key_storage_statuses(self, session_id: str, action: str) -> Optional[List[Dict]]:
        """Returns the ``key_storage_statuses`` list of a session.

        Must be called with ``_sessions_lock`` held.

        Args:
            session_id: Target session.
            action: Description used in the warning when the session is missing.

        Returns:
            The list (possibly empty / ``None``) or ``None`` if no session.
        """
        session_obj = self._sessions.get(session_id)
        if session_obj is None:
            logger.warning(f"Attempted to {action} for non-existent session_id: {session_id}")
            return None
        return (session_obj.client_status or {}).get("key_storage_statuses")

    def _with_client_status(self, session_id: str, name: str, mutate: Callable[[Dict], None]) -> None:
        """Applies ``mutate`` to the session's client_status (creating it if needed).

        Args:
            session_id: Target session.
            name: Field description used in log messages.
            mutate: Callback receiving the client_status dict.
        """
        with self._sessions_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj is None:
                logger.warning(
                    f"Attempted to update {name} for non-existent session_id: {session_id}"
                )
                return
            if session_obj.client_status is None:
                session_obj.client_status = {}
            mutate(session_obj.client_status)
            logger.debug(f"Updated {name} for session_id {session_id}")

    # ------------------------------------------------------------------
    # Creation
    # ------------------------------------------------------------------

    def add_session(
        self,
        session_id: str,
        country: Optional[str] = None,
        pre_authorized_code: Optional[str] = None,
        pre_authorized_code_ref: Optional[str] = None,
        jws_token: Optional[str] = None,
        frontend_id: Optional[str] = None,
        scope: Optional[str] = None,
        authorization_details: Optional[List[Dict]] = None,
        credentials_requested: Optional[List[Dict]] = None,
        user_data: Optional[Dict] = None,
        tx_code: Optional[int] = None,
        is_batch_credential: bool = False,
    ) -> Session:
        """Creates and stores a new session.

        Args:
            session_id: Unique session identifier.
            country: Country code.
            pre_authorized_code: Pre-authorized code.
            pre_authorized_code_ref: Pre-authorized code reference.
            jws_token: JWS token.
            frontend_id: Frontend identifier.
            scope: Requested scope.
            authorization_details: Authorization details.
            credentials_requested: Credentials requested.
            user_data: User data.
            tx_code: Transaction code.
            is_batch_credential: Batch credential flag.

        Returns:
            The new :class:`Session`.
        """
        expiry_time = datetime.now(timezone.utc) + timedelta(minutes=self.default_expiry_minutes)
        session_obj = Session(
            session_id=session_id,
            expiry_time=expiry_time,
            country=country,
            pre_authorized_code=pre_authorized_code,
            pre_authorized_code_ref=pre_authorized_code_ref,
            jws_token=jws_token,
            frontend_id=frontend_id,
            scope=scope,
            authorization_details=authorization_details,
            credentials_requested=credentials_requested,
            user_data=user_data,
            tx_code=tx_code,
            is_batch_credential=is_batch_credential,
        )
        with self._sessions_lock:
            self._sessions[session_id] = session_obj
            logger.info(
                f"Added session with session_id: {session_id} (Expires: {expiry_time.isoformat()})"
            )
        return session_obj

    # ------------------------------------------------------------------
    # Simple attribute setters
    # ------------------------------------------------------------------

    def update_country(self, session_id: str, country: str) -> None:
        """Updates the session country.

        Args:
            session_id: Target session.
            country: Country code.
        """
        self._set_attribute(session_id, "country", country)

    def update_user_data(self, session_id: str, user_data: Dict) -> None:
        """Replaces the session user data.

        Args:
            session_id: Target session.
            user_data: New user data.
        """
        self._set_attribute(session_id, "user_data", user_data, log_value=False)

    def update_authorization_details(self, session_id: str, authorization_details: List[Dict]) -> None:
        """Replaces the session authorization details.

        Args:
            session_id: Target session.
            authorization_details: New authorization details.
        """
        self._set_attribute(session_id, "authorization_details", authorization_details, log_value=False)

    def update_credentials_requested(self, session_id: str, credentials_requested: List[Dict]) -> None:
        """Replaces the list of credentials requested.

        Args:
            session_id: Target session.
            credentials_requested: New list.
        """
        self._set_attribute(session_id, "credentials_requested", credentials_requested, log_value=False)

    def update_jws_token(self, session_id: str, jws_token: str) -> None:
        """Updates the session JWS token.

        Args:
            session_id: Target session.
            jws_token: New token.
        """
        self._set_attribute(session_id, "jws_token", jws_token, log_value=False)

    def update_frontend_id(self, session_id: str, frontend_id: str) -> None:
        """Updates the session frontend id.

        Args:
            session_id: Target session.
            frontend_id: Frontend identifier.
        """
        self._set_attribute(session_id, "frontend_id", frontend_id)

    def update_tx_code(self, session_id: str, tx_code: int) -> None:
        """Updates the session transaction code.

        Args:
            session_id: Target session.
            tx_code: Transaction code.
        """
        self._set_attribute(session_id, "tx_code", tx_code, log_value=False)

    def update_is_batch_credential(self, session_id: str, is_batch_credential: bool) -> None:
        """Updates the batch credential flag.

        Args:
            session_id: Target session.
            is_batch_credential: New flag value.
        """
        self._set_attribute(session_id, "is_batch_credential", is_batch_credential)

    def mark_credential_issued(self, session_id: str) -> None:
        """Records that a credential was issued in the session.

        Args:
            session_id: Target session.
        """
        self._set_attribute(session_id, "credential_issued", True)

    def update_max_credential_exp(self, session_id: str, max_credential_exp: int) -> None:
        """Updates the TS3 2.4.3 credential expiry ceiling.

        The ceiling is derived from the WIA ``client_status.exp`` and KA
        ``key_storage_status.exp`` seen during the credential request.

        Args:
            session_id: Target session.
            max_credential_exp: Ceiling as epoch seconds.
        """
        self._set_attribute(session_id, "max_credential_exp", max_credential_exp)

    def update_oid4vp_transaction_id(self, session_id: str, oid4vp_transaction_id: str) -> None:
        """Updates the same-device OID4VP transaction id.

        Args:
            session_id: Target session.
            oid4vp_transaction_id: Verifier transaction id.
        """
        self._set_attribute(session_id, "oid4vp_transaction_id", oid4vp_transaction_id)

    def update_oid4vp_presentation(
        self, session_id: str, same_device_id: str, cross_device_id: str, nonce: str
    ) -> None:
        """Records the OID4VP presentation requested for this session.

        Args:
            session_id: Target session.
            same_device_id: Same-device verifier transaction id.
            cross_device_id: Cross-device verifier transaction id.
            nonce: Nonce sent to the verifier.
        """
        with self._sessions_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj is None:
                logger.warning(f"Attempted to update OID4VP presentation for non-existent session_id: {session_id}")
                return
            session_obj.oid4vp_transaction_id = same_device_id
            session_obj.oid4vp_cross_device_id = cross_device_id
            session_obj.oid4vp_nonce = nonce
            logger.debug(f"Updated OID4VP presentation for session_id {session_id}")

    def update_verified_attributes(self, session_id: str, verified_attributes: Dict[str, Any]) -> None:
        """Records the attributes of a verified PID presentation.

        Args:
            session_id: Target session.
            verified_attributes: Attribute name -> verified value.
        """
        self._set_attribute(session_id, "verified_attributes", verified_attributes, log_value=False)

    def update_client_status(self, session_id: str, client_status: Dict) -> None:
        """Replaces the whole ``client_status`` structure.

        Args:
            session_id: Target session.
            client_status: New client status tree.
        """
        self._set_attribute(session_id, "client_status", client_status, log_value=False)

    # ------------------------------------------------------------------
    # Indexed setters
    # ------------------------------------------------------------------

    def update_pre_authorized_code(self, session_id: str, pre_authorized_code: str) -> None:
        """Updates the pre-authorized code and its lookup index.

        Args:
            session_id: Target session.
            pre_authorized_code: New code.
        """
        self._set_indexed_attribute(
            session_id,
            "pre_authorized_code",
            pre_authorized_code,
            self._sessions_by_preauth_code,
            self._sessions_by_preauth_code_lock,
        )

    def update_pre_authorized_code_ref(self, session_id: str, pre_authorized_code_ref: str) -> None:
        """Updates the pre-authorized code reference and its lookup index.

        Args:
            session_id: Target session.
            pre_authorized_code_ref: New reference.
        """
        self._set_indexed_attribute(
            session_id,
            "pre_authorized_code_ref",
            pre_authorized_code_ref,
            self._sessions_by_preauth_code_ref,
            self._sessions_by_preauth_code_ref_lock,
        )

    def add_transaction_id(
        self, session_id: str, transaction_id: str, credential_request: Dict, holder_keys: Any = None
    ) -> None:
        """Registers a deferred-issuance transaction on a session.

        Args:
            session_id: Target session.
            transaction_id: New transaction id.
            credential_request: Credential request to replay when issuing.
            holder_keys: Holder keys proven by that request
                (:class:`app.services.credential_issuance.ProvenKeys`).
        """
        with self._sessions_lock, self._sessions_by_transaction_id_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj is None:
                logger.warning(
                    f"Attempted to add transaction ID for non-existent session_id: {session_id}"
                )
                return
            session_obj.transaction_id[transaction_id] = credential_request
            if holder_keys is not None:
                session_obj.deferred_holder_keys[transaction_id] = holder_keys
            self._sessions_by_transaction_id[transaction_id] = session_obj
            logger.debug(f"Added transaction_id '{transaction_id}' to session_id '{session_id}'.")

    def remove_transaction_id(self, session_id: str, transaction_id: str) -> None:
        """Invalidates a deferred-issuance transaction once its credential is obtained.

        OpenID4VCI 1.0 section 9.1: a later request with the same
        ``transaction_id`` is then an ``invalid_transaction_id``.

        Args:
            session_id: Session the transaction belongs to.
            transaction_id: Transaction id to remove.
        """
        with self._sessions_lock, self._sessions_by_transaction_id_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj is not None:
                session_obj.transaction_id.pop(transaction_id, None)
                session_obj.deferred_holder_keys.pop(transaction_id, None)
            if self._sessions_by_transaction_id.get(transaction_id) is session_obj:
                self._sessions_by_transaction_id.pop(transaction_id, None)
            logger.debug(f"Removed transaction_id '{transaction_id}' from session_id '{session_id}'.")

    def store_notification_id(self, session_id: str, notification_id: str) -> None:
        """Registers a notification id on a session.

        Args:
            session_id: Target session.
            notification_id: New notification id.
        """
        with self._sessions_lock, self._sessions_by_notification_id_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj is None:
                logger.warning(
                    f"Attempted to add notification ID for non-existent session_id: {session_id}"
                )
                return
            session_obj.notification_ids.append(notification_id)
            self._sessions_by_notification_id[notification_id] = session_obj
            logger.debug(f"Added notification_id '{notification_id}' to session_id '{session_id}'.")

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def get_session(self, session_id: str) -> Optional[Session]:
        """Retrieves a live session by id.

        Args:
            session_id: Session id.

        Returns:
            The session, or ``None`` if missing or expired.
        """
        return self._get_live(self._sessions, self._sessions_lock, session_id, "session_id")

    def get_session_by_preauth_code(self, pre_authorized_code: str) -> Optional[Session]:
        """Retrieves a live session by pre-authorized code.

        Args:
            pre_authorized_code: Code to look up.

        Returns:
            The session, or ``None``.
        """
        return self._get_live(
            self._sessions_by_preauth_code,
            self._sessions_by_preauth_code_lock,
            pre_authorized_code,
            "pre_authorized_code",
        )

    def get_session_by_preauth_code_ref(self, pre_authorized_code_ref: str) -> Optional[Session]:
        """Retrieves a live session by pre-authorized code reference.

        Args:
            pre_authorized_code_ref: Reference to look up.

        Returns:
            The session, or ``None``.
        """
        return self._get_live(
            self._sessions_by_preauth_code_ref,
            self._sessions_by_preauth_code_ref_lock,
            pre_authorized_code_ref,
            "pre_authorized_code_ref",
        )

    def get_session_by_transaction_id(self, transaction_id: str) -> Optional[Session]:
        """Retrieves a live session by deferred transaction id.

        Args:
            transaction_id: Transaction id to look up.

        Returns:
            The session, or ``None``.
        """
        return self._get_live(
            self._sessions_by_transaction_id,
            self._sessions_by_transaction_id_lock,
            transaction_id,
            "transaction_id",
        )

    def get_session_by_notification_id(self, notification_id: str) -> Optional[Session]:
        """Retrieves a live session by notification id.

        Args:
            notification_id: Notification id to look up.

        Returns:
            The session, or ``None``.
        """
        return self._get_live(
            self._sessions_by_notification_id,
            self._sessions_by_notification_id_lock,
            notification_id,
            "notification_id",
        )

    # ------------------------------------------------------------------
    # Client status (WIA / key attestation) mutators
    # ------------------------------------------------------------------

    def update_client_status_exp(self, session_id: str, exp: int) -> None:
        """Sets ``client_status['exp']``.

        Args:
            session_id: Target session.
            exp: WIA expiry (epoch seconds).
        """
        self._with_client_status(
            session_id, "client_status.exp", lambda cs: cs.__setitem__("exp", exp)
        )

    def update_client_status_status(self, session_id: str, status: Dict) -> None:
        """Sets ``client_status['status']`` (the WIA status list entry).

        Args:
            session_id: Target session.
            status: Status structure.
        """
        self._with_client_status(
            session_id, "client_status.status", lambda cs: cs.__setitem__("status", status)
        )

    def add_key_storage_status(
        self,
        session_id: str,
        status: Optional[Dict] = None,
        keys: Optional[List[Dict]] = None,
    ) -> Optional[int]:
        """Appends one key attestation entry to ``client_status.key_storage_statuses``.

        Args:
            session_id: Target session.
            status: KA status structure.
            keys: Initial keys of this KA.

        Returns:
            Index of the new entry, or ``None`` if the session does not exist.
        """
        with self._sessions_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj is None:
                logger.warning(
                    f"Attempted to add key_storage_status for non-existent session_id: {session_id}"
                )
                return None
            if session_obj.client_status is None:
                session_obj.client_status = {}
            entries = session_obj.client_status.setdefault("key_storage_statuses", [])
            entries.append({"status": status, "keys": keys if keys is not None else []})
            index = len(entries) - 1
            logger.debug(f"Added key_storage_status at index {index} for session_id {session_id}")
            return index

    def _ka_entry(self, session_id: str, ka_index: int, action: str) -> Optional[Dict]:
        """Returns ``key_storage_statuses[ka_index]`` or ``None``.

        Must be called with ``_sessions_lock`` held.

        Args:
            session_id: Target session.
            ka_index: Entry index.
            action: Description used when the session is missing.

        Returns:
            The KA entry, or ``None`` if session or index is unknown.
        """
        entries = self._key_storage_statuses(session_id, action)
        if session_id not in self._sessions:
            return None
        if not entries or ka_index >= len(entries):
            logger.warning(
                f"key_storage_status index {ka_index} not found for session_id: {session_id}"
            )
            return None
        return entries[ka_index]

    def update_key_storage_status(self, session_id: str, key_storage_status_index: int, status: Dict) -> None:
        """Updates the ``status`` of one key_storage_statuses entry.

        Args:
            session_id: Target session.
            key_storage_status_index: Entry index.
            status: New status.
        """
        with self._sessions_lock:
            entry = self._ka_entry(session_id, key_storage_status_index, "update key_storage_status")
            if entry is None:
                return
            entry["status"] = status
            logger.debug(
                f"Updated key_storage_statuses[{key_storage_status_index}].status for session_id {session_id}"
            )

    def add_key_to_key_storage_status(
        self,
        session_id: str,
        key_storage_status_index: int,
        key: str,
        key_status: Optional[Dict] = None,
    ) -> Optional[int]:
        """Appends ``{'key', 'key_status'}`` to a key_storage_statuses entry.

        Args:
            session_id: Target session.
            key_storage_status_index: Entry index.
            key: Device key (serialized).
            key_status: Optional key status.

        Returns:
            Index of the new key in the entry, or ``None`` if not found.
        """
        with self._sessions_lock:
            entry = self._ka_entry(session_id, key_storage_status_index, "add key")
            if entry is None:
                return None
            keys_list = entry.setdefault("keys", [])
            keys_list.append({"key": key, "key_status": key_status})
            index = len(keys_list) - 1
            logger.debug(
                f"Added key at index {index} to key_storage_statuses[{key_storage_status_index}] "
                f"for session_id {session_id}"
            )
            return index

    def update_key_status(
        self,
        session_id: str,
        key_storage_status_index: int,
        key_index: int,
        key_status: Dict,
    ) -> None:
        """Updates the ``key_status`` of one key, addressed by indexes.

        Args:
            session_id: Target session.
            key_storage_status_index: KA entry index.
            key_index: Key index within the KA entry.
            key_status: New key status.
        """
        with self._sessions_lock:
            entry = self._ka_entry(session_id, key_storage_status_index, "update key_status")
            if entry is None:
                return
            keys_list = entry.get("keys", [])
            if key_index >= len(keys_list):
                logger.warning(
                    f"key index {key_index} not found in "
                    f"key_storage_statuses[{key_storage_status_index}] for session_id: {session_id}"
                )
                return
            keys_list[key_index]["key_status"] = key_status
            logger.debug(
                f"Updated key_status for key {key_index} in "
                f"key_storage_statuses[{key_storage_status_index}] for session_id {session_id}"
            )

    def update_key_status_by_key(self, session_id: str, key: str, key_status: Dict) -> bool:
        """Finds a key anywhere in the session's KA entries and updates its status.

        Args:
            session_id: Target session.
            key: Device key to match.
            key_status: New key status.

        Returns:
            ``True`` if the key was found and updated.
        """
        with self._sessions_lock:
            entries = self._key_storage_statuses(session_id, "update key_status")
            if session_id not in self._sessions:
                return False
            if not entries:
                logger.warning(f"no key_storage_statuses found for session_id: {session_id}")
                return False
            for key_entry in (k for ka in entries for k in ka.get("keys", [])):
                if key_entry.get("key") == key:
                    key_entry["key_status"] = key_status
                    logger.debug(f"Updated key_status for matching key in session_id {session_id}")
                    return True
            logger.warning(f"key not found in key_storage_statuses for session_id: {session_id}")
            return False

    # ------------------------------------------------------------------
    # Expiry / housekeeping
    # ------------------------------------------------------------------

    def is_expired(self, session_obj: Session) -> bool:
        """Checks whether a session has expired.

        Args:
            session_obj: Session to check.

        Returns:
            ``True`` if the expiry time has passed.
        """
        return datetime.now(timezone.utc) >= session_obj.expiry_time

    def _remove_session_from_all_managers(self, session_obj: Session) -> None:
        """Atomically removes a session from the main store and all indexes.

        Args:
            session_obj: Session to remove.
        """
        locks = self._all_locks()
        for lock in locks:
            lock.acquire()
        try:
            self._sessions.pop(session_obj.session_id, None)
            if session_obj.pre_authorized_code:
                self._sessions_by_preauth_code.pop(session_obj.pre_authorized_code, None)
            if session_obj.pre_authorized_code_ref:
                self._sessions_by_preauth_code_ref.pop(session_obj.pre_authorized_code_ref, None)
            for tx_id in list(session_obj.transaction_id):
                self._sessions_by_transaction_id.pop(tx_id, None)
            for notif_id in session_obj.notification_ids:
                self._sessions_by_notification_id.pop(notif_id, None)
            logger.debug(f"Removed all references for session_id: {session_obj.session_id}")
        finally:
            for lock in reversed(locks):
                lock.release()

    def clean_expired_sessions(self) -> None:
        """Removes every expired session from the store."""
        locks = self._all_locks()
        for lock in locks:
            lock.acquire()
        try:
            expired = [s for s in self._sessions.values() if self.is_expired(s)]
            for session_obj in expired:
                logger.debug(f"Cleaning up expired session: {session_obj.session_id}")
                self._remove_session_from_all_managers(session_obj)
            if expired:
                logger.info(f"Cleaned up {len(expired)} expired sessions.")
            else:
                logger.debug("No expired sessions to clean up.")
        finally:
            for lock in reversed(locks):
                lock.release()

    def get_all_client_statuses(self) -> Dict[str, Dict]:
        """Maps session id to client_status for every live session that has one.

        Expired sessions are skipped but not removed (see
        :meth:`clean_expired_sessions`).

        Returns:
            ``{session_id: client_status}``.
        """
        with self._sessions_lock:
            return {
                session_id: s.client_status
                for session_id, s in self._sessions.items()
                if not self.is_expired(s) and s.client_status
            }
