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
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, List
import threading


class Session:
    """
    A simplified class to represent a request session.
    It includes session management details and optional codes.

    Attributes:
        session_id (str): A unique identifier for this request session.
        expiry_time (datetime): The UTC datetime when this session expires.
        country (Optional[str]): The country code for the session.
        pre_authorized_code (Optional[str]): A pre-authorized code for issuance.
        pre_authorized_code_ref (Optional[str]): A reference for the pre-authorized code.
        jws_token (Optional[str]): A JWS token for the session.
        frontend_id (Optional[str]): A unique identifier for the frontend application.
        scope (Optional[str]): A string representing the requested scope.
        authorization_details (Optional[List[Dict]]): A list of dictionaries of authorization details.
        credentials_requested (Optional[List[Dict]]): A list of dictionaries representing the credentials requested.
        user_data (Optional[Dict]): A dictionary for storing user-specific data.
        tx_code (Optional[int]): A numeric code for the session.
        transaction_id (Optional[Dict[str, Dict]]): A dictionary of transaction IDs for deferred issuance.
        notification_ids (List[str]): A list of notification IDs for the session.
        is_batch_credential (bool): A flag indicating if the session is for a batch credential.
    """

    def __init__(
        self,
        session_id: str,
        expiry_time: datetime,
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
        transaction_id: Optional[Dict[str, Dict]] = None,
        notification_ids: Optional[List[str]] = None,
        is_batch_credential: bool = False,  # Changed to be non-optional with a default value
    ):
        """Initializes a new Session instance."""
        self.session_id = session_id
        self.expiry_time = expiry_time
        self.country = country
        self.pre_authorized_code = pre_authorized_code
        self.pre_authorized_code_ref = pre_authorized_code_ref
        self.jws_token = jws_token
        self.frontend_id = frontend_id
        self.scope = scope
        self.authorization_details = authorization_details
        self.credentials_requested = credentials_requested
        self.user_data = user_data
        self.tx_code = tx_code
        self.transaction_id = transaction_id if transaction_id is not None else {}
        self.notification_ids = notification_ids if notification_ids is not None else []
        self.is_batch_credential = is_batch_credential

    def to_dict(self) -> Dict:
        """Converts the Session object into a dictionary."""
        data = {
            "session_id": self.session_id,
            "expiry_time": self.expiry_time.isoformat(),
            "is_batch_credential": self.is_batch_credential,  # Always include this attribute
        }
        # Add optional attributes if they exist
        if self.country is not None:
            data["country"] = self.country
        if self.pre_authorized_code is not None:
            data["pre_authorized_code"] = self.pre_authorized_code
        if self.pre_authorized_code_ref is not None:
            data["pre_authorized_code_ref"] = self.pre_authorized_code_ref
        if self.jws_token is not None:
            data["jws_token"] = self.jws_token
        if self.frontend_id is not None:
            data["frontend_id"] = self.frontend_id
        if self.scope is not None:
            data["scope"] = self.scope
        if self.authorization_details is not None:
            data["authorization_details"] = self.authorization_details
        if self.credentials_requested is not None:
            data["credentials_requested"] = self.credentials_requested
        if self.user_data is not None:
            data["user_data"] = self.user_data
        if self.tx_code is not None:
            data["tx_code"] = self.tx_code
        if self.transaction_id:
            data["transaction_id"] = self.transaction_id
        if self.notification_ids:
            data["notification_ids"] = self.notification_ids
        return data

    def __repr__(self):
        """Returns a string representation of the Session object."""
        optional_parts = []
        if self.country:
            optional_parts.append(f"country='{self.country}'")
        if self.pre_authorized_code:
            optional_parts.append(f"pre_authorized_code='{self.pre_authorized_code}'")
        if self.pre_authorized_code_ref:
            optional_parts.append(
                f"pre_authorized_code_ref='{self.pre_authorized_code_ref}'"
            )
        if self.jws_token:
            optional_parts.append(f"jws_token='{self.jws_token}'")
        if self.frontend_id:
            optional_parts.append(f"frontend_id='{self.frontend_id}'")
        if self.scope:
            optional_parts.append(f"scope='{self.scope}'")
        if self.authorization_details:
            optional_parts.append(
                f"authorization_details='{self.authorization_details}'"
            )
        if self.credentials_requested:
            optional_parts.append(
                f"credentials_requested='{self.credentials_requested}'"
            )
        if self.user_data:
            optional_parts.append(f"user_data='{self.user_data}'")
        if self.tx_code:
            optional_parts.append(f"tx_code='{self.tx_code}'")
        if self.transaction_id:
            optional_parts.append(f"transaction_id='{self.transaction_id}'")
        if self.notification_ids:
            optional_parts.append(f"notification_ids='{self.notification_ids}'")

        return (
            f"Session(session_id='{self.session_id}', "
            f"is_batch_credential={self.is_batch_credential}, "  # Always include this attribute
            f"expiry_time='{self.expiry_time.isoformat()}'"
            f"{', ' + ', '.join(optional_parts) if optional_parts else ''})"
        )


# --- SessionManager: The thread-safe manager for all request sessions ---
class SessionManager:
    """
    Manages Session objects with fine-grained locking.
    This ensures that multiple threads can safely read and write to different
    parts of the data store concurrently without corrupting data.
    """

    def __init__(self, default_expiry_minutes: int = 15):
        # The primary storage for session objects, keyed by a unique session ID.
        self._sessions: Dict[str, Session] = {}
        # Secondary indexes for fast lookup by different attributes.
        self._sessions_by_preauth_code: Dict[str, Session] = {}
        self._sessions_by_preauth_code_ref: Dict[str, Session] = {}
        self._sessions_by_transaction_id: Dict[str, Session] = {}
        self._sessions_by_notification_id: Dict[str, Session] = {}

        self.default_expiry_minutes = default_expiry_minutes

        # Create a separate lock for each dictionary to enable fine-grained locking.
        self._sessions_lock = threading.Lock()
        self._sessions_by_preauth_code_lock = threading.Lock()
        self._sessions_by_preauth_code_ref_lock = threading.Lock()
        self._sessions_by_transaction_id_lock = threading.Lock()
        self._sessions_by_notification_id_lock = threading.Lock()

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
        is_batch_credential: bool = False,  # Changed to be non-optional with a default value
    ) -> Session:
        """
        Creates and stores a new Session object.
        """
        expiry_time = datetime.now(timezone.utc) + timedelta(
            minutes=self.default_expiry_minutes
        )

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
            print(
                f"Added session with session_id: {session_id} (Expires: {expiry_time.isoformat()})"
            )
        return session_obj

    def update_country(self, session_id: str, country: str):
        """
        Updates the 'country' attribute of a session.
        """
        with self._sessions_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj:
                session_obj.country = country
                print(f"Updated country for session_id {session_id} to: {country}")
            else:
                print(
                    f"Warning: Attempted to update country for non-existent session_id: {session_id}"
                )

    def update_user_data(self, session_id: str, user_data: Dict):
        """
        Updates the 'user_data' dictionary of a session.
        """
        with self._sessions_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj:
                session_obj.user_data = user_data
                print(f"Updated user_data for session_id {session_id}")
            else:
                print(
                    f"Warning: Attempted to update user_data for non-existent session_id: {session_id}"
                )

    def update_authorization_details(
        self, session_id: str, authorization_details: List[Dict]
    ):
        """
        Updates the 'authorization_details' list of a session.
        """
        with self._sessions_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj:
                session_obj.authorization_details = authorization_details
                print(f"Updated authorization_details for session_id {session_id}")
            else:
                print(
                    f"Warning: Attempted to update authorization_details for non-existent session_id: {session_id}"
                )

    def update_credentials_requested(
        self, session_id: str, credentials_requested: List[Dict]
    ):
        """
        Updates the 'credentials_requested' list of a session.
        """
        with self._sessions_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj:
                session_obj.credentials_requested = credentials_requested
                print(f"Updated credentials_requested for session_id {session_id}")
            else:
                print(
                    f"Warning: Attempted to update credentials_requested for non-existent session_id: {session_id}"
                )

    def update_pre_authorized_code(self, session_id: str, pre_authorized_code: str):
        """
        Updates the 'pre_authorized_code' and its lookup index.
        """
        with self._sessions_lock, self._sessions_by_preauth_code_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj:
                if (
                    session_obj.pre_authorized_code
                    and session_obj.pre_authorized_code
                    in self._sessions_by_preauth_code
                ):
                    del self._sessions_by_preauth_code[session_obj.pre_authorized_code]

                session_obj.pre_authorized_code = pre_authorized_code
                self._sessions_by_preauth_code[pre_authorized_code] = session_obj
                print(
                    f"Updated pre_authorized_code for session_id {session_id} to: {pre_authorized_code}"
                )
            else:
                print(
                    f"Warning: Attempted to update pre_authorized_code for non-existent session_id: {session_id}"
                )

    def update_pre_authorized_code_ref(
        self, session_id: str, pre_authorized_code_ref: str
    ):
        """
        Updates the 'pre_authorized_code_ref' and its lookup index.
        """
        with self._sessions_lock, self._sessions_by_preauth_code_ref_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj:
                if (
                    session_obj.pre_authorized_code_ref
                    and session_obj.pre_authorized_code_ref
                    in self._sessions_by_preauth_code_ref
                ):
                    del self._sessions_by_preauth_code_ref[
                        session_obj.pre_authorized_code_ref
                    ]

                session_obj.pre_authorized_code_ref = pre_authorized_code_ref
                self._sessions_by_preauth_code_ref[pre_authorized_code_ref] = (
                    session_obj
                )
                print(
                    f"Updated pre_authorized_code_ref for session_id {session_id} to: {pre_authorized_code_ref}"
                )
            else:
                print(
                    f"Warning: Attempted to update pre_authorized_code_ref for non-existent session_id: {session_id}"
                )

    def update_jws_token(self, session_id: str, jws_token: str):
        """
        Updates the 'jws_token' attribute of a session.
        """
        with self._sessions_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj:
                session_obj.jws_token = jws_token
                print(f"Updated jws_token for session_id {session_id}")
            else:
                print(
                    f"Warning: Attempted to update jws_token for non-existent session_id: {session_id}"
                )

    def update_frontend_id(self, session_id: str, frontend_id: str):
        """
        Updates the 'frontend_id' attribute of a session.
        """
        with self._sessions_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj:
                session_obj.frontend_id = frontend_id
                print(
                    f"Updated frontend_id for session_id {session_id} to: {frontend_id}"
                )
            else:
                print(
                    f"Warning: Attempted to update frontend_id for non-existent session_id: {session_id}"
                )

    def update_tx_code(self, session_id: str, tx_code: int):
        """
        Updates the 'tx_code' attribute of a session.
        """
        with self._sessions_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj:
                session_obj.tx_code = tx_code
                print(f"Updated tx_code for session_id {session_id} to: {tx_code}")
            else:
                print(
                    f"Warning: Attempted to update tx_code for non-existent session_id: {session_id}"
                )

    def update_is_batch_credential(self, session_id: str, is_batch_credential: bool):
        """
        Updates the 'is_batch_credential' attribute of a session.
        """
        with self._sessions_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj:
                session_obj.is_batch_credential = is_batch_credential
                print(
                    f"Updated is_batch_credential for session_id {session_id} to: {is_batch_credential}"
                )
            else:
                print(
                    f"Warning: Attempted to update is_batch_credential for non-existent session_id: {session_id}"
                )

    def add_transaction_id(
        self, session_id: str, transaction_id: str, credential_request: Dict
    ):
        """
        Adds a new transaction ID and its details to an existing session's dictionary.
        This operation requires locking the primary sessions dictionary and the transaction ID index.
        """
        with self._sessions_lock, self._sessions_by_transaction_id_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj:
                session_obj.transaction_id[transaction_id] = credential_request
                self._sessions_by_transaction_id[transaction_id] = session_obj
                print(
                    f"Added transaction_id '{transaction_id}' "
                    f"to session_id '{session_id}'."
                )
            else:
                print(
                    f"Warning: Attempted to add transaction ID for non-existent session_id: {session_id}"
                )

    def store_notification_id(self, session_id: str, notification_id: str):
        """
        Adds a notification ID to an existing session and updates the lookup index.
        """
        with self._sessions_lock, self._sessions_by_notification_id_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj:
                session_obj.notification_ids.append(notification_id)
                self._sessions_by_notification_id[notification_id] = session_obj
                print(
                    f"Added notification_id '{notification_id}' "
                    f"to session_id '{session_id}'."
                )
            else:
                print(
                    f"Warning: Attempted to add notification ID for non-existent session_id: {session_id}"
                )

    def get_session(self, session_id: str) -> Optional[Session]:
        """
        Retrieves a Session object by its session ID.
        """
        with self._sessions_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj and not self.is_expired(session_obj):
                return session_obj
            elif session_obj and self.is_expired(session_obj):
                print(
                    f"Session with session_id {session_id} found but has expired. Removing."
                )
                self._remove_session_from_all_managers(session_obj)
        return None

    def get_session_by_preauth_code(
        self, pre_authorized_code: str
    ) -> Optional[Session]:
        """
        Retrieves a session by its pre-authorized code.
        """
        with self._sessions_by_preauth_code_lock:
            session_obj = self._sessions_by_preauth_code.get(pre_authorized_code)
            if session_obj and not self.is_expired(session_obj):
                return session_obj
            elif session_obj and self.is_expired(session_obj):
                print(
                    f"Session with pre_authorized_code {pre_authorized_code} found but has expired. Removing."
                )
                self._remove_session_from_all_managers(session_obj)
        return None

    def get_session_by_preauth_code_ref(
        self, pre_authorized_code_ref: str
    ) -> Optional[Session]:
        """
        Retrieves a session by its pre-authorized code reference.
        """
        with self._sessions_by_preauth_code_ref_lock:
            session_obj = self._sessions_by_preauth_code_ref.get(
                pre_authorized_code_ref
            )
            if session_obj and not self.is_expired(session_obj):
                return session_obj
            elif session_obj and self.is_expired(session_obj):
                print(
                    f"Session with pre_authorized_code_ref {pre_authorized_code_ref} found but has expired. Removing."
                )
                self._remove_session_from_all_managers(session_obj)
        return None

    def get_session_by_transaction_id(self, transaction_id: str) -> Optional[Session]:
        """
        Retrieves a Session object using its transaction ID.
        """
        with self._sessions_by_transaction_id_lock:
            session_obj = self._sessions_by_transaction_id.get(transaction_id)
            if session_obj and not self.is_expired(session_obj):
                return session_obj
            elif session_obj and self.is_expired(session_obj):
                print(
                    f"Session with transaction_id {transaction_id} found but has expired. Removing."
                )
                self._remove_session_from_all_managers(session_obj)
        return None

    def get_session_by_notification_id(self, notification_id: str) -> Optional[Session]:
        """
        Retrieves a Session object using its notification ID.
        """
        with self._sessions_by_notification_id_lock:
            session_obj = self._sessions_by_notification_id.get(notification_id)
            if session_obj and not self.is_expired(session_obj):
                return session_obj
            elif session_obj and self.is_expired(session_obj):
                print(
                    f"Session with notification_id {notification_id} found but has expired. Removing."
                )
                self._remove_session_from_all_managers(session_obj)
        return None

    def is_expired(self, session_obj: Session) -> bool:
        """
        Checks if a Session object has expired.
        """
        return datetime.now(timezone.utc) >= session_obj.expiry_time

    def _remove_session_from_all_managers(self, session_obj: Session):
        """
        A helper method to remove a session from all internal dictionaries.
        This requires acquiring all locks to ensure a complete, atomic removal.
        """
        with self._sessions_lock, self._sessions_by_preauth_code_lock, self._sessions_by_preauth_code_ref_lock, self._sessions_by_transaction_id_lock, self._sessions_by_notification_id_lock:
            if session_obj.session_id in self._sessions:
                del self._sessions[session_obj.session_id]
            if (
                session_obj.pre_authorized_code
                and session_obj.pre_authorized_code in self._sessions_by_preauth_code
            ):
                del self._sessions_by_preauth_code[session_obj.pre_authorized_code]
            if (
                session_obj.pre_authorized_code_ref
                and session_obj.pre_authorized_code_ref
                in self._sessions_by_preauth_code_ref
            ):
                del self._sessions_by_preauth_code_ref[
                    session_obj.pre_authorized_code_ref
                ]
            for tx_id in list(session_obj.transaction_id.keys()):
                if tx_id in self._sessions_by_transaction_id:
                    del self._sessions_by_transaction_id[tx_id]
            for notif_id in session_obj.notification_ids:
                if notif_id in self._sessions_by_notification_id:
                    del self._sessions_by_notification_id[notif_id]
            print(f"Removed all references for session_id: {session_obj.session_id}")

    def clean_expired_sessions(self):
        """
        Removes all expired Session objects from the manager.
        """
        with self._sessions_lock, self._sessions_by_preauth_code_lock, self._sessions_by_preauth_code_ref_lock, self._sessions_by_transaction_id_lock, self._sessions_by_notification_id_lock:
            expired_session_ids = [
                session_id
                for session_id, session_obj in self._sessions.items()
                if self.is_expired(session_obj)
            ]
            for session_id in expired_session_ids:
                session_obj = self._sessions[session_id]
                print(
                    f"Cleaning up expired session: {session_id} (Pre-auth Code: {session_obj.pre_authorized_code})"
                )
                self._remove_session_from_all_managers(session_obj)

            if expired_session_ids:
                print(f"Cleaned up {len(expired_session_ids)} expired sessions.")
            else:
                print("No expired sessions to clean up.")

    def get_active_sessions_count(self) -> int:
        """
        Returns the number of active sessions.
        """
        with self._sessions_lock:
            return len(self._sessions)
