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
"""
This manages necessary data and it's removal

"""

import json
import threading
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from app_config.config_service import ConfService as cfgservice
import requests


parRequests = {}
transaction_codes = {}
deferredRequests = {}
oid4vp_requests = {}
form_dynamic_data = {}
session_ids = {}
credential_offer_references = {}
revocation_requests = {}


def getSessionId_requestUri(target_request_uri):
    matching_session_id = None
    for session_id, session_data in session_ids.items():

        if (
            "request_uri" in session_data
            and session_data["request_uri"] == target_request_uri
        ):
            matching_session_id = session_id
            break

    return matching_session_id


def getSessionId_authCode(target_authCode):
    matching_session_id = None
    for session_id, session_data in session_ids.items():
        if "auth_code" in session_data and session_data["auth_code"] == target_authCode:
            matching_session_id = session_id
            break

    return matching_session_id


def getSessionId_accessToken(target_accessToken):
    matching_session_id = None
    for session_id, session_data in session_ids.items():
        if (
            "access_token" in session_data
            and session_data["access_token"] == target_accessToken
        ):
            matching_session_id = session_id
            break

    return matching_session_id


################################################
## To be moved to a file with scheduled jobs

scheduler_call = 30  # scheduled periodic job will be called every scheduler_call seconds (should be 300; 30 for debug)


def clear_par():
    """Function to clear parRequests"""
    now = int(datetime.timestamp(datetime.now()))
    # print("Job scheduled: clear_par() at " + str(now))
    # print("Job scheduled: clear_par() at " + str(now))

    for uri in parRequests.copy():
        expire_time = parRequests[uri]["expires"]
        if now > expire_time:
            parRequests.pop(uri)
            """ print(
                "Job scheduled: clear_par: "
                + uri
                + " eliminated. "
                + str(now)
                + " > "
                + str(expire_time)
            )
        else:
            print(
                "Job scheduled: clear_par: "
                + uri
                + " not eliminated. "
                + str(now)
                + " < "
                + str(expire_time)
            ) """

    """ for req in deferredRequests.copy():
            
            if datetime.now() > deferredRequests[req]["expires"]:
                deferredRequests.pop(req)
            else:
                request_data = json.loads(deferredRequests[req]["data"])
                print("\ndata: ", request_data)
                request_data.update({"transaction_id": req})
                print("\ntransaction_id: ", req)
                request_data = json.dumps(request_data)
                print("\ndata2: ", request_data)
                request_headers = deferredRequests[req]["headers"]
                print("\nheaders: ", request_headers)

                response = requests.post(cfgservice.service_url+"credential", data=request_data, headers=request_headers)
                print("\nresponse", response.text)
                response_data = response.json()

                if response.status_code == 200:
                    if "credentials" in response_data or "encrypted_response" in response_data and not "decrypted_transaction_id" in response_data:
                        deferredRequests.pop(req) """

    for code in transaction_codes.copy():
        if datetime.now() > transaction_codes[code]["expires"]:
            # cfgservice.logger_info.info("Current transaction_codes:\n" + str(transaction_codes))
            cfgservice.app_logger.info("Removing tx_code for code: " + str(code))
            transaction_codes.pop(code)

    for id in oid4vp_requests.copy():
        if datetime.now() > oid4vp_requests[id]["expires"]:
            # cfgservice.logger_info.info("Current oid4vp_requests:\n" + str(oid4vp_requests))
            cfgservice.app_logger.info("Removing oid4vp_requests with id: " + str(id))
            oid4vp_requests.pop(id)

    for id in session_ids.copy():
        if datetime.now() > session_ids[id]["expires"]:
            cfgservice.app_logger.info("Removing session id: " + str(id))
            session_ids.pop(id)

    for id in form_dynamic_data.copy():
        if datetime.now() > form_dynamic_data[id]["expires"]:
            cfgservice.app_logger.info("Removing form id: " + str(id))
            form_dynamic_data.pop(id)

    for id in credential_offer_references.copy():
        if datetime.now() > credential_offer_references[id]["expires"]:
            cfgservice.app_logger.info("Removing credential reference id: " + str(id))
            credential_offer_references.pop(id)

    for id in revocation_requests.copy():
        if datetime.now() > revocation_requests[id]["expires"]:
            cfgservice.app_logger.info("Removing revpcatopm reference id: " + str(id))
            revocation_requests.pop(id)


def run_scheduler():
    # print("Run scheduler.")
    threading.Timer(scheduler_call, run_scheduler).start()
    clear_par()


run_scheduler()


# --- Session: The data model for a single request session ---
# This class is a simple data container, holding the state for a single session.
# It does not perform any multi-threaded operations and therefore does not need any locks.
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
        scope (Optional[str]): A string representing the requested scope.
        authorization_details (Optional[List[Dict]]): A list of dictionaries of authorization details.
        credentials_requested (Optional[List[Dict]]): A list of dictionaries representing the credentials requested.
        user_data (Optional[Dict]): A dictionary for storing user-specific data.
        tx_code (Optional[int]): A numeric code for the session.
    """

    def __init__(
        self,
        session_id: str,
        expiry_time: datetime,
        country: Optional[str] = None,
        pre_authorized_code: Optional[str] = None,
        pre_authorized_code_ref: Optional[str] = None,
        jws_token: Optional[str] = None,
        scope: Optional[str] = None,
        authorization_details: Optional[List[Dict]] = None,
        credentials_requested: Optional[List[Dict]] = None,
        user_data: Optional[Dict] = None,
        tx_code: Optional[int] = None,
    ):
        """Initializes a new Session instance."""
        self.session_id = session_id
        self.expiry_time = expiry_time
        self.country = country
        self.pre_authorized_code = pre_authorized_code
        self.pre_authorized_code_ref = pre_authorized_code_ref
        self.jws_token = jws_token
        self.scope = scope
        self.authorization_details = authorization_details
        self.credentials_requested = credentials_requested
        self.user_data = user_data
        self.tx_code = tx_code

    def to_dict(self) -> Dict:
        """Converts the Session object into a dictionary."""
        data = {
            "session_id": self.session_id,
            "expiry_time": self.expiry_time.isoformat(),
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

        return (
            f"Session(session_id='{self.session_id}', "
            f"{', '.join(optional_parts)}, "
            f"expiry_time='{self.expiry_time.isoformat()}')"
        )


# --- SessionManager: The thread-safe manager for all request sessions ---
# This class manages the state for multiple in-flight requests. Because it is
# accessed by different threads simultaneously, it must be thread-safe.
# This implementation achieves thread safety using fine-grained locking.
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

        self.default_expiry_minutes = default_expiry_minutes

        # Create a separate lock for each dictionary to enable fine-grained locking.
        self._sessions_lock = threading.Lock()
        self._sessions_by_preauth_code_lock = threading.Lock()
        self._sessions_by_preauth_code_ref_lock = threading.Lock()

    def add_session(
        self,
        session_id: str,
        country: Optional[str] = None,
        pre_authorized_code: Optional[str] = None,
        pre_authorized_code_ref: Optional[str] = None,
        jws_token: Optional[str] = None,
        scope: Optional[str] = None,
        authorization_details: Optional[List[Dict]] = None,
        credentials_requested: Optional[List[Dict]] = None,
        user_data: Optional[Dict] = None,
        tx_code: Optional[int] = None,
    ) -> Session:
        """
        Creates and stores a new Session object.

        Args:
            session_id (str): A unique identifier for this request session.
            country (Optional[str]): The country code for the session.
            pre_authorized_code (Optional[str]): A pre-authorized code for issuance.
            pre_authorized_code_ref (Optional[str]): A reference for the pre-authorized code.
            jws_token (Optional[str]): A JWS token for the session.
            scope (Optional[str]): A string representing the requested scope.
            authorization_details (Optional[List[Dict]]): A list of authorization details.
            credentials_requested (Optional[List[Dict]]): A list of credentials requested.
            user_data (Optional[Dict]): A dictionary for storing user-specific data.
            tx_code (Optional[int]): A numeric code for the session.

        Returns:
            Session: The newly created Session object.
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
            scope=scope,
            authorization_details=authorization_details,
            credentials_requested=credentials_requested,
            user_data=user_data,
            tx_code=tx_code,
        )

        # Acquire lock only for the primary _sessions dictionary.
        with self._sessions_lock:
            self._sessions[session_id] = session_obj
            print(
                f"Added session with session_id: {session_id} (Expires: {expiry_time.isoformat()})"
            )
        return session_obj

    def update_country(self, session_id: str, country: str):
        """
        Updates the 'country' attribute of a session.
        Only the primary dictionary needs to be locked.
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
        Only the primary dictionary needs to be locked.
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
        Only the primary dictionary needs to be locked.
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
        Only the primary dictionary needs to be locked.
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
        Requires locking both the primary and the pre-authorized code dictionaries.
        """
        with self._sessions_lock, self._sessions_by_preauth_code_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj:
                # Remove old code mapping if it exists to prevent stale data
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
        Requires locking both the primary and the pre-authorized code reference dictionaries.
        """
        with self._sessions_lock, self._sessions_by_preauth_code_ref_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj:
                # Remove old code reference mapping if it exists to prevent stale data
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
        Only the primary dictionary needs to be locked.
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

    def update_tx_code(self, session_id: str, tx_code: int):
        """
        Updates the 'tx_code' attribute of a session.
        Only the primary dictionary needs to be locked.
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

    def get_session(self, session_id: str) -> Optional[Session]:
        """
        Retrieves a Session object by its session ID.
        Locks the primary dictionary for a safe read.
        """
        with self._sessions_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj and not self.is_expired(session_obj):
                return session_obj
            elif session_obj and self.is_expired(session_obj):
                print(
                    f"Session with session_id {session_id} found but has expired. Removing."
                )
                # If a session is expired, we need to clean it up from all managers.
                # This requires acquiring all locks to ensure a complete, atomic removal.
                self._remove_session_from_all_managers(session_obj)
        return None

    def get_session_by_preauth_code(
        self, pre_authorized_code: str
    ) -> Optional[Session]:
        """
        Retrieves a session by its pre-authorized code.
        Locks the pre-auth code index.
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
        Locks the pre-auth code reference index.
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

    def is_expired(self, session_obj: Session) -> bool:
        """
        Checks if a Session object has expired.
        This method does not modify any shared state and therefore does not need a lock.
        """
        return datetime.now(timezone.utc) >= session_obj.expiry_time

    def _remove_session_from_all_managers(self, session_obj: Session):
        """
        A helper method to remove a session from all internal dictionaries.
        This critical operation requires acquiring all locks to ensure a complete
        and atomic removal, preventing partial state corruption.
        """
        with self._sessions_lock, self._sessions_by_preauth_code_lock, self._sessions_by_preauth_code_ref_lock:
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
            print(f"Removed all references for session_id: {session_obj.session_id}")

    def clean_expired_sessions(self):
        """
        Removes all expired Session objects from the manager.
        This operation modifies all dictionaries, so it must acquire all locks
        to ensure thread safety during the cleanup process.
        """
        # A single nested `with` statement safely acquires and releases all locks
        # for this complex, multi-dictionary operation.
        with self._sessions_lock, self._sessions_by_preauth_code_lock, self._sessions_by_preauth_code_ref_lock:
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
        Only needs to lock the primary sessions dictionary for a safe read.
        """
        with self._sessions_lock:
            return len(self._sessions)