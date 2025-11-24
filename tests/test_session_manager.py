# tests/test_session_manager.py
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
import pytest
from datetime import datetime, timedelta, timezone
from app.session_manager import Session, SessionManager

# Assuming Session and SessionManager are correctly imported


# -------------------------------
# Test the Session class
# -------------------------------
class TestSession:
    # Fixture for a base expiry time
    @pytest.fixture
    def expiry_time(self):
        return datetime.now(timezone.utc) + timedelta(minutes=5)

    def test_init_required_only(self, expiry_time):
        """Test initialization with only required fields."""
        session = Session(session_id="123", expiry_time=expiry_time)
        assert session.session_id == "123"
        assert session.expiry_time == expiry_time
        assert session.is_batch_credential is False
        assert session.transaction_id == {}
        assert session.notification_ids == []

    def test_init_all_attributes(self, expiry_time):
        """Test initialization and to_dict method with all optional fields."""
        session = Session(
            session_id="123",
            expiry_time=expiry_time,
            country="US",
            pre_authorized_code="code1",
            pre_authorized_code_ref="ref1",
            jws_token="token",
            frontend_id="frontend",
            scope="scope1",
            authorization_details=[{"auth": "val"}],
            credentials_requested=[{"cred": "val"}],
            user_data={"user": "data"},
            tx_code=42,
            transaction_id={"tx": {}},
            notification_ids=["notif1"],
            is_batch_credential=True,
            oid4vp_transaction_id="oid123",
        )
        data = session.to_dict()
        assert data["country"] == "US"
        assert data["is_batch_credential"] is True
        assert data["transaction_id"] == {"tx": {}}
        assert data["notification_ids"] == ["notif1"]
        assert session.__repr__().startswith("Session(session_id='123'")


# -------------------------------
# Test adding, retrieving, and updating sessions
# -------------------------------
class TestSessionManagerCore:
    @pytest.fixture
    def manager(self):
        # Default expiry minutes set to 1 for easier testing of expiration if needed
        return SessionManager(default_expiry_minutes=1)

    def test_add_and_get_session(self, manager):
        """Test adding a session with minimal fields and retrieval by ID."""
        session = manager.add_session(session_id="s1")
        assert session.session_id == "s1"
        assert manager.get_session("s1") is session
        assert manager.get_active_sessions_count() == 1

    def test_add_session_all_attributes(self, manager):
        """Test adding a session with all optional fields."""
        session = manager.add_session(
            session_id="s2",
            country="US",
            pre_authorized_code="code2",
            is_batch_credential=True,
        )
        assert session.country == "US"
        assert session.pre_authorized_code == "code2"
        assert session.is_batch_credential is True

    def test_update_all_session_fields(self, manager):
        """Test updating various fields of an existing session."""
        session_id = "s3"
        session = manager.add_session(session_id=session_id)

        # Test attribute updates
        manager.update_country(session_id, "FR")
        manager.update_user_data(session_id, {"key": "val"})
        manager.update_authorization_details(session_id, [{"auth": "val"}])
        manager.update_credentials_requested(session_id, [{"cred": "val"}])
        manager.update_pre_authorized_code(session_id, "code5")
        manager.update_pre_authorized_code_ref(session_id, "ref5")
        manager.update_jws_token(session_id, "token6")
        manager.update_frontend_id(session_id, "front6")
        manager.update_tx_code(session_id, 101)
        manager.update_is_batch_credential(session_id, True)
        manager.update_oid4vp_transaction_id(session_id, "oid6")

        # Assertions
        assert session.country == "FR"
        assert session.user_data == {"key": "val"}
        assert session.authorization_details == [{"auth": "val"}]
        assert session.credentials_requested == [{"cred": "val"}]
        assert session.pre_authorized_code == "code5"
        assert session.pre_authorized_code_ref == "ref5"
        assert session.jws_token == "token6"
        assert session.frontend_id == "front6"
        assert session.tx_code == 101
        assert session.is_batch_credential is True
        assert session.oid4vp_transaction_id == "oid6"


# -------------------------------
# Test transaction, notification, and indexed lookup methods
# -------------------------------
class TestSessionManagerLookup:
    @pytest.fixture
    def manager(self):
        return SessionManager()

    def test_indexed_lookups(self, manager):
        """
        Test adding codes/IDs and retrieving sessions via those indexed values.
        """
        session = manager.add_session(session_id="s1")

        # Add indexed values
        manager.update_pre_authorized_code("s1", "codeX")
        manager.update_pre_authorized_code_ref("s1", "refX")
        manager.add_transaction_id("s1", "txX", {"cred": "val"})
        manager.store_notification_id("s1", "notifX")

        # Test lookups
        assert manager.get_session_by_preauth_code("codeX") is session
        assert manager.get_session_by_preauth_code_ref("refX") is session
        assert manager.get_session_by_transaction_id("txX") is session
        assert manager.get_session_by_notification_id("notifX") is session

        # Check session data updates
        assert session.transaction_id["txX"] == {"cred": "val"}
        assert "notifX" in session.notification_ids

    def test_nonexistent_lookups(self, manager):
        """Test retrieving sessions with non-existent codes/IDs returns None."""
        assert manager.get_session_by_preauth_code("nonexistent_code") is None
        assert manager.get_session_by_transaction_id("nonexistent_tx") is None


# -------------------------------
# Test expiration and cleanup logic
# -------------------------------
class TestSessionManagerExpirationAndCleanup:
    def test_get_session_expired_removal(self):
        """
        Test that retrieving an expired session returns None and triggers
        the full removal from all indexes.
        """
        manager = SessionManager()
        # Add session with all indexed fields
        session_id = "s_exp_1"
        session = manager.add_session(session_id)
        session.pre_authorized_code = "code_rem"
        session.pre_authorized_code_ref = "ref_rem"
        manager.add_transaction_id(session_id, "tx_rem", {})
        manager.store_notification_id(session_id, "notif_rem")

        # Expire the session
        session.expiry_time = datetime.now(timezone.utc) - timedelta(seconds=1)

        # Retrieval by session ID triggers cleanup
        assert manager.get_session(session_id) is None

        # Check all indexed lookups also return None (meaning they were cleaned up)
        assert manager.get_session_by_preauth_code("code_rem") is None
        assert manager.get_session_by_transaction_id("tx_rem") is None
        assert manager.get_session_by_notification_id("notif_rem") is None

        # Confirm session is fully removed from internal dicts
        assert session_id not in manager._sessions
        assert "code_rem" not in manager._sessions_by_preauth_code
        assert "tx_rem" not in manager._sessions_by_transaction_id

    def test_clean_expired_sessions_method(self):
        """
        Test the explicit clean_expired_sessions method.
        """
        manager = SessionManager()
        s1 = manager.add_session("expired_s1")
        s2 = manager.add_session("active_s2")

        # Expire s1
        s1.expiry_time = datetime.now(timezone.utc) - timedelta(seconds=1)
        # s2 is active by default

        manager.clean_expired_sessions()

        # s1 removed, s2 still exists
        assert manager.get_session("expired_s1") is None
        assert manager.get_session("active_s2") is s2
        assert manager.get_active_sessions_count() == 1


# -------------------------------
# Test edge cases and non-existent sessions (warning paths)
# -------------------------------
class TestSessionManagerEdgeCases:
    @pytest.fixture
    def manager(self):
        return SessionManager()

    def test_update_methods_nonexistent_session(self, manager):
        """
        Test that update methods on a non-existent session do not fail.
        These are expected to trigger warnings/logs in a real application.
        """
        nonexistent_id = "no_sess"
        # Test various update methods (should execute without error)
        manager.update_country(nonexistent_id, "XX")
        manager.update_user_data(nonexistent_id, {"a": 1})
        manager.update_pre_authorized_code(nonexistent_id, "codeX")
        manager.add_transaction_id(nonexistent_id, "txX", {})
        manager.store_notification_id(nonexistent_id, "notifX")
        manager.update_jws_token(nonexistent_id, "jwt")

        # Retrieval should still be None
        assert manager.get_session(nonexistent_id) is None

    def test_removal_with_empty_indices(self, manager):
        """
        Test session removal when it has no indexed values (codes, tx/notif IDs).
        Ensures the removal logic handles None/empty values correctly.
        """
        session_id = "s_empty"
        s = manager.add_session(session_id)
        # Ensure indexed fields are explicitly empty/None
        s.pre_authorized_code = None
        s.pre_authorized_code_ref = None
        s.transaction_id = {}
        s.notification_ids = []

        # Expire session to trigger _remove_session_from_all_managers
        s.expiry_time = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert manager.get_session(session_id) is None

        # Confirm all internal dicts are empty/cleared after removal
        assert not manager._sessions
        assert not manager._sessions_by_preauth_code
        assert not manager._sessions_by_transaction_id
