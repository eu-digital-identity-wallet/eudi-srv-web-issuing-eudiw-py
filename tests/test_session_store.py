###############################################################################
# Copyright (c) 2026 European Commission
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
"""Additional tests for the session store: indexes, client status tree, expiry."""

import datetime
import logging
import threading
from unittest.mock import patch

import pytest

from app.repositories import offer_store
from app.repositories.session_store import Session, SessionManager

PAST = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)


@pytest.fixture(autouse=True)
def _info_logs(caplog):
    """Capture the session store's DEBUG / WARNING messages."""
    caplog.set_level(logging.DEBUG, logger="app.repositories.session_store")


@pytest.fixture
def manager():
    return SessionManager(default_expiry_minutes=5)


def _expire(manager, session_id):
    manager._sessions[session_id].expiry_time = PAST


class TestSession:
    def test_none_collections_are_normalised(self):
        session = Session("s", PAST, transaction_id=None, notification_ids=None)
        assert session.transaction_id == {} and session.notification_ids == []

    def test_to_dict_only_includes_set_fields(self):
        session = Session("s", PAST, country="FC", tx_code=0)
        data = session.to_dict()
        assert data == {
            "session_id": "s",
            "expiry_time": PAST.isoformat(),
            "is_batch_credential": False,
            "country": "FC",
            "tx_code": 0,
        }

    def test_to_dict_includes_non_empty_collections(self):
        session = Session("s", PAST, transaction_id={"t": {}}, notification_ids=["n"])
        assert session.to_dict()["transaction_id"] == {"t": {}}
        assert session.to_dict()["notification_ids"] == ["n"]

    def test_repr_skips_falsy_optionals(self):
        text = repr(Session("s", PAST, country="FC", tx_code=0))
        assert text.startswith("Session(session_id='s'") and "country='FC'" in text and "tx_code" not in text


class TestSetters:
    @pytest.mark.parametrize(
        "method, attribute, value",
        [
            ("update_country", "country", "PT"),
            ("update_user_data", "user_data", {"a": 1}),
            ("update_authorization_details", "authorization_details", [{"type": "x"}]),
            ("update_credentials_requested", "credentials_requested", ["pid"]),
            ("update_jws_token", "jws_token", "jws"),
            ("update_frontend_id", "frontend_id", "fe"),
            ("update_tx_code", "tx_code", 12345),
            ("update_is_batch_credential", "is_batch_credential", True),
            ("update_max_credential_exp", "max_credential_exp", 99),
            ("update_oid4vp_transaction_id", "oid4vp_transaction_id", "tx"),
            ("update_client_status", "client_status", {"exp": 1}),
        ],
    )
    def test_setter_updates_attribute(self, manager, method, attribute, value):
        manager.add_session("s1")
        getattr(manager, method)("s1", value)
        assert getattr(manager.get_session("s1"), attribute) == value

    def test_setter_on_missing_session_is_logged(self, manager, caplog):
        manager.update_country("missing", "PT")
        assert "non-existent session_id: missing" in caplog.text

    def test_indexed_setters_replace_old_index_entry(self, manager):
        manager.add_session("s1")
        manager.update_pre_authorized_code("s1", "code-1")
        manager.update_pre_authorized_code("s1", "code-2")
        manager.update_pre_authorized_code_ref("s1", "ref-1")
        manager.update_pre_authorized_code_ref("s1", "ref-2")

        assert manager.get_session_by_preauth_code("code-1") is None
        assert manager.get_session_by_preauth_code("code-2").session_id == "s1"
        assert manager.get_session_by_preauth_code_ref("ref-1") is None
        assert manager.get_session_by_preauth_code_ref("ref-2").session_id == "s1"

    def test_indexed_setter_on_missing_session(self, manager):
        manager.update_pre_authorized_code("missing", "code")
        assert manager.get_session_by_preauth_code("code") is None

    def test_transaction_and_notification_indexes(self, manager):
        manager.add_session("s1")
        manager.add_transaction_id("s1", "tx-1", {"credential_configuration_id": "pid"})
        manager.store_notification_id("s1", "n-1")

        assert manager.get_session_by_transaction_id("tx-1").transaction_id == {"tx-1": {"credential_configuration_id": "pid"}}
        assert manager.get_session_by_notification_id("n-1").notification_ids == ["n-1"]

    def test_transaction_and_notification_on_missing_session(self, manager):
        manager.add_transaction_id("missing", "tx", {})
        manager.store_notification_id("missing", "n")
        assert manager.get_session_by_transaction_id("tx") is None
        assert manager.get_session_by_notification_id("n") is None


class TestExpiry:
    @pytest.mark.parametrize(
        "lookup, key",
        [
            ("get_session", "s1"),
            ("get_session_by_preauth_code", "code"),
            ("get_session_by_preauth_code_ref", "ref"),
            ("get_session_by_transaction_id", "tx"),
            ("get_session_by_notification_id", "n"),
        ],
    )
    def test_expired_lookup_evicts_from_every_index(self, manager, lookup, key):
        manager.add_session("s1")
        manager.update_pre_authorized_code("s1", "code")
        manager.update_pre_authorized_code_ref("s1", "ref")
        manager.add_transaction_id("s1", "tx", {})
        manager.store_notification_id("s1", "n")
        _expire(manager, "s1")

        assert getattr(manager, lookup)(key) is None
        assert not manager._sessions
        assert not manager._sessions_by_preauth_code and not manager._sessions_by_preauth_code_ref
        assert not manager._sessions_by_transaction_id and not manager._sessions_by_notification_id

    def test_clean_expired_sessions(self, manager, caplog):
        manager.add_session("old")
        manager.add_session("live")
        _expire(manager, "old")

        manager.clean_expired_sessions()

        assert list(manager._sessions) == ["live"]
        assert "Cleaned up 1 expired sessions." in caplog.text

    def test_clean_with_nothing_expired(self, manager, caplog):
        manager.add_session("live")
        manager.clean_expired_sessions()
        assert "No expired sessions to clean up." in caplog.text


class TestClientStatus:
    def test_exp_and_status_create_client_status(self, manager):
        manager.add_session("s1")
        manager.update_client_status_exp("s1", 123)
        manager.update_client_status_status("s1", {"status_list": {"idx": 1}})
        assert manager.get_session("s1").client_status == {"exp": 123, "status": {"status_list": {"idx": 1}}}

    def test_client_status_mutators_on_missing_session(self, manager):
        manager.update_client_status_exp("missing", 1)
        assert manager.add_key_storage_status("missing") is None
        assert manager.add_key_to_key_storage_status("missing", 0, "k") is None
        manager.update_key_storage_status("missing", 0, {})
        manager.update_key_status("missing", 0, 0, {})
        assert manager.update_key_status_by_key("missing", "k", {}) is False

    def test_key_storage_tree(self, manager):
        manager.add_session("s1")
        ka0 = manager.add_key_storage_status("s1", status={"status_list": {"idx": 1}})
        ka1 = manager.add_key_storage_status("s1")
        k0 = manager.add_key_to_key_storage_status("s1", ka0, "key-a")
        k1 = manager.add_key_to_key_storage_status("s1", ka0, "key-b", key_status={"x": 1})
        manager.update_key_storage_status("s1", ka1, {"status_list": {"idx": 2}})
        manager.update_key_status("s1", ka0, k0, {"status_list": {"idx": 9}})

        assert (ka0, ka1, k0, k1) == (0, 1, 0, 1)
        statuses = manager.get_session("s1").client_status["key_storage_statuses"]
        assert statuses == [
            {
                "status": {"status_list": {"idx": 1}},
                "keys": [
                    {"key": "key-a", "key_status": {"status_list": {"idx": 9}}},
                    {"key": "key-b", "key_status": {"x": 1}},
                ],
            },
            {"status": {"status_list": {"idx": 2}}, "keys": []},
        ]

    def test_bad_indexes_are_ignored(self, manager, caplog):
        manager.add_session("s1")
        assert manager.add_key_to_key_storage_status("s1", 0, "k") is None  # no KA yet
        manager.update_key_storage_status("s1", 0, {"x": 1})
        ka = manager.add_key_storage_status("s1")
        manager.update_key_status("s1", ka, 5, {"x": 1})  # no such key
        manager.update_key_status("s1", 7, 0, {"x": 1})  # no such KA

        assert manager.get_session("s1").client_status["key_storage_statuses"] == [{"status": None, "keys": []}]
        assert "key_storage_status index 0 not found" in caplog.text
        assert "key index 5 not found" in caplog.text

    def test_update_key_status_by_key(self, manager):
        manager.add_session("s1")
        assert manager.update_key_status_by_key("s1", "key-a", {}) is False  # no statuses yet
        ka = manager.add_key_storage_status("s1")
        manager.add_key_to_key_storage_status("s1", ka, "key-a")

        assert manager.update_key_status_by_key("s1", "key-a", {"status_list": {"idx": 4}}) is True
        assert manager.update_key_status_by_key("s1", "other", {}) is False
        keys = manager.get_session("s1").client_status["key_storage_statuses"][0]["keys"]
        assert keys == [{"key": "key-a", "key_status": {"status_list": {"idx": 4}}}]

    def test_get_all_client_statuses_skips_expired_and_empty(self, manager):
        for sid in ("with", "without", "expired"):
            manager.add_session(sid)
        manager.update_client_status("with", {"exp": 1})
        manager.update_client_status("expired", {"exp": 2})
        _expire(manager, "expired")

        assert manager.get_all_client_statuses() == {"with": {"exp": 1}}


def test_concurrent_updates_are_consistent(manager):
    for i in range(20):
        manager.add_session(f"s{i}")
        manager.add_key_storage_status(f"s{i}")

    def worker(i):
        for n in range(50):
            manager.add_key_to_key_storage_status(f"s{i}", 0, f"key-{n}")
            manager.store_notification_id(f"s{i}", f"n-{i}-{n}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for i in range(20):
        session = manager.get_session(f"s{i}")
        assert len(session.client_status["key_storage_statuses"][0]["keys"]) == 50
        assert len(session.notification_ids) == 50
    assert len(manager._sessions_by_notification_id) == 1000


class TestOfferStore:
    def test_purge_expired_purges_only_expired(self):
        now = datetime.datetime.now()
        offers = {"old": {"expires": now - datetime.timedelta(seconds=1)}, "live": {"expires": now + datetime.timedelta(minutes=5)}}
        revocations = {"old": {"expires": now - datetime.timedelta(seconds=1)}, "live": {"expires": now + datetime.timedelta(minutes=5)}}

        with patch.dict(offer_store.credential_offer_references, offers, clear=True), patch.dict(
            offer_store.revocation_requests, revocations, clear=True
        ), patch.object(offer_store, "session_manager") as sessions:
            offer_store.purge_expired()
            assert list(offer_store.credential_offer_references) == ["live"]
            assert list(offer_store.revocation_requests) == ["live"]
        sessions.clean_expired_sessions.assert_called_once()
