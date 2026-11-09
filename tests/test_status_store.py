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
"""Tests for Postgres status persistence (against an in-memory fake database)."""

from unittest.mock import patch

import pytest

from app.repositories import status_store
from fake_status_db import FakePool

POSTGRES = {"host": "db.test", "port": 6543, "dbname": "issuer", "user": "u", "password": "p"}

CLIENT_STATUS = {
    "status": {"status_list": {"idx": 1, "uri": "https://status.test/wia"}},
    "exp": 1999999999,
    "key_storage_statuses": [
        {
            "status": {"status_list": {"idx": 2, "uri": "https://status.test/ka"}},
            "keys": [
                {
                    "key": "device-key-1",
                    "key_status": {
                        "status_list": {"idx": 10, "uri": "https://status.test/pid"},
                        "identifier_list": {"id": "abc", "uri": "https://status.test/ids"},
                    },
                },
                {"key": "device-key-2", "key_status": None},
            ],
        },
        {"status": None, "keys": []},
    ],
}


@pytest.fixture
def pool():
    """Initialises the module with a fake pool and restores it afterwards."""
    saved = status_store._pool
    with patch.object(status_store, "ConnectionPool", FakePool):
        status_store.init_db_status(POSTGRES)
    yield status_store._pool
    status_store._pool = saved


def test_build_conninfo_default_port():
    config = {k: v for k, v in POSTGRES.items() if k != "port"}
    assert status_store.build_conninfo(config) == "host=db.test port=5432 dbname=issuer user=u password=p"


def test_build_conninfo_missing_key():
    with pytest.raises(KeyError):
        status_store.build_conninfo({"host": "x"})


def test_init_creates_pool_and_tables(pool):
    assert pool.conninfo == "host=db.test port=6543 dbname=issuer user=u password=p"
    assert pool.sizes == (1, 10) and pool.opened is True
    tables = " ".join(pool.db.ddl)
    for table in ("wia_client_status", "ka_key_storage_status", "issued_key_status"):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in tables
    assert pool.db.commits == 1


def test_requires_initialisation():
    saved = status_store._pool
    status_store._pool = None
    try:
        with pytest.raises(RuntimeError, match="init_db_status"):
            status_store.persist_client_status("s1", CLIENT_STATUS)
    finally:
        status_store._pool = saved


def test_to_jsonb():
    assert status_store.to_jsonb(None) is None
    assert status_store.to_jsonb({"a": 1}).obj == {"a": 1}


def test_persist_full_tree(pool):
    status_store.persist_client_status("s1", CLIENT_STATUS)
    db = pool.db

    assert db.wia["s1"] == {"status": CLIENT_STATUS["status"], "exp": 1999999999}
    ka_rows = sorted(db.ka.values(), key=lambda r: r["ka_index"])
    assert [(r["session_id"], r["ka_index"], r["status"]) for r in ka_rows] == [
        ("s1", 0, CLIENT_STATUS["key_storage_statuses"][0]["status"]),
        ("s1", 1, None),
    ]
    first_ka_id = next(ka_id for ka_id, r in db.ka.items() if r["ka_index"] == 0)
    key1 = db.keys[(first_ka_id, "device-key-1")]
    assert key1["status_list"] == {"idx": 10, "uri": "https://status.test/pid"}
    assert key1["identifier_list"] == {"id": "abc", "uri": "https://status.test/ids"}
    assert db.keys[(first_ka_id, "device-key-2")] == {"session_id": "s1", "identifier_list": None, "status_list": None}
    assert db.commits == 2  # table creation + this upsert


def test_persist_is_an_upsert(pool):
    status_store.persist_client_status("s1", CLIENT_STATUS)
    updated = {**CLIENT_STATUS, "exp": 2000000000, "key_storage_statuses": CLIENT_STATUS["key_storage_statuses"][:1]}

    status_store.persist_client_status("s1", updated)

    assert pool.db.wia["s1"]["exp"] == 2000000000
    assert len(pool.db.ka) == 2  # same (session, ka_index) rows are updated, not duplicated
    assert len(pool.db.keys) == 2


def test_empty_status_is_a_noop(pool):
    status_store.persist_client_status("s1", {})
    status_store.persist_client_status("s1", None)
    assert pool.db.wia == {} and pool.db.commits == 1


def test_database_error_is_logged_and_raised(pool, caplog):
    def boom(*args, **kwargs):
        raise ConnectionError("db down")

    with patch.object(pool.db, "cursor", boom):
        with pytest.raises(ConnectionError):
            status_store.persist_client_status("s1", CLIENT_STATUS)
    assert "Failed to persist client_status for session_id s1" in caplog.text


class TestIssuedStatusEntries:
    """Batch siblings of a presented status entry (#167)."""

    @staticmethod
    def _entry(idx, identifier=None):
        status = {"status_list": {"idx": idx, "uri": "https://status.test/pid"}}
        if identifier:
            status["identifier_list"] = {"id": identifier, "uri": "https://status.test/ids"}
        return status

    def test_table_created(self, pool):
        assert "CREATE TABLE IF NOT EXISTS issued_status_entry" in " ".join(pool.db.ddl)

    def test_siblings_of_presented_entry(self, pool):
        for idx in range(3):
            status_store.record_issued_status("s1", "pid", self._entry(idx, f"id{idx}"))
        status_store.record_issued_status("s1", "mdl", self._entry(50))  # other credential type
        status_store.record_issued_status("s2", "pid", self._entry(99))  # other session

        siblings = status_store.batch_status_entries(self._entry(1))

        assert sorted(s["status_list"]["idx"] for s in siblings) == [0, 1, 2]
        assert {s["identifier_list"]["id"] for s in siblings} == {"id0", "id1", "id2"}

    def test_lookup_by_identifier_bytes_from_mso(self, pool):
        status_store.record_issued_status("s1", "pid", {"identifier_list": {"id": "abc", "uri": "https://status.test/ids"}})
        status_store.record_issued_status("s1", "pid", {"identifier_list": {"id": "def", "uri": "https://status.test/ids"}})

        siblings = status_store.batch_status_entries({"identifier_list": {"id": b"abc", "uri": "https://status.test/ids"}})

        assert sorted(s["identifier_list"]["id"] for s in siblings) == ["abc", "def"]
        assert all("status_list" not in s for s in siblings)

    def test_unknown_entry(self, pool):
        assert status_store.batch_status_entries(self._entry(7)) == []
        assert status_store.batch_status_entries({}) == []

    def test_no_session_is_not_recorded(self, pool):
        status_store.record_issued_status(None, "pid", self._entry(1))
        assert pool.db.entries == []

    def test_database_unavailable_is_best_effort(self):
        saved = status_store._pool
        status_store._pool = None
        try:
            status_store.record_issued_status("s1", "pid", self._entry(1))  # does not raise
            assert status_store.batch_status_entries(self._entry(1)) == []
        finally:
            status_store._pool = saved
