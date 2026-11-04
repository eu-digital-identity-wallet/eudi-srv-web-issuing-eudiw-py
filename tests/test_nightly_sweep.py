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
"""Tests for the nightly revocation sweep and its scheduler (fake database)."""

import datetime
from unittest.mock import MagicMock, patch

import pytest

from app.repositories import offer_store
from app.services import nightly_sweep, scheduler
from config_helpers import patch_configuration
from fake_status_db import FakeStatusDB

WIA = {"status_list": {"idx": 1, "uri": "https://status.test/wia"}}
KA_A = {"status_list": {"idx": 2, "uri": "https://status.test/ka"}}
KA_B = {"status_list": {"idx": 3, "uri": "https://status.test/ka"}}


def _key(name, idx):
    return {"device_key": name, "status_list": {"idx": idx, "uri": "https://status.test/pid"}}


@pytest.fixture
def config():
    with patch_configuration(
        {
            "postgres": {"host": "db", "dbname": "issuer", "user": "u", "password": "p"},
            "status_validator": {"enabled": True, "url": "https://validator.test/status"},
            "revocation": {"enabled": True, "set_url": "https://revocation.test/set", "api_key": "k"},
        }
    ) as cfg:
        yield cfg


@pytest.fixture
def db():
    database = FakeStatusDB()
    database.add_session("s1", WIA, 100, kas=[(KA_A, [_key("k1", 10), _key("k2", 11)]), (KA_B, [_key("k3", 12)])])
    database.add_session("s2", None, None, kas=[(KA_A, [_key("k4", 13)])])
    return database


def test_get_connection_uses_postgres_config(config):
    with patch("app.services.nightly_sweep.psycopg.connect") as connect:
        nightly_sweep.get_connection()
    connect.assert_called_once_with("host=db port=5432 dbname=issuer user=u password=p")


def test_iter_session_ids_uses_server_side_cursor(db):
    cursors = []
    original = db.cursor

    def tracking_cursor(name=None):
        cursor = original(name)
        cursors.append(cursor)
        return cursor

    db.cursor = tracking_cursor
    assert list(nightly_sweep.iter_session_ids(db)) == ["s1", "s2"]
    assert cursors[0].name == "session_id_cursor" and cursors[0].itersize == 500


def test_load_session_status_tree(db):
    tree = nightly_sweep.load_session_status_tree(db, "s1")

    assert tree["wia"] == {"status": WIA, "exp": 100}
    assert [ka["ka_index"] for ka in tree["key_storage_statuses"]] == [0, 1]
    assert [k["device_key"] for k in tree["key_storage_statuses"][0]["keys"]] == ["k1", "k2"]
    assert [k["device_key"] for k in tree["key_storage_statuses"][1]["keys"]] == ["k3"]


def test_load_unknown_session(db):
    assert nightly_sweep.load_session_status_tree(db, "missing") == {
        "wia": {"status": None, "exp": None},
        "key_storage_statuses": [],
    }


class TestRevocation:
    def test_revoke_key_flips_status_list_bit(self, config):
        with patch("app.services.nightly_sweep.set_token_status") as set_status:
            nightly_sweep._revoke_key(_key("k1", 10))
        set_status.assert_called_once_with("idx", 10, "https://status.test/pid", status=1)

    @pytest.mark.parametrize("bad", [{"device_key": "k"}, {"device_key": "k", "status_list": {"idx": 1}}])
    def test_revoke_key_malformed(self, config, bad, caplog):
        with patch("app.services.nightly_sweep.set_token_status") as set_status:
            nightly_sweep._revoke_key(bad)
        set_status.assert_not_called()
        assert "missing/malformed status_list" in caplog.text

    def test_revoke_wia_session_revokes_every_key(self, db):
        tree = nightly_sweep.load_session_status_tree(db, "s1")
        with patch("app.services.nightly_sweep.set_token_status") as set_status:
            nightly_sweep.revoke_wia_session("s1", tree)
        assert sorted(c.args[1] for c in set_status.call_args_list) == [10, 11, 12]

    def test_revoke_ka_keys_only_that_ka(self, db):
        tree = nightly_sweep.load_session_status_tree(db, "s1")
        with patch("app.services.nightly_sweep.set_token_status") as set_status:
            nightly_sweep.revoke_ka_keys("s1", tree["key_storage_statuses"][1])
        assert [c.args[1] for c in set_status.call_args_list] == [12]

    def test_extract_status_list_pointer(self):
        assert nightly_sweep._extract_status_list_pointer(WIA) == WIA["status_list"]
        assert nightly_sweep._extract_status_list_pointer(None) is None
        assert nightly_sweep._extract_status_list_pointer({"status_list": {"uri": "x"}}) is None


class TestRunSweep:
    def _run(self, db, batch_results):
        """Runs the sweep; ``batch_results`` maps session id -> validator results."""
        calls = []

        def check(entries):
            session = "s1" if len(calls) == 0 else "s2"
            calls.append((session, entries))
            return batch_results[session]

        with patch("app.services.nightly_sweep.get_connection", return_value=db), patch(
            "app.services.nightly_sweep.check_statuses_batch", side_effect=check
        ), patch("app.services.nightly_sweep.set_token_status") as set_status:
            nightly_sweep.run_sweep()
        revoked = sorted(c.args[1] for c in set_status.call_args_list)
        return calls, revoked

    def test_nothing_revoked(self, config, db):
        calls, revoked = self._run(db, {"s1": [{"valid": True}] * 3, "s2": [{"valid": True}]})

        assert revoked == []
        assert calls[0][1] == [WIA, KA_A, KA_B]  # WIA first, then KAs
        assert calls[1][1] == [KA_A]  # no WIA status for s2
        assert db.closed

    def test_wia_revoked_revokes_everything_and_skips_kas(self, config, db):
        _, revoked = self._run(db, {"s1": [{"valid": False}, {"valid": True}, {"valid": True}], "s2": [{"valid": True}]})
        assert revoked == [10, 11, 12]

    def test_ka_revoked_revokes_only_its_keys(self, config, db):
        _, revoked = self._run(db, {"s1": [{"valid": True}, {"valid": True}, {"valid": False}], "s2": [{"valid": False}]})
        assert revoked == [12, 13]

    def test_validator_errors_do_not_revoke(self, config, db):
        _, revoked = self._run(db, {"s1": [{"error": "request_failed"}] * 3, "s2": [None]})
        assert revoked == []

    def test_failure_is_logged_raised_and_connection_closed(self, config, db, caplog):
        with patch("app.services.nightly_sweep.get_connection", return_value=db), patch(
            "app.services.nightly_sweep.check_statuses_batch", side_effect=RuntimeError("validator exploded")
        ):
            with pytest.raises(RuntimeError):
                nightly_sweep.run_sweep()
        assert db.closed
        assert "Nightly status sweep failed" in caplog.text


class TestScheduler:
    @pytest.fixture(autouse=True)
    def _reset(self):
        saved = scheduler._scheduler
        scheduler._scheduler = None
        yield
        scheduler._scheduler = saved

    def test_starts_once_with_nightly_job_and_purge(self):
        instance = MagicMock()
        with patch("app.services.scheduler.BackgroundScheduler", return_value=instance) as cls, patch(
            "app.services.scheduler.atexit.register"
        ) as register, patch.dict(scheduler.CONFIGURATION, {"expiry": {"session": 30}}):
            first = scheduler.start_scheduler()
            second = scheduler.start_scheduler()

        assert first is second is instance
        cls.assert_called_once()
        instance.start.assert_called_once()
        register.assert_called_once_with(instance.shutdown, wait=False)
        jobs = {call.kwargs["id"]: call for call in instance.add_job.call_args_list}
        assert set(jobs) == {"nightly_status_sweep", "purge_expired"}

        nightly = jobs["nightly_status_sweep"]
        assert nightly.args[0] is nightly_sweep.run_sweep
        assert (nightly.kwargs["max_instances"], nightly.kwargs["coalesce"]) == (1, True)
        trigger = str(nightly.kwargs["trigger"])
        assert "hour='2'" in trigger and "minute='0'" in trigger

        purge = jobs["purge_expired"]
        assert purge.args[0] is offer_store.purge_expired
        assert (purge.kwargs["max_instances"], purge.kwargs["coalesce"]) == (1, True)
        assert purge.kwargs["trigger"].interval == datetime.timedelta(minutes=scheduler.DEFAULT_CLEANUP_INTERVAL)

    def test_purge_interval_comes_from_config(self):
        instance = MagicMock()
        with patch("app.services.scheduler.BackgroundScheduler", return_value=instance), patch(
            "app.services.scheduler.atexit.register"
        ), patch.dict(scheduler.CONFIGURATION, {"expiry": {"session": 30, "cleanup_interval": 5}}):
            scheduler.start_scheduler()

        purge = next(c for c in instance.add_job.call_args_list if c.kwargs["id"] == "purge_expired")
        assert purge.kwargs["trigger"].interval == datetime.timedelta(minutes=5)
