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
"""In-memory stand-in for the status tables used by the persistence code.

It understands exactly the statements issued by
``app.repositories.status_store`` and ``app.services.nightly_sweep`` and keeps
real rows, so tests can assert on stored data rather than on mock calls.
"""

from contextlib import contextmanager


def _value(param):
    """Unwraps psycopg ``Json`` adapters (``to_jsonb``) to plain values."""
    return getattr(param, "obj", param)


class FakeStatusDB:
    """Tables: wia_client_status, ka_key_storage_status, issued_key_status, issued_status_entry."""

    def __init__(self):
        self.wia = {}  # session_id -> {"status", "exp"}
        self.ka = {}  # id -> {"session_id", "ka_index", "status"}
        self.keys = {}  # (ka_status_id, device_key) -> {"session_id", "identifier_list", "status_list"}
        self.entries = []  # issued_status_entry rows (dicts named like the columns)
        self.ddl = []
        self.commits = 0
        self.closed = False
        self._next_ka_id = 1

    # -- connection API -------------------------------------------------
    def cursor(self, name=None):
        return FakeCursor(self, name)

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    # -- seeding helpers for sweep tests --------------------------------
    def add_session(self, session_id, status=None, exp=None, kas=()):
        """Adds a session; ``kas`` is a list of ``(status, [key dicts])``."""
        self.wia[session_id] = {"status": status, "exp": exp}
        for ka_index, (ka_status, keys) in enumerate(kas):
            ka_id = self._insert_ka(session_id, ka_index, ka_status)
            for key in keys:
                self.keys[(ka_id, key["device_key"])] = {
                    "session_id": session_id,
                    "identifier_list": key.get("identifier_list"),
                    "status_list": key.get("status_list"),
                }

    def _insert_ka(self, session_id, ka_index, status):
        for ka_id, row in self.ka.items():
            if (row["session_id"], row["ka_index"]) == (session_id, ka_index):
                row["status"] = status
                return ka_id
        ka_id = self._next_ka_id
        self._next_ka_id += 1
        self.ka[ka_id] = {"session_id": session_id, "ka_index": ka_index, "status": status}
        return ka_id


class FakeCursor:
    def __init__(self, db, name):
        self.db = db
        self.name = name
        self.itersize = None
        self._rows = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def __iter__(self):
        return iter(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)

    def execute(self, sql, params=()):
        statement = " ".join(sql.split())
        db = self.db
        self._rows = []

        if statement.startswith(("CREATE TABLE", "CREATE INDEX")):
            db.ddl.append(statement)
        elif statement.startswith("INSERT INTO wia_client_status"):
            session_id, status, exp = params
            db.wia[session_id] = {"status": _value(status), "exp": exp}
        elif statement.startswith("INSERT INTO ka_key_storage_status"):
            session_id, ka_index, status = params
            self._rows = [(db._insert_ka(session_id, ka_index, _value(status)),)]
        elif statement.startswith("INSERT INTO issued_key_status"):
            ka_status_id, session_id, device_key, identifier_list, status_list = params
            db.keys[(ka_status_id, device_key)] = {
                "session_id": session_id,
                "identifier_list": _value(identifier_list),
                "status_list": _value(status_list),
            }
        elif statement.startswith("INSERT INTO issued_status_entry"):
            columns = (
                "session_id", "credential_type", "status_list", "identifier_list",
                "status_list_uri", "status_list_idx", "identifier_list_uri", "identifier_list_id",
            )
            db.entries.append({c: _value(p) for c, p in zip(columns, params)})
        elif statement.startswith("SELECT status_list, identifier_list FROM issued_status_entry"):
            sl_uri, sl_idx, il_uri, il_id = params

            def sql_eq(column, value):  # SQL: NULL never equals anything
                return column is not None and value is not None and column == value

            batches = {
                (e["session_id"], e["credential_type"])
                for e in db.entries
                if (sql_eq(e["status_list_uri"], sl_uri) and sql_eq(e["status_list_idx"], sl_idx))
                or (sql_eq(e["identifier_list_uri"], il_uri) and sql_eq(e["identifier_list_id"], il_id))
            }
            self._rows = [
                (e["status_list"], e["identifier_list"])
                for e in db.entries
                if (e["session_id"], e["credential_type"]) in batches
            ]
        elif statement.startswith("SELECT session_id FROM wia_client_status"):
            self._rows = [(sid,) for sid in sorted(db.wia)]
        elif statement.startswith("SELECT status, exp FROM wia_client_status"):
            row = db.wia.get(params[0])
            self._rows = [(row["status"], row["exp"])] if row else []
        elif statement.startswith("SELECT id, ka_index, status FROM ka_key_storage_status"):
            rows = [(ka_id, r["ka_index"], r["status"]) for ka_id, r in db.ka.items() if r["session_id"] == params[0]]
            self._rows = sorted(rows, key=lambda r: r[1])
        elif statement.startswith("SELECT ka_status_id, device_key, identifier_list, status_list FROM issued_key_status"):
            wanted = set(params[0])
            self._rows = [
                (ka_id, device_key, r["identifier_list"], r["status_list"])
                for (ka_id, device_key), r in db.keys.items()
                if ka_id in wanted
            ]
        else:  # pragma: no cover - guards against untested SQL
            raise AssertionError(f"Unexpected SQL: {statement}")


class FakePool:
    """Minimal ``psycopg_pool.ConnectionPool`` replacement."""

    instances = []

    def __init__(self, conninfo, min_size, max_size, open):
        self.conninfo = conninfo
        self.sizes = (min_size, max_size)
        self.opened = open
        self.db = FakeStatusDB()
        FakePool.instances.append(self)

    @contextmanager
    def connection(self):
        yield self.db
