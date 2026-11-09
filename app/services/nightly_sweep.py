# coding: latin-1
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
"""Nightly sweep revoking credentials whose wallet or key storage is revoked.

For every session persisted in Postgres the sweep checks the WIA and key
attestation (KA) status list entries against the status-list validator and,
when one is revoked, flips the status bit of every credential issued under it
via the revocation service.
"""

from __future__ import annotations

import logging
from typing import Any, Iterator, Optional

import psycopg
import requests

from app.core.config import CONFIGURATION
from app.repositories.status_store import build_conninfo
from app.services.auth_server import status_validation_context
from app.services.revocation_status import set_token_status

logger = logging.getLogger(__name__)

_BATCH_SIZE = 100  # status-list-validator caps 'checks' at 100 items per call
_REVOKED_STATUS = 1  # per draft-ietf-oauth-status-list-10: 0=VALID, 1=INVALID/revoked
_HTTP_TIMEOUT = 15


def get_connection() -> psycopg.Connection:
    """Opens a dedicated Postgres connection for the sweep.

    Returns:
        A new psycopg connection (caller closes it).
    """
    return psycopg.connect(build_conninfo(CONFIGURATION["postgres"]))


def iter_session_ids(conn: psycopg.Connection) -> Iterator[Any]:
    """Yields session ids using a server-side cursor.

    The sweep therefore never holds the full session set in memory.

    Args:
        conn: Open connection.

    Yields:
        Session ids, ordered.
    """
    with conn.cursor(name="session_id_cursor") as cur:
        cur.itersize = 500
        cur.execute("SELECT session_id FROM wia_client_status ORDER BY session_id")
        for row in cur:
            yield row[0]


def load_session_status_tree(conn: psycopg.Connection, session_id: Any) -> dict[str, Any]:
    """Loads the WIA status, KA entries and issued keys of one session.

    Args:
        conn: Open connection.
        session_id: Session to load.

    Returns:
        ``{"wia": {status, exp}, "key_storage_statuses": [{id, ka_index, status, keys}]}``.
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT status, exp FROM wia_client_status WHERE session_id = %s",
            (session_id,),
        )
        wia_row = cur.fetchone()
        wia_status, wia_exp = wia_row if wia_row else (None, None)

        cur.execute(
            "SELECT id, ka_index, status FROM ka_key_storage_status "
            "WHERE session_id = %s ORDER BY ka_index",
            (session_id,),
        )
        ka_rows = cur.fetchall()  # (id, ka_index, status)

        ka_ids = [r[0] for r in ka_rows]
        keys_by_ka = {ka_id: [] for ka_id in ka_ids}
        if ka_ids:
            cur.execute(
                "SELECT ka_status_id, device_key, identifier_list, status_list "
                "FROM issued_key_status WHERE ka_status_id = ANY(%s)",
                (ka_ids,),
            )
            for ka_status_id, device_key, identifier_list, status_list in cur.fetchall():
                keys_by_ka[ka_status_id].append(
                    {
                        "device_key": device_key,
                        "identifier_list": identifier_list,
                        "status_list": status_list,
                    }
                )

    return {
        "wia": {"status": wia_status, "exp": wia_exp},
        "key_storage_statuses": [
            {"id": ka_id, "ka_index": ka_index, "status": status, "keys": keys_by_ka[ka_id]}
            for ka_id, ka_index, status in ka_rows
        ],
    }


def _extract_status_list_pointer(status_field: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """Extracts ``{'idx', 'uri'}`` from a raw ``status`` column value.

    Args:
        status_field: Value shaped like ``{'status_list': {'idx': int, 'uri': str}}``.

    Returns:
        The inner pointer, or ``None`` if missing or malformed.
    """
    if not status_field:
        return None
    status_list = status_field.get("status_list")
    if not status_list or "idx" not in status_list or "uri" not in status_list:
        return None
    return status_list


def check_statuses_batch(entries: list[dict[str, Any]]) -> list[Optional[dict[str, Any]]]:
    """Checks status list entries against the status-list validator.

    Requests are split into chunks of 100 (the API batch limit).

    Args:
        entries: Raw ``status`` column values as stored (WIA
            ``client_status.status`` or KA ``key_storage_statuses[].status``).

    Returns:
        Results in input order: a ``BatchStatusResultItem`` (``valid`` on
        success, ``error`` + ``status_code`` on a per-item failure) or
        ``{'error': ...}`` for malformed entries / failed requests.
    """
    if not entries:
        return []

    context = status_validation_context()
    results: list[Optional[dict[str, Any]]] = []
    for start in range(0, len(entries), _BATCH_SIZE):
        results.extend(_check_chunk(entries[start : start + _BATCH_SIZE], context, start))
    return results


def _check_chunk(chunk: list[dict[str, Any]], context: Any, start: int) -> list[Optional[dict[str, Any]]]:
    """Checks one chunk of at most :data:`_BATCH_SIZE` status entries.

    Args:
        chunk: Raw ``status`` values.
        context: Validation context sent with every check.
        start: Position of the chunk in the whole batch (for logging).

    Returns:
        Results in chunk order (see :func:`check_statuses_batch`).
    """
    chunk_results: list[Optional[dict[str, Any]]] = [None] * len(chunk)

    # Malformed entries are not sent (the validator would reject them).
    positions, checks = [], []
    for position, entry in enumerate(chunk):
        pointer = _extract_status_list_pointer(entry)
        if pointer is None:
            logger.warning("Skipping malformed/missing status_list entry in batch.")
            chunk_results[position] = {"error": "malformed_status_entry"}
            continue
        positions.append(position)
        checks.append({"idx": pointer["idx"], "uri": pointer["uri"], "validation_context": context})

    if not checks:
        return chunk_results
    try:
        response = requests.post(
            CONFIGURATION["status_validator"]["url"],
            json={"checks": checks},
            headers={"Content-Type": "application/json"},
            timeout=_HTTP_TIMEOUT,
        )
        response.raise_for_status()
        # Correlate by 'index' (position in 'checks') rather than order.
        for item in response.json().get("results", []):
            if item.get("error"):
                logger.warning(f"Status check failed for {checks[item['index']]['uri']}: {item['error']}")
            chunk_results[positions[item["index"]]] = item
    except requests.RequestException:
        logger.exception(f"Batch status check failed for chunk starting at {start}")
        for position in positions:
            chunk_results[position] = {"error": "request_failed"}
    return chunk_results


def is_revoked(result: Optional[dict[str, Any]]) -> bool:
    """Interprets one ``BatchStatusResultItem``.

    Errors and missing results count as *not revoked* (fail-safe) rather
    than revoking on an inconclusive check.

    Args:
        result: Validator result item.

    Returns:
        ``True`` only when the validator reported the entry as invalid.
    """
    if not result or "error" in result:
        return False
    return not result.get("valid", True)


def _revoke_key(key: dict[str, Any]) -> None:
    """Revokes one issued key's credential by flipping its status_list bit.

    The ``status_list`` (idx/uri) pointer is used because that is what the
    status-list validator checks; ``identifier_list`` is informational only.

    Args:
        key: Issued key row (``device_key``, ``identifier_list``, ``status_list``).
    """
    status_list = key.get("status_list")
    if not status_list or "idx" not in status_list or "uri" not in status_list:
        logger.warning(
            f"Cannot revoke key {key.get('device_key')}: missing/malformed status_list"
        )
        return
    set_token_status("idx", status_list["idx"], status_list["uri"], status=_REVOKED_STATUS)


def revoke_wia_session(session_id: Any, tree: dict[str, Any]) -> None:
    """Revokes every credential issued under a session whose WIA is revoked.

    Args:
        session_id: Session id (for logging).
        tree: Status tree from :func:`load_session_status_tree`.
    """
    all_keys = [
        key
        for ka_entry in tree["key_storage_statuses"]
        for key in ka_entry["keys"]
    ]
    logger.warning(
        f"Session {session_id}: WIA revoked. Revoking {len(all_keys)} issued key(s)."
    )
    for key in all_keys:
        _revoke_key(key)


def revoke_ka_keys(session_id: Any, ka_entry: dict[str, Any]) -> None:
    """Revokes every credential issued under one revoked key attestation.

    Args:
        session_id: Session id (for logging).
        ka_entry: KA entry from the status tree.
    """
    keys = ka_entry["keys"]
    logger.warning(
        f"Session {session_id}: KA (ka_index={ka_entry['ka_index']}) revoked. "
        f"Revoking {len(keys)} issued key(s)."
    )
    for key in keys:
        _revoke_key(key)


def _sweep_session(conn: Any, session_id: Any) -> tuple[int, int]:
    """Checks one session's WIA and key attestations and revokes accordingly.

    Args:
        conn: Database connection.
        session_id: Session to check.

    Returns:
        ``(wia_revoked, ka_revoked)`` counts (``wia_revoked`` is 0 or 1).
    """
    tree = load_session_status_tree(conn, session_id)
    logger.debug(
        f"Sweep session {session_id}: WIA status={'yes' if tree['wia']['status'] else 'no'}, "
        f"{len(tree['key_storage_statuses'])} key attestation(s)"
    )

    wia_status = tree["wia"]["status"]
    ka_statuses = [ka["status"] for ka in tree["key_storage_statuses"]]

    entries = ([wia_status] if wia_status else []) + [s for s in ka_statuses if s]
    result_iter = iter(check_statuses_batch(entries))
    wia_result = next(result_iter) if wia_status else None

    if wia_result and is_revoked(wia_result):
        revoke_wia_session(session_id, tree)
        return 1, 0  # WIA revoked -> every credential under this session is gone

    ka_revoked = 0
    for ka_entry in (ka for ka in tree["key_storage_statuses"] if ka["status"]):
        if is_revoked(next(result_iter, None)):
            ka_revoked += 1
            revoke_ka_keys(session_id, ka_entry)
    return 0, ka_revoked


def run_sweep() -> None:
    """Runs the full nightly sweep over all persisted sessions.

    Raises:
        Exception: Unhandled errors are logged and re-raised.
    """
    logger.info("Starting nightly status sweep.")
    conn = get_connection()
    sessions_checked = 0
    wia_revoked_count = 0
    ka_revoked_count = 0

    try:
        for session_id in iter_session_ids(conn):
            sessions_checked += 1
            wia_revoked, ka_revoked = _sweep_session(conn, session_id)
            wia_revoked_count += wia_revoked
            ka_revoked_count += ka_revoked

    except Exception:
        logger.exception("Nightly status sweep failed with an unhandled exception.")
        raise
    finally:
        conn.close()

    logger.info(
        f"Sweep complete. Sessions checked: {sessions_checked}, "
        f"WIA-revoked: {wia_revoked_count}, KA-revoked: {ka_revoked_count}"
    )
