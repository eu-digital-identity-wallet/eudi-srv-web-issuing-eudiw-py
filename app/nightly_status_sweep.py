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
import logging

import psycopg
import requests

from app import CONFIGURATION

logger = logging.getLogger(__name__)

STATUS_VALIDATOR_URL = CONFIGURATION["status_validator"]["url"]
VALIDATION_CONTEXT = "WalletOrKeyStorageStatus"
POSTGRES_CONFIG = CONFIGURATION["postgres"]

REVOCATION_SET_URL = CONFIGURATION["revocation"]["set_url"]
REVOCATION_API_KEY = CONFIGURATION["revocation"]["api_key"]
REVOCATION_ENABLED = CONFIGURATION["revocation"].get("enabled", True)

_BATCH_SIZE = 100  # status-list-validator caps 'checks' at 100 items per call
_REVOKED_STATUS = 1  # per draft-ietf-oauth-status-list-10: 0=VALID, 1=INVALID/revoked


def get_connection():
    conninfo = (
        f"host={POSTGRES_CONFIG['host']} "
        f"port={POSTGRES_CONFIG.get('port', 5432)} "
        f"dbname={POSTGRES_CONFIG['dbname']} "
        f"user={POSTGRES_CONFIG['user']} "
        f"password={POSTGRES_CONFIG['password']}"
    )
    return psycopg.connect(conninfo)


def iter_session_ids(conn):
    """
    Yields session_ids one at a time using a server-side cursor, so the
    sweep never holds the full session set in memory.
    """
    with conn.cursor(name="session_id_cursor") as cur:
        cur.itersize = 500
        cur.execute("SELECT session_id FROM wia_client_status ORDER BY session_id")
        for row in cur:
            yield row[0]


def load_session_status_tree(conn, session_id) -> dict:
    """
    Loads the WIA status, all KA entries, and all issued keys under them
    for a single session_id.
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


def _extract_status_list_pointer(status_field):
    """
    Given a raw 'status' column value shaped like
    {'status_list': {'idx': int, 'uri': str}}, returns the inner
    {'idx':..., 'uri':...} dict, or None if it's missing/malformed.
    """
    if not status_field:
        return None
    status_list = status_field.get("status_list")
    if not status_list or "idx" not in status_list or "uri" not in status_list:
        return None
    return status_list


def check_statuses_batch(entries: list) -> list:
    """
    entries: list of {'status_list': {'idx': int, 'uri': str}} dicts, i.e.
    the raw 'status' column value as stored (WIA client_status.status or
    KA key_storage_statuses[].status). Returns a list of result dicts in
    the same order as input, each either a BatchStatusResultItem on
    success or {'error': ...} on failure. Splits into chunks of 100 per
    the API's batch size limit.
    """
    if not entries:
        return []

    results = []
    for i in range(0, len(entries), _BATCH_SIZE):
        chunk = entries[i : i + _BATCH_SIZE]
        checks = []
        for e in chunk:
            status_list = _extract_status_list_pointer(e)
            if status_list is None:
                checks.append(
                    {"idx": 0, "uri": "", "validation_context": VALIDATION_CONTEXT}
                )
                logger.warning("Skipping malformed/missing status_list entry in batch.")
                continue
            checks.append(
                {
                    "idx": status_list["idx"],
                    "uri": status_list["uri"],
                    "validation_context": VALIDATION_CONTEXT,
                }
            )
        try:
            response = requests.post(
                STATUS_VALIDATOR_URL,
                json={"checks": checks},
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            response.raise_for_status()
            body = response.json()
            # Correlate by 'index' rather than assuming order is preserved.
            chunk_results = [None] * len(chunk)
            for item in body.get("results", []):
                chunk_results[item["index"]] = item
            results.extend(chunk_results)
        except requests.RequestException:
            logger.exception(f"Batch status check failed for chunk starting at {i}")
            results.extend([{"error": "request_failed"}] * len(chunk))

    return results


def is_revoked(result) -> bool:
    """
    Interprets a single BatchStatusResultItem. Treats errors and missing
    results as 'not revoked' (fail-safe) rather than revoking on an
    inconclusive check.
    """
    if not result or "error" in result:
        return False
    return not result.get("valid", True)


def _set_token_status(id_or_idx_field: str, id_or_idx_value, uri: str) -> bool:
    """
    Calls POST /token_status_list/set to flip a single credential's status
    bit to revoked. id_or_idx_field is either 'id' or 'idx', matching
    which pointer we're revoking against (identifier_list uses 'id',
    status_list uses 'idx').
    """
    if not REVOCATION_ENABLED:
        logger.info(f"Revocation disabled via config; skipping set for {uri}")
        return False

    payload = {
        id_or_idx_field: id_or_idx_value,
        "status": _REVOKED_STATUS,
        "uri": uri,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Api-Key": REVOCATION_API_KEY,
    }
    try:
        response = requests.post(
            REVOCATION_SET_URL, data=payload, headers=headers, timeout=15
        )
        response.raise_for_status()
        logger.info(f"Revoked token status for {id_or_idx_field}={id_or_idx_value}, uri={uri}")
        return True
    except requests.RequestException:
        logger.exception(
            f"Failed to set revoked status for {id_or_idx_field}={id_or_idx_value}, uri={uri}"
        )
        return False


def _revoke_key(key: dict):
    """
    Revokes a single issued key's credential by flipping its status_list
    bit (preferred; matches how validity is actually checked) via
    /token_status_list/set. Uses status_list (idx/uri) since that's the
    pointer status-list-validator checks; identifier_list is left as an
    informational lookup, not used for revocation itself.
    """
    status_list = key.get("status_list")
    if not status_list or "idx" not in status_list or "uri" not in status_list:
        logger.warning(
            f"Cannot revoke key {key.get('device_key')}: missing/malformed status_list"
        )
        return
    _set_token_status("idx", status_list["idx"], status_list["uri"])


def revoke_wia_session(session_id, tree: dict):
    """
    Revokes every issued credential under a session whose WIA is revoked,
    by flipping each key's status_list bit via /token_status_list/set.
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


def revoke_ka_keys(session_id, ka_entry: dict):
    """
    Revokes every issued credential under a single revoked KA, by flipping
    each key's status_list bit via /token_status_list/set.
    """
    keys = ka_entry["keys"]
    logger.warning(
        f"Session {session_id}: KA (ka_index={ka_entry['ka_index']}) revoked. "
        f"Revoking {len(keys)} issued key(s)."
    )
    for key in keys:
        _revoke_key(key)


def run_sweep():
    logger.info("Starting nightly status sweep.")
    conn = get_connection()
    sessions_checked = 0
    wia_revoked_count = 0
    ka_revoked_count = 0

    try:
        for session_id in iter_session_ids(conn):
            sessions_checked += 1
            tree = load_session_status_tree(conn, session_id)

            wia_status = tree["wia"]["status"]
            ka_statuses = [ka["status"] for ka in tree["key_storage_statuses"]]

            entries = ([wia_status] if wia_status else []) + [s for s in ka_statuses if s]
            results = check_statuses_batch(entries)

            result_iter = iter(results)
            wia_result = next(result_iter) if wia_status else None

            if wia_result and is_revoked(wia_result):
                wia_revoked_count += 1
                revoke_wia_session(session_id, tree)
                continue  # WIA revoked -> every credential under this session is gone

            for ka_entry in tree["key_storage_statuses"]:
                if not ka_entry["status"]:
                    continue
                ka_result = next(result_iter, None)
                if ka_result and is_revoked(ka_result):
                    ka_revoked_count += 1
                    revoke_ka_keys(session_id, ka_entry)

    except Exception:
        logger.exception("Nightly status sweep failed with an unhandled exception.")
        raise
    finally:
        conn.close()

    logger.info(
        f"Sweep complete. Sessions checked: {sessions_checked}, "
        f"WIA-revoked: {wia_revoked_count}, KA-revoked: {ka_revoked_count}"
    )
