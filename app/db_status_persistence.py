import logging

import psycopg
from psycopg_pool import ConnectionPool

logger = logging.getLogger(__name__)

_pool: ConnectionPool | None = None


def init_db_status(postgres_config: dict):
    """
    Initializes the connection pool and ensures the required tables exist.
    Call this once at application startup, passing CONFIGURATION["postgres"].
    """
    global _pool

    conninfo = (
        f"host={postgres_config['host']} "
        f"port={postgres_config.get('port', 5432)} "
        f"dbname={postgres_config['dbname']} "
        f"user={postgres_config['user']} "
        f"password={postgres_config['password']}"
    )

    _pool = ConnectionPool(
        conninfo=conninfo,
        min_size=1,
        max_size=10,
        open=True,  # opens and primes the pool immediately, raising here if DB is unreachable
    )
    _create_tables()
    logger.info("Status persistence DB pool initialized and tables ensured.")


def _create_tables():
    with _pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS wia_client_status (
                    session_id UUID PRIMARY KEY,
                    status JSONB,
                    exp BIGINT,
                    created_at TIMESTAMPTZ DEFAULT now(),
                    updated_at TIMESTAMPTZ DEFAULT now()
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS ka_key_storage_status (
                    id SERIAL PRIMARY KEY,
                    session_id UUID REFERENCES wia_client_status(session_id),
                    ka_index INT,
                    status JSONB,
                    created_at TIMESTAMPTZ DEFAULT now(),
                    CONSTRAINT uq_session_ka_index UNIQUE (session_id, ka_index)
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS issued_key_status (
                    id SERIAL PRIMARY KEY,
                    ka_status_id INT REFERENCES ka_key_storage_status(id),
                    session_id UUID REFERENCES wia_client_status(session_id),
                    device_key TEXT,
                    identifier_list JSONB,
                    status_list JSONB,
                    created_at TIMESTAMPTZ DEFAULT now(),
                    CONSTRAINT uq_ka_device_key UNIQUE (ka_status_id, device_key)
                );
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_ka_session ON ka_key_storage_status(session_id);"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_issued_key_session ON issued_key_status(session_id);"
            )
        conn.commit()


def to_jsonb(value):
    """
    Wraps dicts for JSONB columns using psycopg3's Json adapter, so psycopg
    serializes them correctly at bind time. Passes None through untouched so
    psycopg writes a real SQL NULL instead of a JSON 'null' literal.
    """
    return psycopg.types.json.Json(value) if value is not None else None


def persist_client_status(session_id: str, client_status: dict):
    if not client_status:
        return

    try:
        with _pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO wia_client_status (session_id, status, exp, updated_at)
                    VALUES (%s, %s, %s, now())
                    ON CONFLICT (session_id) DO UPDATE
                        SET status = EXCLUDED.status,
                            exp = EXCLUDED.exp,
                            updated_at = now()
                    """,
                    (
                        session_id,
                        to_jsonb(client_status.get("status")),
                        client_status.get("exp"),
                    ),
                )

                for ka_index, ka_entry in enumerate(
                    client_status.get("key_storage_statuses", [])
                ):
                    cur.execute(
                        """
                        INSERT INTO ka_key_storage_status (session_id, ka_index, status)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (session_id, ka_index) DO UPDATE
                            SET status = EXCLUDED.status
                        RETURNING id
                        """,
                        (session_id, ka_index, to_jsonb(ka_entry.get("status"))),
                    )
                    ka_status_id = cur.fetchone()[0]

                    for key_entry in ka_entry.get("keys", []):
                        key_status = key_entry.get("key_status") or {}
                        cur.execute(
                            """
                            INSERT INTO issued_key_status
                                (ka_status_id, session_id, device_key, identifier_list, status_list)
                            VALUES (%s, %s, %s, %s, %s)
                            ON CONFLICT (ka_status_id, device_key) DO UPDATE
                                SET identifier_list = EXCLUDED.identifier_list,
                                    status_list = EXCLUDED.status_list
                            """,
                            (
                                ka_status_id,
                                session_id,
                                key_entry.get("key"),
                                to_jsonb(key_status.get("identifier_list")),
                                to_jsonb(key_status.get("status_list")),
                            ),
                        )
            conn.commit()
        logger.info(f"Persisted client_status for session_id {session_id} to Postgres.")
    except Exception:
        logger.exception(f"Failed to persist client_status for session_id {session_id}")
        raise
