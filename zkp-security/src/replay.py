"""One-time invoice challenge storage for replay protection."""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Protocol


class ChallengeStore(Protocol):
    """Atomic challenge issuance and consumption boundary."""

    def issue(
        self,
        tenant_id: str,
        invoice_id: str,
        ttl_seconds: int = 300,
    ) -> tuple[str, int]:
        """Return a verifier-issued one-time token and its expiry timestamp."""

    def consume(self, token: str, tenant_id: str, invoice_id: str) -> bool:
        """Atomically consume a live token bound to the given tenant and invoice."""


class SQLiteChallengeStore:
    """SQLite-backed challenge store with atomic cross-thread/process consumption.

    A file-backed database can be shared by workers on one host. Distributed
    deployments should inject a store backed by their transactional database.
    """

    def __init__(self, database_path: str) -> None:
        if not isinstance(database_path, str) or not database_path:
            raise ValueError("A challenge database path is required.")
        self._database_path = database_path
        self._lock = threading.Lock()
        self._memory_connection: sqlite3.Connection | None = None
        if database_path == ":memory:":
            self._memory_connection = sqlite3.connect(
                database_path, timeout=5, check_same_thread=False
            )
        else:
            Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS zkp_challenges (
                    token_hash TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    invoice_id TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            if database_path != ":memory:":
                connection.execute("PRAGMA journal_mode=WAL")

    def _connection(self):
        if self._memory_connection is not None:
            return _LockedConnection(self._memory_connection, self._lock)
        return _ClosingConnection(
            sqlite3.connect(self._database_path, timeout=5, isolation_level=None)
        )

    def issue(
        self,
        tenant_id: str,
        invoice_id: str,
        ttl_seconds: int = 300,
    ) -> tuple[str, int]:
        if not tenant_id or not invoice_id:
            raise ValueError("tenant_id and invoice_id are required.")
        if type(ttl_seconds) is not int or not (1 <= ttl_seconds <= 3600):
            raise ValueError("Challenge lifetime must be in [1, 3600] seconds.")
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        expires_at = int(time.time()) + ttl_seconds
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM zkp_challenges WHERE expires_at <= ? OR consumed = 1",
                (int(time.time()),),
            )
            connection.execute(
                """
                INSERT INTO zkp_challenges
                    (token_hash, tenant_id, invoice_id, expires_at, consumed)
                VALUES (?, ?, ?, ?, 0)
                """,
                (token_hash, tenant_id, invoice_id, expires_at),
            )
            connection.commit()
        return token, expires_at

    def consume(self, token: str, tenant_id: str, invoice_id: str) -> bool:
        if not isinstance(token, str) or not token or len(token) > 256:
            return False
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE zkp_challenges
                   SET consumed = 1
                 WHERE token_hash = ?
                   AND tenant_id = ?
                   AND invoice_id = ?
                   AND consumed = 0
                   AND expires_at > ?
                """,
                (token_hash, tenant_id, invoice_id, int(time.time())),
            )
            connection.commit()
            return cursor.rowcount == 1


class _LockedConnection:
    """Context manager serializing access to SQLite's shared in-memory DB."""

    def __init__(self, connection: sqlite3.Connection, lock: threading.Lock) -> None:
        self._connection = connection
        self._lock = lock

    def __enter__(self) -> sqlite3.Connection:
        self._lock.acquire()
        return self._connection

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        self._lock.release()
        return False


class _ClosingConnection:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def __enter__(self) -> sqlite3.Connection:
        return self._connection

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        try:
            if exc_type is not None:
                self._connection.rollback()
        finally:
            self._connection.close()
        return False
