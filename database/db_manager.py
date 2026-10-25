"""RegAudit Database Manager.

Provides thread-safe persistence using SQLite in WAL mode. Manages schemas for
change audit logs, baseline snapshots, and monitoring sessions with transaction
rollback guarantees.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

LOGGER = logging.getLogger("RegAudit.Database")


class DatabaseManager:
    """Encapsulates SQLite connection management, transactions, and audit table queries."""

    def __init__(self, db_path: Path) -> None:
        """Initialize database manager and enforce schema creation.

        Args:
            db_path: Path to the SQLite database file (e.g. data/regaudit.db).
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Create and configure a connection with WAL mode enabled."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def init_db(self) -> None:
        """Create required tables and indexes if they do not exist."""
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    # Table 1: registry_changes
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS registry_changes (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp TEXT NOT NULL,
                            hive TEXT NOT NULL,
                            key_path TEXT NOT NULL,
                            value_name TEXT NOT NULL,
                            change_type TEXT NOT NULL,
                            old_data TEXT,
                            new_data TEXT,
                            old_type TEXT,
                            new_type TEXT,
                            severity TEXT NOT NULL,
                            pattern_matched TEXT,
                            detail TEXT,
                            session_id TEXT
                        );
                        """
                    )
                    conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_changes_timestamp ON registry_changes(timestamp);"
                    )
                    conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_changes_severity ON registry_changes(severity);"
                    )
                    conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_changes_session ON registry_changes(session_id);"
                    )

                    # Table 2: baseline_snapshots
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS baseline_snapshots (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            captured_at TEXT NOT NULL,
                            total_keys_monitored INTEGER NOT NULL,
                            total_values_captured INTEGER NOT NULL,
                            notes TEXT
                        );
                        """
                    )

                    # Table 3: sessions
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS sessions (
                            id TEXT PRIMARY KEY,
                            start_time TEXT NOT NULL,
                            end_time TEXT,
                            total_changes INTEGER DEFAULT 0,
                            critical_count INTEGER DEFAULT 0,
                            high_count INTEGER DEFAULT 0,
                            medium_count INTEGER DEFAULT 0,
                            low_count INTEGER DEFAULT 0,
                            baseline_used TEXT
                        );
                        """
                    )
                LOGGER.info("Database initialized successfully at %s (WAL mode active).", self.db_path)
            except Exception as exc:
                LOGGER.error("Failed to initialize database: %s", exc)
                raise
            finally:
                conn.close()

    def insert_change(self, change: Dict[str, Any]) -> int:
        """Insert a detected registry change into the registry_changes table.

        Args:
            change: Dictionary with keys corresponding to registry_changes columns.

        Returns:
            The inserted row ID.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO registry_changes (
                        timestamp, hive, key_path, value_name, change_type,
                        old_data, new_data, old_type, new_type, severity,
                        pattern_matched, detail, session_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        change.get("timestamp"),
                        change.get("hive"),
                        change.get("key_path"),
                        change.get("value_name"),
                        change.get("change_type"),
                        change.get("old_data"),
                        change.get("new_data"),
                        change.get("old_type"),
                        change.get("new_type"),
                        change.get("severity"),
                        change.get("pattern_matched"),
                        change.get("detail"),
                        change.get("session_id"),
                    ),
                )
                conn.commit()
                row_id = cursor.lastrowid or 0
                return row_id
            except Exception as exc:
                conn.rollback()
                LOGGER.error("Database error inserting change: %s", exc)
                raise
            finally:
                conn.close()

    def record_baseline_snapshot(
        self,
        total_keys: int,
        total_values: int,
        notes: str = "",
        captured_at: Optional[str] = None,
    ) -> int:
        """Record metadata for a newly generated baseline snapshot."""
        now_iso = captured_at or datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO baseline_snapshots (
                        captured_at, total_keys_monitored, total_values_captured, notes
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (now_iso, total_keys, total_values, notes),
                )
                conn.commit()
                return cursor.lastrowid or 0
            except Exception as exc:
                conn.rollback()
                LOGGER.error("Database error recording snapshot: %s", exc)
                return 0
            finally:
                conn.close()

    def start_session(self, session_id: str, baseline_used: str = "") -> None:
        """Register the start of a monitoring session."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO sessions (
                        id, start_time, baseline_used
                    ) VALUES (?, ?, ?)
                    """,
                    (session_id, now_iso, baseline_used),
                )
                conn.commit()
            except Exception as exc:
                conn.rollback()
                LOGGER.error("Database error starting session %s: %s", session_id, exc)
            finally:
                conn.close()

    def close_session(self, session_id: str, stats: Dict[str, int]) -> None:
        """Finalize a monitoring session with end timestamp and counts."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute(
                    """
                    UPDATE sessions SET
                        end_time = ?,
                        total_changes = ?,
                        critical_count = ?,
                        high_count = ?,
                        medium_count = ?,
                        low_count = ?
                    WHERE id = ?
                    """,
                    (
                        now_iso,
                        stats.get("total", 0),
                        stats.get("critical", 0),
                        stats.get("high", 0),
                        stats.get("medium", 0),
                        stats.get("low", 0),
                        session_id,
                    ),
                )
                conn.commit()
            except Exception as exc:
                conn.rollback()
                LOGGER.error("Database error closing session %s: %s", session_id, exc)
            finally:
                conn.close()

    def get_changes(
        self,
        limit: Optional[int] = None,
        session_id: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve historical change records ordered newest first."""
        query = "SELECT * FROM registry_changes WHERE 1=1"
        params: List[Any] = []

        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())

        query += " ORDER BY id DESC"
        if limit:
            query += " LIMIT ?"
            params.append(limit)

        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
            except Exception as exc:
                LOGGER.error("Database error querying changes: %s", exc)
                return []
            finally:
                conn.close()

    def get_snapshots(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Fetch historical baseline snapshots."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM baseline_snapshots ORDER BY id DESC LIMIT ?", (limit,))
                return [dict(row) for row in cursor.fetchall()]
            except Exception as exc:
                LOGGER.error("Database error fetching snapshots: %s", exc)
                return []
            finally:
                conn.close()

    def get_total_change_counts(self) -> Dict[str, int]:
        """Aggregate total changes and severities across all sessions."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT
                        COUNT(*) as total,
                        SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                        SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
                        SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                        SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low
                    FROM registry_changes
                    """
                )
                row = cursor.fetchone()
                if row:
                    return {
                        "total": row["total"] or 0,
                        "critical": row["critical"] or 0,
                        "high": row["high"] or 0,
                        "medium": row["medium"] or 0,
                        "low": row["low"] or 0,
                    }
                return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            except Exception as exc:
                LOGGER.error("Database error fetching change counts: %s", exc)
                return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            finally:
                conn.close()
