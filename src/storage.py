"""SQLite storage engine for recording and replaying webhook events."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class EventStore:
    def __init__(self, db_path: Optional[str | Path] = None):
        if db_path is None:
            # Default to .webhook_sentinel.db in current directory
            db_path = Path(".webhook_sentinel.db")
        self.db_path = Path(db_path)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS webhook_events (
                    id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    event_type TEXT,
                    headers_json TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    verified INTEGER NOT NULL,
                    received_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def save_event(
        self,
        provider: str,
        headers: Dict[str, str],
        payload: str,
        verified: bool,
        event_type: Optional[str] = None,
        event_id: Optional[str] = None,
    ) -> str:
        """Record an incoming webhook event."""
        eid = event_id or f"evt_{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()

        # If event_type not provided, attempt extraction from payload if JSON
        if not event_type:
            try:
                parsed = json.loads(payload)
                if isinstance(parsed, dict):
                    event_type = parsed.get("type") or parsed.get("action") or parsed.get("event")
            except Exception:
                pass

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO webhook_events (id, provider, event_type, headers_json, payload, verified, received_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    eid,
                    provider.lower(),
                    event_type or "unknown",
                    json.dumps(headers),
                    payload,
                    1 if verified else 0,
                    now,
                ),
            )
            conn.commit()

        return eid

    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an event by ID."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM webhook_events WHERE id = ?",
                (event_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            return {
                "id": row["id"],
                "provider": row["provider"],
                "event_type": row["event_type"],
                "headers": json.loads(row["headers_json"]),
                "payload": row["payload"],
                "verified": bool(row["verified"]),
                "received_at": row["received_at"],
            }

    def list_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List recently recorded events."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT id, provider, event_type, verified, received_at, length(payload) as payload_len FROM webhook_events ORDER BY received_at DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
            return [
                {
                    "id": r["id"],
                    "provider": r["provider"],
                    "event_type": r["event_type"],
                    "verified": bool(r["verified"]),
                    "received_at": r["received_at"],
                    "payload_len": r["payload_len"],
                }
                for r in rows
            ]

    def clear(self) -> None:
        """Clear all stored events."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM webhook_events")
            conn.commit()
