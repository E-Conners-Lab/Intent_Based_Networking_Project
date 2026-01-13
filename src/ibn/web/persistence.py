"""SQLite-based persistence for intents and deployments."""

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any


class IntentRepository:
    """Repository for storing and retrieving intents from SQLite."""

    def __init__(self, db_path: str | Path = "ibn_intents.db"):
        self.db_path = str(db_path)

    @contextmanager
    def _get_connection(self):
        """Get a database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def initialize(self) -> None:
        """Initialize the database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Intents table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS intents (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    protocol TEXT DEFAULT 'bgp',
                    source TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    requirements TEXT,
                    constraints TEXT,
                    status TEXT DEFAULT 'pending',
                    solution TEXT,
                    configs TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT
                )
            """)

            # Migration: add protocol column if missing
            cursor.execute("PRAGMA table_info(intents)")
            columns = [col[1] for col in cursor.fetchall()]
            if "protocol" not in columns:
                cursor.execute("ALTER TABLE intents ADD COLUMN protocol TEXT DEFAULT 'bgp'")

            # Deployments table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS deployments (
                    id TEXT PRIMARY KEY,
                    intent_id TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    results TEXT,
                    deployed_at TEXT NOT NULL,
                    FOREIGN KEY (intent_id) REFERENCES intents(id)
                )
            """)

            # Create index for faster lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_intents_status ON intents(status)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_deployments_intent ON deployments(intent_id)
            """)

    def _row_to_dict(self, row: sqlite3.Row | None) -> dict[str, Any] | None:
        """Convert a database row to a dictionary."""
        if row is None:
            return None

        result = dict(row)

        # Parse JSON fields
        for field in ["requirements", "constraints", "solution", "configs", "results"]:
            if field in result and result[field]:
                try:
                    result[field] = json.loads(result[field])
                except (json.JSONDecodeError, TypeError):
                    pass

        return result

    def create(self, intent_data: dict[str, Any]) -> dict[str, Any]:
        """Create a new intent."""
        intent_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO intents (id, name, type, protocol, source, destination,
                                    requirements, constraints, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    intent_id,
                    intent_data["name"],
                    intent_data["type"],
                    intent_data.get("protocol", "bgp"),
                    intent_data["source"],
                    intent_data["destination"],
                    json.dumps(intent_data.get("requirements", {})),
                    json.dumps(intent_data.get("constraints", {})),
                    "pending",
                    now,
                ),
            )

        return self.get(intent_id)

    def get(self, intent_id: str) -> dict[str, Any] | None:
        """Get an intent by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM intents WHERE id = ?", (intent_id,))
            row = cursor.fetchone()
            return self._row_to_dict(row)

    def list_all(self) -> list[dict[str, Any]]:
        """List all intents."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM intents ORDER BY created_at ASC")
            rows = cursor.fetchall()
            return [self._row_to_dict(row) for row in rows]

    def list_by_status(self, status: str) -> list[dict[str, Any]]:
        """List intents filtered by status."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM intents WHERE status = ? ORDER BY created_at ASC",
                (status,),
            )
            rows = cursor.fetchall()
            return [self._row_to_dict(row) for row in rows]

    def update_status(self, intent_id: str, status: str) -> dict[str, Any] | None:
        """Update the status of an intent."""
        now = datetime.utcnow().isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE intents SET status = ?, updated_at = ? WHERE id = ?",
                (status, now, intent_id),
            )

        return self.get(intent_id)

    def update_solution(
        self, intent_id: str, solution: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Update intent with solver result and set status to solved."""
        now = datetime.utcnow().isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE intents
                SET solution = ?, status = 'solved', updated_at = ?
                WHERE id = ?
                """,
                (json.dumps(solution), now, intent_id),
            )

        return self.get(intent_id)

    def update_configs(
        self, intent_id: str, configs: dict[str, str]
    ) -> dict[str, Any] | None:
        """Store generated configurations for an intent."""
        now = datetime.utcnow().isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE intents SET configs = ?, updated_at = ? WHERE id = ?",
                (json.dumps(configs), now, intent_id),
            )

        return self.get(intent_id)

    def delete(self, intent_id: str) -> bool:
        """Delete an intent."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM intents WHERE id = ?", (intent_id,))
            return cursor.rowcount > 0

    # --- Deployment history ---

    def record_deployment(
        self,
        intent_id: str,
        success: bool,
        results: dict[str, Any],
    ) -> dict[str, Any]:
        """Record a deployment attempt."""
        deployment_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO deployments (id, intent_id, success, results, deployed_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    deployment_id,
                    intent_id,
                    1 if success else 0,
                    json.dumps(results),
                    now,
                ),
            )

        return self._get_deployment(deployment_id)

    def _get_deployment(self, deployment_id: str) -> dict[str, Any] | None:
        """Get a deployment by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM deployments WHERE id = ?", (deployment_id,)
            )
            row = cursor.fetchone()
            if row is None:
                return None

            result = dict(row)
            result["success"] = bool(result["success"])
            if result.get("results"):
                try:
                    result["results"] = json.loads(result["results"])
                except json.JSONDecodeError:
                    pass
            return result

    def get_deployment_history(self, intent_id: str) -> list[dict[str, Any]]:
        """Get deployment history for an intent, most recent first."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM deployments
                WHERE intent_id = ?
                ORDER BY deployed_at DESC
                """,
                (intent_id,),
            )
            rows = cursor.fetchall()

            result = []
            for row in rows:
                d = dict(row)
                d["success"] = bool(d["success"])
                if d.get("results"):
                    try:
                        d["results"] = json.loads(d["results"])
                    except json.JSONDecodeError:
                        pass
                result.append(d)

            return result

    def get_latest_deployment(self, intent_id: str) -> dict[str, Any] | None:
        """Get the most recent deployment for an intent."""
        history = self.get_deployment_history(intent_id)
        return history[0] if history else None
