"""Small SQLite repository for rules, events, bans, and rollback snapshots."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinelgate.models import Ban, Event, Rule, utc_now

SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    priority INTEGER NOT NULL,
    enabled INTEGER NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    action TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    destination_port INTEGER,
    protocol TEXT,
    rule_id TEXT,
    raw TEXT,
    details TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_ip);
CREATE TABLE IF NOT EXISTS bans (
    ip TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    active INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    digest TEXT NOT NULL,
    config TEXT NOT NULL,
    reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA)

    def add_rule(self, rule: Rule) -> Rule:
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO rules(id, priority, enabled, data, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    rule.id,
                    rule.priority,
                    int(rule.enabled),
                    json.dumps(rule.to_dict(), sort_keys=True),
                    rule.created_at,
                    now,
                ),
            )
        return rule

    def list_rules(self, enabled_only: bool = False) -> list[Rule]:
        query = "SELECT data FROM rules"
        parameters: tuple[Any, ...] = ()
        if enabled_only:
            query += " WHERE enabled = ?"
            parameters = (1,)
        query += " ORDER BY priority ASC, created_at ASC"
        with self.connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [Rule.from_dict(json.loads(row["data"])) for row in rows]

    def get_rule(self, rule_id: str) -> Rule | None:
        with self.connect() as connection:
            row = connection.execute("SELECT data FROM rules WHERE id = ?", (rule_id,)).fetchone()
        return Rule.from_dict(json.loads(row["data"])) if row else None

    def update_rule(self, rule: Rule) -> Rule:
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE rules SET priority = ?, enabled = ?, data = ?, updated_at = ? WHERE id = ?",
                (
                    rule.priority,
                    int(rule.enabled),
                    json.dumps(rule.to_dict(), sort_keys=True),
                    utc_now(),
                    rule.id,
                ),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"Rule not found: {rule.id}")
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        with self.connect() as connection:
            cursor = connection.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
        return cursor.rowcount == 1

    def add_event(self, event: Event) -> Event:
        with self.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO events(occurred_at, event_type, severity, action, source_ip, "
                "destination_ip, destination_port, protocol, rule_id, raw, details) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event.occurred_at,
                    event.event_type,
                    event.severity,
                    event.action,
                    event.source_ip,
                    event.destination_ip,
                    event.destination_port,
                    event.protocol,
                    event.rule_id,
                    event.raw,
                    json.dumps(event.details, sort_keys=True),
                ),
            )
            event.id = cursor.lastrowid
        return event

    def list_events(
        self,
        limit: int = 100,
        severity: str | None = None,
        source_ip: str | None = None,
    ) -> list[Event]:
        limit = max(1, min(int(limit), 1000))
        where: list[str] = []
        parameters: list[Any] = []
        if severity:
            where.append("severity = ?")
            parameters.append(severity)
        if source_ip:
            where.append("source_ip = ?")
            parameters.append(source_ip)
        query = "SELECT * FROM events"
        if where:
            query += " WHERE " + " AND ".join(where)
        query += " ORDER BY occurred_at DESC, id DESC LIMIT ?"
        parameters.append(limit)
        with self.connect() as connection:
            rows = connection.execute(query, tuple(parameters)).fetchall()
        return [
            Event(
                id=row["id"],
                occurred_at=row["occurred_at"],
                event_type=row["event_type"],
                severity=row["severity"],
                action=row["action"],
                source_ip=row["source_ip"],
                destination_ip=row["destination_ip"],
                destination_port=row["destination_port"],
                protocol=row["protocol"],
                rule_id=row["rule_id"],
                raw=row["raw"],
                details=json.loads(row["details"]),
            )
            for row in rows
        ]

    def event_stats(self) -> dict[str, Any]:
        with self.connect() as connection:
            total = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            blocked = connection.execute(
                "SELECT COUNT(*) FROM events WHERE action IN ('blocked', 'banned')"
            ).fetchone()[0]
            high = connection.execute(
                "SELECT COUNT(*) FROM events WHERE severity IN ('high', 'critical')"
            ).fetchone()[0]
            sources = connection.execute(
                "SELECT source_ip, COUNT(*) AS count FROM events "
                "WHERE source_ip IS NOT NULL GROUP BY source_ip ORDER BY count DESC LIMIT 5"
            ).fetchall()
            ports = connection.execute(
                "SELECT destination_port, COUNT(*) AS count FROM events "
                "WHERE destination_port IS NOT NULL GROUP BY destination_port "
                "ORDER BY count DESC LIMIT 5"
            ).fetchall()
        return {
            "total_events": total,
            "blocked_events": blocked,
            "high_severity_events": high,
            "top_sources": [dict(row) for row in sources],
            "top_ports": [dict(row) for row in ports],
        }

    def upsert_ban(self, ban: Ban) -> Ban:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO bans(ip, reason, created_at, expires_at, active) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, "
                "created_at = excluded.created_at, expires_at = excluded.expires_at, active = 1",
                (ban.ip, ban.reason, ban.created_at, ban.expires_at, int(ban.active)),
            )
        return ban

    def list_bans(self, active_only: bool = True) -> list[Ban]:
        query = "SELECT * FROM bans"
        if active_only:
            query += " WHERE active = 1 AND expires_at > ?"
            parameters: tuple[Any, ...] = (datetime.now(UTC).isoformat(timespec="seconds"),)
        else:
            parameters = ()
        query += " ORDER BY created_at DESC"
        with self.connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [
            Ban(
                ip=row["ip"],
                reason=row["reason"],
                created_at=row["created_at"],
                expires_at=row["expires_at"],
                active=bool(row["active"]),
            )
            for row in rows
        ]

    def deactivate_ban(self, ip: str) -> bool:
        with self.connect() as connection:
            cursor = connection.execute("UPDATE bans SET active = 0 WHERE ip = ?", (ip,))
        return cursor.rowcount == 1

    def add_snapshot(self, digest: str, config: str, reason: str) -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO snapshots(created_at, digest, config, reason) VALUES (?, ?, ?, ?)",
                (utc_now(), digest, config, reason[:200]),
            )
            snapshot_id = int(cursor.lastrowid)
            connection.execute(
                "INSERT INTO settings(key, value) VALUES ('active_snapshot', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(snapshot_id),),
            )
        return snapshot_id

    def get_snapshot(self, snapshot_id: int) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT id, created_at, digest, config, reason FROM snapshots WHERE id = ?",
                (snapshot_id,),
            ).fetchone()
        return dict(row) if row else None

    def list_snapshots(self, limit: int = 20) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id, created_at, digest, reason FROM snapshots ORDER BY id DESC LIMIT ?",
                (max(1, min(int(limit), 100)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def active_snapshot_id(self) -> int | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT value FROM settings WHERE key = 'active_snapshot'"
            ).fetchone()
        return int(row["value"]) if row else None
