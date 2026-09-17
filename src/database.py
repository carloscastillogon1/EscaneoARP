"""Persistencia en SQLite para los dispositivos LAN descubiertos."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


def utc_now_iso() -> str:
    """Devuelve un timestamp UTC compacto adecuado para columnas TEXT de SQLite."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True)
class DeviceRecord:
    id: int
    mac: str
    first_seen: str
    last_seen: str
    last_ip: str
    vendor: str | None
    status: str


class NetworkDatabase:
    """Pequeño repositorio SQLite con una tablade dispositivos e historial de descubrimiento."""

    def __init__(self, path: str | Path = "network.db") -> None:
        self.path = Path(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._initialize_schema()

    def _initialize_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL UNIQUE,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                last_ip TEXT NOT NULL,
                vendor TEXT,
                status TEXT NOT NULL DEFAULT 'new'
                    CHECK (status IN ('new', 'known', 'inactive'))
            );

            CREATE TABLE IF NOT EXISTS sightings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                seen_at TEXT NOT NULL,
                ip TEXT NOT NULL,
                FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_devices_last_seen
                ON devices(last_seen);

            CREATE INDEX IF NOT EXISTS idx_sightings_device_time
                ON sightings(device_id, seen_at);
            """
        )
        self.conn.commit()

    def upsert_observation(
        self,
        *,
        mac: str,
        ip: str,
        vendor: str | None = None,
    ) -> tuple[DeviceRecord, bool]:
        """Inserta o actualiza un dispositivo.

        Returns:
            (device_record, is_new_finding)
        """
        now = utc_now_iso()
        mac = mac.strip().lower()

        row = self.conn.execute(
            "SELECT * FROM devices WHERE mac = ?",
            (mac,),
        ).fetchone()

        if row is None:
            cursor = self.conn.execute(
                """
                INSERT INTO devices
                    (mac, first_seen, last_seen, last_ip, vendor, status)
                VALUES
                    (?, ?, ?, ?, ?, 'new')
                """,
                (mac, now, now, ip, vendor),
            )
            device_id = int(cursor.lastrowid)
            is_new = True
        else:
            device_id = int(row["id"])
            is_new = False
            self.conn.execute(
                """
                UPDATE devices
                SET last_seen = ?,
                    last_ip = ?,
                    vendor = COALESCE(?, vendor),
                    status = 'known'
                WHERE id = ?
                """,
                (now, ip, vendor, device_id),
            )

        self.conn.execute(
            """
            INSERT INTO sightings (device_id, seen_at, ip)
            VALUES (?, ?, ?)
            """,
            (device_id, now, ip),
        )

        self.conn.commit()

        return self.get_by_mac(mac), is_new  # type: ignore[return-value]

    def mark_all_known(self) -> None:
        """Marca todos los registros actuales como conocidos sin eliminar el historial."""
        self.conn.execute(
            "UPDATE devices SET status = 'known' WHERE status = 'new'"
        )
        self.conn.commit()

    def get_by_mac(self, mac: str) -> DeviceRecord | None:
        row = self.conn.execute(
            "SELECT * FROM devices WHERE mac = ?",
            (mac.strip().lower(),),
        ).fetchone()
        if row is None:
            return None
        return DeviceRecord(
            id=int(row["id"]),
            mac=str(row["mac"]),
            first_seen=str(row["first_seen"]),
            last_seen=str(row["last_seen"]),
            last_ip=str(row["last_ip"]),
            vendor=row["vendor"],
            status=str(row["status"]),
        )

    def list_devices(self) -> list[DeviceRecord]:
        rows = self.conn.execute(
            "SELECT * FROM devices ORDER BY last_seen DESC"
        ).fetchall()
        return [
            DeviceRecord(
                id=int(row["id"]),
                mac=str(row["mac"]),
                first_seen=str(row["first_seen"]),
                last_seen=str(row["last_seen"]),
                last_ip=str(row["last_ip"]),
                vendor=row["vendor"],
                status=str(row["status"]),
            )
            for row in rows
        ]

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "NetworkDatabase":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
