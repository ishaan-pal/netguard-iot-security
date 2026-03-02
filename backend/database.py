"""
Device Database Module
Async SQLite storage for device profiles, history, and alerts.
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional

import aiosqlite

logger = logging.getLogger("database")

DB_PATH = "iot_security.db"


class DeviceDatabase:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._lock = asyncio.Lock()

    async def initialize(self):
        """Create database tables if they don't exist"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript("""
                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT PRIMARY KEY,
                    mac TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    device_type TEXT,
                    os_guess TEXT,
                    open_ports TEXT,
                    services TEXT,
                    risk_score INTEGER DEFAULT 0,
                    risk_level TEXT DEFAULT 'low',
                    risk_factors TEXT,
                    recommendations TEXT,
                    vulnerabilities TEXT,
                    weak_configs TEXT,
                    risky_ports TEXT,
                    risk_summary TEXT,
                    exploitation_likelihood TEXT,
                    predicted_attack_vectors TEXT,
                    fingerprint TEXT,
                    behavior_baseline TEXT,
                    http_info TEXT,
                    status TEXT DEFAULT 'active',
                    first_seen REAL,
                    last_seen REAL,
                    profile_timestamp REAL,
                    deep_analysis TEXT,
                    notes TEXT,
                    extra TEXT
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    device_ip TEXT,
                    device_type TEXT,
                    severity TEXT,
                    title TEXT,
                    message TEXT,
                    factors TEXT,
                    category TEXT,
                    timestamp REAL,
                    acknowledged INTEGER DEFAULT 0,
                    acknowledged_at REAL
                );

                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    device_count INTEGER,
                    risk_distribution TEXT,
                    scan_duration REAL
                );

                CREATE TABLE IF NOT EXISTS device_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    timestamp REAL,
                    risk_score INTEGER,
                    risk_level TEXT,
                    open_ports TEXT,
                    fingerprint TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_ip);
                CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged);
                CREATE INDEX IF NOT EXISTS idx_device_history_ip ON device_history(ip);
            """)
            # Add new columns if they don't exist (for existing databases)
            try:
                await db.execute("ALTER TABLE devices ADD COLUMN deep_analysis TEXT")
            except Exception:
                pass  # Column already exists
            try:
                await db.execute("ALTER TABLE devices ADD COLUMN notes TEXT")
            except Exception:
                pass  # Column already exists

            await db.commit()
        logger.info(f"Database initialized: {self.db_path}")

    async def upsert_device(self, device: Dict):
        """Insert or update device record"""
        ip = device.get("ip")
        if not ip:
            return

        now = time.time()

        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                # Check if device exists
                cursor = await db.execute("SELECT first_seen FROM devices WHERE ip = ?", (ip,))
                row = await cursor.fetchone()
                first_seen = row[0] if row else now

                def serialize(val):
                    if isinstance(val, (list, dict)):
                        return json.dumps(val)
                    return val

                # Main device record
                await db.execute("""
                    INSERT INTO devices (
                        ip, mac, hostname, vendor, device_type, os_guess,
                        open_ports, services, risk_score, risk_level, risk_factors,
                        recommendations, vulnerabilities, weak_configs, risky_ports,
                        risk_summary, exploitation_likelihood, predicted_attack_vectors,
                        fingerprint, behavior_baseline, http_info,
                        status, first_seen, last_seen, profile_timestamp, extra
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(ip) DO UPDATE SET
                        mac=excluded.mac,
                        hostname=excluded.hostname,
                        vendor=excluded.vendor,
                        device_type=excluded.device_type,
                        os_guess=excluded.os_guess,
                        open_ports=excluded.open_ports,
                        services=excluded.services,
                        risk_score=excluded.risk_score,
                        risk_level=excluded.risk_level,
                        risk_factors=excluded.risk_factors,
                        recommendations=excluded.recommendations,
                        vulnerabilities=excluded.vulnerabilities,
                        weak_configs=excluded.weak_configs,
                        risky_ports=excluded.risky_ports,
                        risk_summary=excluded.risk_summary,
                        exploitation_likelihood=excluded.exploitation_likelihood,
                        predicted_attack_vectors=excluded.predicted_attack_vectors,
                        fingerprint=excluded.fingerprint,
                        behavior_baseline=excluded.behavior_baseline,
                        http_info=excluded.http_info,
                        last_seen=excluded.last_seen,
                        profile_timestamp=excluded.profile_timestamp,
                        extra=excluded.extra
                """, (
                    ip,
                    device.get("mac", ""),
                    device.get("hostname", ""),
                    device.get("vendor", "Unknown"),
                    device.get("device_type", "unknown"),
                    device.get("os_guess", ""),
                    serialize(device.get("open_ports", [])),
                    serialize(device.get("services", {})),
                    device.get("risk_score", 0),
                    device.get("risk_level", "low"),
                    serialize(device.get("risk_factors", [])),
                    serialize(device.get("recommendations", [])),
                    serialize(device.get("vulnerabilities", [])),
                    serialize(device.get("weak_configs", [])),
                    serialize(device.get("risky_ports", [])),
                    device.get("risk_summary", ""),
                    device.get("exploitation_likelihood", ""),
                    serialize(device.get("predicted_attack_vectors", [])),
                    device.get("fingerprint", ""),
                    serialize(device.get("behavior_baseline", {})),
                    serialize(device.get("http_info", {})),
                    device.get("status", "active"),
                    first_seen,
                    now,
                    device.get("profile_timestamp", now),
                    serialize({})
                ))

                # Add to device history
                await db.execute("""
                    INSERT INTO device_history (ip, timestamp, risk_score, risk_level, open_ports, fingerprint)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    ip, now,
                    device.get("risk_score", 0),
                    device.get("risk_level", "low"),
                    serialize(device.get("open_ports", [])),
                    device.get("fingerprint", "")
                ))

                # Store alerts
                for alert in device.get("alerts", []):
                    await db.execute("""
                        INSERT OR IGNORE INTO alerts (id, device_ip, device_type, severity, title, message, factors, category, timestamp, acknowledged)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                    """, (
                        alert.get("id"),
                        alert.get("device_ip", ip),
                        alert.get("device_type", ""),
                        alert.get("severity", "low"),
                        alert.get("title", ""),
                        alert.get("message", ""),
                        serialize(alert.get("factors", [])),
                        alert.get("category", ""),
                        alert.get("timestamp", now)
                    ))

                await db.commit()

    async def get_all_devices(self) -> List[Dict]:
        """Retrieve all devices"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM devices ORDER BY risk_score DESC, last_seen DESC"
            )
            rows = await cursor.fetchall()
            return [self._deserialize_device(dict(row)) for row in rows]

    async def get_device(self, ip: str) -> Optional[Dict]:
        """Get a specific device by IP"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM devices WHERE ip = ?", (ip,))
            row = await cursor.fetchone()
            if row:
                device = self._deserialize_device(dict(row))
                # Add history
                hist_cursor = await db.execute(
                    "SELECT timestamp, risk_score, risk_level, open_ports FROM device_history WHERE ip = ? ORDER BY timestamp DESC LIMIT 30",
                    (ip,)
                )
                device["history"] = [dict(r) for r in await hist_cursor.fetchall()]
                return device
            return None

    async def update_device(self, ip: str, updates: Dict):
        """Partial update a device"""
        allowed = {"status", "deep_analysis", "notes", "risk_score", "risk_level"}
        filtered = {k: v for k, v in updates.items() if k in allowed}
        if not filtered:
            return

        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                for key, value in filtered.items():
                    val = json.dumps(value) if isinstance(value, (dict, list)) else value
                    await db.execute(f"UPDATE devices SET {key} = ? WHERE ip = ?", (val, ip))
                await db.commit()

    async def get_alerts(self, unread_only: bool = False) -> List[Dict]:
        """Get alerts, optionally only unread"""
        query = "SELECT * FROM alerts"
        if unread_only:
            query += " WHERE acknowledged = 0"
        query += " ORDER BY timestamp DESC LIMIT 100"

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(query)
            rows = await cursor.fetchall()
            results = []
            for row in rows:
                d = dict(row)
                try:
                    d["factors"] = json.loads(d.get("factors") or "[]")
                except Exception:
                    d["factors"] = []
                results.append(d)
            return results

    async def acknowledge_alert(self, alert_id: str):
        """Mark an alert as acknowledged"""
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    "UPDATE alerts SET acknowledged = 1, acknowledged_at = ? WHERE id = ?",
                    (time.time(), alert_id)
                )
                await db.commit()

    def _deserialize_device(self, row: Dict) -> Dict:
        """Parse JSON fields back to Python objects"""
        JSON_FIELDS = [
            "open_ports", "services", "risk_factors", "recommendations",
            "vulnerabilities", "weak_configs", "risky_ports",
            "predicted_attack_vectors", "behavior_baseline", "http_info", "extra"
        ]
        for field in JSON_FIELDS:
            if field in row and isinstance(row[field], str):
                try:
                    row[field] = json.loads(row[field])
                except (json.JSONDecodeError, TypeError):
                    row[field] = [] if field != "services" and field != "behavior_baseline" and field != "http_info" else {}
        return row
