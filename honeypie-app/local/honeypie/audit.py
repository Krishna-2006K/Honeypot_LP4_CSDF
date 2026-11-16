"""Small rotating JSONL audit logs with a dashboard-friendly event schema."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLog:
    LOGS = {"http": "http_audits.log", "ssh": "ssh_audits.log", "command": "cmd_audits.log", "system": "system_audits.log"}

    def __init__(self, directory: Path, *, capture_secrets: bool = False, max_bytes: int = 2_000, backups: int = 5):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.capture_secrets = capture_secrets
        self.max_bytes = max_bytes
        self.backups = backups
        self._lock = threading.Lock()

    def password_value(self, password: str) -> str:
        if self.capture_secrets:
            return password
        return f"[redacted; {len(password)} characters]" if password else "[empty]"

    def record(self, service: str, event_type: str, remote_ip: str, **fields: Any) -> dict[str, Any]:
        safe_service = service if service in self.LOGS else "system"
        event: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "service": safe_service,
            "event_type": event_type,
            "remote_ip": remote_ip,
        }
        event.update(fields)
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
        with self._lock:
            self._rotate_if_needed(safe_service, len(line.encode("utf-8")))
            path = self.directory / self.LOGS[safe_service]
            with path.open("a", encoding="utf-8") as output:
                output.write(line)
        return event

    def _rotate_if_needed(self, service: str, incoming_bytes: int) -> None:
        path = self.directory / self.LOGS[service]
        if not path.exists() or path.stat().st_size + incoming_bytes <= self.max_bytes:
            return
        oldest = path.with_name(path.name + f".{self.backups}")
        if oldest.exists():
            oldest.unlink()
        for number in range(self.backups - 1, 0, -1):
            source = path.with_name(path.name + f".{number}")
            if source.exists():
                source.replace(path.with_name(path.name + f".{number + 1}"))
        path.replace(path.with_name(path.name + ".1"))

    def events(self, limit: int = 100) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        for base in self.LOGS.values():
            for path in self.directory.glob(base + "*"):
                try:
                    with path.open("r", encoding="utf-8") as source:
                        for line in source:
                            try:
                                item = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            if isinstance(item, dict):
                                found.append(item)
                except OSError:
                    continue
        found.sort(key=lambda item: str(item.get("timestamp", "")), reverse=True)
        return found[: max(1, min(limit, 500))]

    def summary(self) -> dict[str, Any]:
        recent = self.events(500)
        credential_types = {"http_credential_attempt", "ssh_auth_attempt"}
        credentials = [item for item in recent if item.get("event_type") in credential_types]
        commands = [item for item in recent if item.get("event_type") == "command" and item.get("service") == "command"]
        ips = {item.get("remote_ip") for item in recent if item.get("remote_ip") and item.get("remote_ip") != "unknown"}
        now = datetime.now().astimezone()
        hourly = [0] * 12
        for item in recent:
            try:
                stamp = datetime.fromisoformat(str(item["timestamp"]))
                delta_hours = int((now - stamp.astimezone()).total_seconds() // 3600)
                if 0 <= delta_hours < len(hourly):
                    hourly[-1 - delta_hours] += 1
            except (KeyError, TypeError, ValueError):
                continue
        return {
            "event_count": len(recent),
            "credential_attempts": len(credentials),
            "commands": len(commands),
            "unique_sources": len(ips),
            "hourly_activity": hourly,
        }

