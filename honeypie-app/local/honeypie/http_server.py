"""Dashboard API and the fake WordPress login lure."""

from __future__ import annotations

import json
import mimetypes
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

STATIC = Path(__file__).resolve().parent.parent / "static"


class HoneypieHandler(BaseHTTPRequestHandler):
    server_version = "Honeypie/1.0"

    @property
    def state(self):
        return self.server.app_state  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args) -> None:
        # Keep the terminal quiet; requests are already in the structured logs.
        return

    def _send(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8", extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: object, status: int = 200) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _client_ip(self) -> str:
        return str(self.client_address[0])

    def _static(self, filename: str) -> None:
        path = STATIC / filename
        try:
            body = path.read_bytes()
        except OSError:
            self._send(404, b"Not found")
            return
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in {"application/javascript", "application/json"}:
            content_type += "; charset=utf-8"
        self._send(200, body, content_type)

    def do_GET(self) -> None:
        route = urlsplit(self.path).path
        if route == "/" or route == "/index.html":
            self._static("index.html")
        elif route in {"/wp-admin.html", "/wp-login.php"}:
            self._static("lure.html")
        elif route == "/api/summary":
            payload = self.state.audit.summary()
            payload["services"] = self.state.service_status()
            payload["capture_secrets"] = self.state.audit.capture_secrets
            self._json(payload)
        elif route == "/api/events":
            self._json({"events": self.state.audit.events(100)})
        else:
            self._send(404, b"Not found")

    def do_POST(self) -> None:
        route = urlsplit(self.path).path
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 16_384:
                self.close_connection = True
                self._send(413, b"Request body too large", extra_headers={"Connection": "close"})
                return
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
        except (ValueError, OSError):
            raw = ""
        form = parse_qs(raw, keep_blank_values=True)
        if route in {"/wp-login.php", "/wp-admin.html"}:
            username = form.get("log", form.get("username", [""]))[0][:256]
            password = form.get("pwd", form.get("password", [""]))[0][:1024]
            self.state.audit.record(
                "http",
                "http_credential_attempt",
                self._client_ip(),
                username=username,
                password=self.state.audit.password_value(password),
                password_length=len(password),
                user_agent=self.headers.get("User-Agent", "")[:300],
                path=route,
            )
            self._static_with_login_error()
        elif route == "/api/ssh/start":
            ok, message = self.state.start_ssh()
            self._json({"ok": ok, "message": message, "services": self.state.service_status()}, 200 if ok else 503)
        elif route == "/api/ssh/stop":
            ok, message = self.state.stop_ssh()
            self._json({"ok": ok, "message": message, "services": self.state.service_status()})
        else:
            self._send(404, b"Not found")

    def _static_with_login_error(self) -> None:
        try:
            body = (STATIC / "lure.html").read_text(encoding="utf-8")
        except OSError:
            self._send(404, b"Not found")
            return
        body = body.replace("<!--LOGIN_ERROR-->", '<div class="login-error" role="alert">Error: The username or password you entered is incorrect. Please try again.</div>')
        self._send(200, body.encode("utf-8"))

