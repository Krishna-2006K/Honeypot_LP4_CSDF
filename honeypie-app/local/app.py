"""Honeypie local honeypot and monitoring dashboard."""

from __future__ import annotations

import argparse
import logging
import threading
import webbrowser
from http.server import ThreadingHTTPServer
from pathlib import Path

from honeypie.audit import AuditLog
from honeypie.http_server import HoneypieHandler


class AppState:
    def __init__(self, host: str, ssh_port: int, data_dir: Path, capture_secrets: bool):
        self.host = host
        self.ssh_port = ssh_port
        self.audit = AuditLog(data_dir, capture_secrets=capture_secrets)
        self._ssh_lock = threading.Lock()
        self._ssh_thread: threading.Thread | None = None
        self._ssh_stop: threading.Event | None = None
        self.ssh_active = False
        self.ssh_error: str | None = None

    def start_ssh(self) -> tuple[bool, str]:
        with self._ssh_lock:
            if self._ssh_thread and self._ssh_thread.is_alive():
                return True, "SSH honeypot is already running."
            try:
                import paramiko  # noqa: F401  (fail early with a helpful UI message)
            except ImportError:
                return False, "Install the optional SSH dependency with: pip install -r requirements.txt"
            stop = threading.Event()
            from honeypie.ssh_server import serve_ssh

            thread = threading.Thread(
                target=serve_ssh,
                args=(self, stop),
                name="honeypie-ssh",
                daemon=True,
            )
            self._ssh_stop = stop
            self._ssh_thread = thread
            self.ssh_error = None
            thread.start()
            return True, "SSH honeypot is starting."

    def stop_ssh(self) -> tuple[bool, str]:
        with self._ssh_lock:
            if not self._ssh_thread or not self._ssh_thread.is_alive():
                self.ssh_active = False
                return True, "SSH honeypot is already stopped."
            assert self._ssh_stop is not None
            self._ssh_stop.set()
            return True, "SSH honeypot is stopping."

    def service_status(self) -> dict[str, object]:
        alive = bool(self._ssh_thread and self._ssh_thread.is_alive())
        return {
            "http": {"state": "online", "address": f"http://{self.host}"},
            "ssh": {
                "state": "online" if self.ssh_active else ("starting" if alive and not self.ssh_error else "offline"),
                "address": f"{self.host}:{self.ssh_port}",
                "error": self.ssh_error,
            },
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Honeypie's local HTTP honeypot and dashboard.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: loopback only).")
    parser.add_argument("--http-port", type=int, default=5000, help="HTTP dashboard and lure port (default: 5000).")
    parser.add_argument("--enable-ssh", action="store_true", help="Start the optional SSH honeypot at launch.")
    parser.add_argument("--ssh-port", type=int, default=2222, help="SSH honeypot port (default: 2222).")
    parser.add_argument("--data-dir", type=Path, default=Path(__file__).parent / "data", help="Directory for rotating audit logs and the SSH host key.")
    parser.add_argument("--capture-secrets", action="store_true", help="Store submitted passwords in plaintext. Off by default; use only in an authorized lab.")
    parser.add_argument("--no-browser", action="store_true", help="Do not open the dashboard automatically.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args.data_dir.mkdir(parents=True, exist_ok=True)
    state = AppState(args.host, args.ssh_port, args.data_dir, args.capture_secrets)
    if args.enable_ssh:
        ok, message = state.start_ssh()
        if not ok:
            raise SystemExit(message)
    server = ThreadingHTTPServer((args.host, args.http_port), HoneypieHandler)
    server.daemon_threads = True
    server.app_state = state  # type: ignore[attr-defined]
    url = f"http://{args.host}:{args.http_port}/"
    print(f"Honeypie dashboard: {url}")
    print(f"WordPress lure:      {url}wp-admin.html")
    print(f"Audit data:          {args.data_dir.resolve()}")
    print("Press Ctrl+C to stop.")
    if not args.no_browser:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Honeypie...")
    finally:
        state.stop_ssh()
        server.server_close()


if __name__ == "__main__":
    main()

