"""Optional Paramiko SSHv2 honeypot. It never invokes a system shell."""

from __future__ import annotations

import logging
import socket
import threading
import time
from pathlib import Path

LOG = logging.getLogger("honeypie.ssh")


def _host_key(data_dir: Path, paramiko):
    path = data_dir / "honeypie_host_key.pem"
    if path.exists():
        return paramiko.RSAKey.from_private_key_file(str(path))
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(path))
    return key


def _fake_output(command: str) -> str:
    cmd = command.strip().lower()
    answers = {
        "pwd": "/var/www/html\n",
        "whoami": "www-data\n",
        "id": "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n",
        "uname -a": "Linux honeypie 5.15.0-generic #1 SMP x86_64 GNU/Linux\n",
        "ls": "index.html  wp-admin.php  wp-content  wp-includes\n",
        "ls -la": "total 24\ndrwxr-xr-x  5 www-data www-data 4096 .\n-rw-r--r--  1 www-data www-data  612 index.html\ndrwxr-xr-x  3 www-data www-data 4096 wp-content\n",
        "whoami; id": "www-data\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\n",
    }
    if cmd in {"exit", "logout", "quit"}:
        return "__EXIT__"
    if cmd.startswith("cat "):
        return "cat: permission denied\n"
    if cmd.startswith("cd"):
        return ""
    return answers.get(cmd, f"sh: {command.strip()[:120]}: command not found\n")


def _handle_client(client: socket.socket, address, state, host_key, paramiko) -> None:
    class Session(paramiko.ServerInterface):
        def check_auth_password(self, username: str, password: str) -> int:
            state.audit.record(
                "ssh",
                "ssh_auth_attempt",
                str(address[0]),
                username=username[:256],
                password=state.audit.password_value(password[:1024]),
                password_length=len(password),
            )
            return paramiko.AUTH_SUCCESSFUL

        def get_allowed_auths(self, username: str) -> str:
            return "password"

        def check_channel_request(self, kind: str, chanid: int) -> int:
            return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
            return True

        def check_channel_shell_request(self, channel) -> bool:
            return True

    transport = None
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(host_key)
        transport.start_server(server=Session())
        channel = transport.accept(15)
        if channel is None:
            return
        state.audit.record("ssh", "ssh_session_open", str(address[0]))
        channel.send("Ubuntu 22.04 LTS\r\n\r\nWelcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-generic x86_64)\r\n\r\nwww-data@honeypie:/var/www/html$ ")
        pending = ""
        while not channel.closed and transport.is_active():
            if not channel.recv_ready():
                time.sleep(0.05)
                continue
            chunk = channel.recv(2048).decode("utf-8", errors="replace")
            if not chunk:
                break
            pending += chunk.replace("\x7f", "").replace("\b", "")
            while "\r" in pending or "\n" in pending:
                endings = [index for index in (pending.find("\r"), pending.find("\n")) if index >= 0]
                end = min(endings)
                line = pending[:end]
                consumed = 2 if pending[end:end + 2] == "\r\n" else 1
                pending = pending[end + consumed:]
                command = line[:1024]
                if not command:
                    channel.send("www-data@honeypie:/var/www/html$ ")
                    continue
                state.audit.record("command", "command", str(address[0]), command=command)
                output = _fake_output(command)
                if output == "__EXIT__":
                    channel.send("logout\r\n")
                    return
                if output:
                    channel.send(output.replace("\n", "\r\n"))
                channel.send("www-data@honeypie:/var/www/html$ ")
    except Exception as exc:  # network clients may disconnect mid-handshake
        LOG.debug("SSH client %s ended: %s", address, exc)
    finally:
        if transport is not None:
            transport.close()
        try:
            client.close()
        except OSError:
            pass


def serve_ssh(state, stop_event: threading.Event) -> None:
    try:
        import paramiko

        host_key = _host_key(state.audit.directory, paramiko)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((state.host, state.ssh_port))
        listener.listen(100)
        listener.settimeout(0.5)
        state.ssh_active = True
        state.ssh_error = None
        state.audit.record("system", "ssh_listener_started", "local", address=f"{state.host}:{state.ssh_port}")
        LOG.info("SSH honeypot listening on %s:%s", state.host, state.ssh_port)
        with listener:
            while not stop_event.is_set():
                try:
                    client, address = listener.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=_handle_client, args=(client, address, state, host_key, paramiko), daemon=True).start()
    except Exception as exc:
        state.ssh_error = str(exc)
        state.ssh_active = False
        state.audit.record("system", "ssh_listener_error", "local", message=str(exc)[:300])
        LOG.exception("SSH honeypot failed to start")
    finally:
        state.ssh_active = False
        state.audit.record("system", "ssh_listener_stopped", "local")

