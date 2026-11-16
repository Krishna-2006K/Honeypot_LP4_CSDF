# Honeypie

A small, modular honeypot based on the attached mini-project report. It provides a WordPress-style HTTP login lure, an optional SSHv2 lure with a simulated shell, rotating JSONL audit logs, and a local monitoring dashboard.

## Run it

Python 3.10 or newer is required. The HTTP lure and dashboard use only the Python standard library. Install the optional SSH server dependency if you want SSH capture:

```powershell
python -m pip install -r requirements.txt
```

Start the dashboard and HTTP lure:

```powershell
python app.py
```

Open `http://127.0.0.1:5000/`. The decoy login page is at `http://127.0.0.1:5000/wp-admin.html`.

Start HTTP and SSH together:

```powershell
python app.py --enable-ssh
```

The SSH service listens on port `2222` by default. SSH can also be started or stopped from the dashboard. It accepts login attempts and presents a small simulated shell; it never executes commands on the host machine.

## Configuration

| Option | Default | Purpose |
| --- | --- | --- |
| `--host` | `127.0.0.1` | Bind address for both services. Loopback keeps the prototype private to this machine. |
| `--http-port` | `5000` | Dashboard and WordPress lure port. |
| `--enable-ssh` | off | Start the SSH honeypot at launch. |
| `--ssh-port` | `2222` | SSH honeypot port. |
| `--data-dir` | `./data` beside `app.py` | Rotating audit logs and generated SSH host key. |
| `--capture-secrets` | off | Store submitted passwords in plaintext. Without this flag, logs keep only a redaction marker and password length. |
| `--no-browser` | off | Keep startup from opening a browser window. |

To bind beyond this machine, pass an address such as `--host 0.0.0.0` only on a network you own or are authorized to monitor. The HTTP dashboard has no login, so do not expose it to an untrusted network.

## Audit data

Events are written as JSON Lines to `http_audits.log`, `ssh_audits.log`, `cmd_audits.log`, and `system_audits.log`. Each file is capped at 2,000 bytes with five numbered backups. Logs can contain usernames, IP addresses, user-agent strings, and commands. Passwords are redacted by default. The dashboard reads the current logs and their backups; the SSH private host key is generated once in the data directory and should be kept private.

The fake shell returns canned responses for a small set of common commands. It does not use `subprocess`, invoke a shell, or open a real system account.

## Layout

- `app.py` - command-line startup and service coordination
- `honeypie/audit.py` - rotating structured audit logs and summary metrics
- `honeypie/http_server.py` - HTTP lure and dashboard API
- `honeypie/ssh_server.py` - optional Paramiko SSHv2 decoy and simulated shell
- `static/` - self-contained dashboard and WordPress-style login lure

