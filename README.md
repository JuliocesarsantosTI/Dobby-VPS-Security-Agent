# VPS Security Agent

A hardened Sentient-Agent-Framework agent that audits a Linux VPS, generates a redacted evidence bundle, asks Fireworks for a remediation plan, and saves **clean plain-text** and **JSON** reports. Includes a minimal SSE server, a one-shot CLI, and a built-in scheduler.

---

## Highlights

- **No hard-coded API keys**; outbound requests restricted to allow-listed hosts  
- **Evidence minimization + redaction** (IP/IPv6/MAC/email/home paths/host vars, passwd usernames)  
- **Structured remediation JSON** with distro-specific steps, verify, rollback, Ansible snippet  
- **Dual output**: atomic `0600` writes to `.txt` and `.json`  
- **CLI flags**: `--no-remote`, `--format text|json|both`, `--output-dir`, `--redact-index`  
- **Delivery** (optional): Telegram text + document uploads  
- **Scheduler**: `--every 15m|2h|1d` + `--max-runs`  
- **Safer exec**: strict `PATH`, `LC_ALL/LANG`, timeouts, `stdin=DEVNULL`, careful `journalctl`

---

## What it checks

- System: kernel, uname, uptime, `/etc/os-release`, recent reboots  
- Updates: `apt`, `dnf/yum`, `pacman`  
- Firewall: `ufw`, `iptables/ip6tables`, `nft` ruleset  
- SSH: `sshd_config`, unit status/logs, listening sockets, effective `sshd -T`  
- Accounts: users, sudo/wheel group, `authorized_keys`, root password status  
- Security tools: Fail2ban, AppArmor/SELinux, unattended-upgrades

All raw evidence is **minimized and redacted** before any remote call.

---

## Requirements

- **Python**: 3.9+  
- **Linux**: Debian/Ubuntu, RHEL/CentOS/Fedora, Arch (best effort on others)  
- **Privileges**: read system config/logs and list firewall rules (run with sudo for full coverage)  
- **Python deps**:
  ```bash
  pip install sentient-agent-framework requests
  ```
  (The framework must expose: `AbstractAgent`, `Query`, `Session`, `ResponseHandler`, and `DefaultServer`.)

### Optional integrations

- **Fireworks** (remote analysis): set `FIREWORKS_API_KEY` and optionally `FIREWORKS_MODEL`
- **Telegram** (report delivery): `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`

---

## Install

```bash
git clone https://github.com/<you>/<repo>.git
cd <repo>
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt  # or: pip install requests sentient-agent-framework
```

> System tools used if present: `ufw`, `iptables`, `ip6tables`, `nft`, `systemctl`, `journalctl`, `sshd`, `ss`, `netstat`, `fail2ban-client`, `apparmor_status`, `getenforce`, `apt-get`, `dnf`/`yum`, `pacman`.

---

## Quick start

### 1) One-shot local audit (recommended first run)

```bash
# Baseline (no remote) and save both txt+json to ./security_reports
python vps_security_agent.py --once --no-remote --format both
```

### 2) One-shot with Fireworks analysis

```bash
export FIREWORKS_API_KEY=...            # required for remote analysis
# optional: export FIREWORKS_MODEL=accounts/fireworks/models/llama-v3p1-70b-instruct
python vps_security_agent.py --once --format both
```

### 3) Periodic scans (built-in scheduler)

```bash
# every 15 minutes, unlimited runs
python vps_security_agent.py --every 15m --format both
# cap runs
python vps_security_agent.py --every 1h --max-runs 24
```

### 4) Run the SSE server

```bash
python vps_security_agent.py --output-dir ./security_reports
# (no flags) starts DefaultServer with the agent; connect via your framework client
```

---

## CLI flags

```
--once                      Run one audit locally and exit
--no-remote                 Skip Fireworks call (use baseline plan)
--format {text,json,both}   Choose saved output(s) [default: both]
--output-dir PATH           Where to write reports [default: ./security_reports]
--redact-index              Redact hostname/user in the emitted evidence index (server mode)
--every "15m|2h|1d|30s|15"  Schedule periodic runs (implies repeated scans)
--max-runs N                Stop after N runs (0 = unlimited)
```

---

## Environment variables

| Variable              | Purpose                                                 | Example |
|-----------------------|---------------------------------------------------------|---------|
| `FIREWORKS_API_KEY`   | Enables remote remediation analysis                     | `sk-...` |
| `FIREWORKS_MODEL`     | Override model id                                       | `accounts/fireworks/models/llama-v3p1-70b-instruct` |
| `NO_REMOTE`           | If `1`, force baseline plan even if key is set          | `1` |
| `OUTPUT_FORMAT`       | Fallback for `--format`                                 | `both` |
| `TELEGRAM_BOT_TOKEN`  | Telegram delivery token                                 | `123:ABC` |
| `TELEGRAM_CHAT_ID`    | Telegram chat/channel id                                | `-1001234` |

> Telegram delivery is attempted automatically if both token and chat id are set.

---

## Outputs

Files are written atomically with mode **0600** into `--output-dir` (default `./security_reports`):

- `security_audit_YYYYMMDD_HHMMSS.txt` – human-readable remediation plan (markdown-free, no decorative bullets)
- `security_audit_YYYYMMDD_HHMMSS.json` – structured remediation document (see schema below)

The program also emits a compact **evidence index** (hostname/user redacted by default in server mode).

---

## Remediation JSON (shape)

The Fireworks prompt enforces a strict schema. Top-level keys:

- `title`, `executive_summary`
- `risk_priorities`: array of `{issue_id,title,risk,why_it_matters}`
- `issues`: array of items with `evidence`, `impact`, and **per-distro** `fix.steps|verify|rollback` for:
  - `debian_ubuntu`, `rhel_centos_fedora`, `arch`
  - plus `downtime`, `automation.ansible_task_example`, `references`
- `quick_harden_checklist` (ordered, copy-pasta friendly)
- `next_steps`

The `.txt` report is rendered from this JSON (no markdown, clean plaintext).

---

## Security & privacy

- **Minimize before send**: only fields required for analysis are kept; sensitive tokens and identities redacted
- **Restricted networking**: remote call only to `https://api.fireworks.ai/…`; otherwise fallback plan is used
- **Atomic writes** with `0600` perms; report directory chmod attempted to `0700`
- Runs system commands with minimal environment, `timeout`, and closed stdin

> If you must keep all data offline, run with `--no-remote` (or `NO_REMOTE=1`). You still get a conservative baseline plan.

---

## Examples

Run with Fireworks and Telegram delivery:

```bash
export FIREWORKS_API_KEY=...
export TELEGRAM_BOT_TOKEN=...
export TELEGRAM_CHAT_ID=...
python vps_security_agent.py --once --format both --output-dir /var/reports/vps
```

Schedule daily at 02:00 using the built-in scheduler (sleep-driven; use systemd/cron for precise timing if preferred):

```bash
python vps_security_agent.py --every 1d --max-runs 14
```

---




## Project structure

```
.
├─ vps_security_agent.py            # the agent + CLI + scheduler + SSE server
├─ security_reports/                # default output dir (created at runtime)
└─ requirements.txt                 # optional (requests, sentient-agent-framework)
```

---


