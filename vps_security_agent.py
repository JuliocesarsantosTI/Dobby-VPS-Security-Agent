

import os
import re
import io
import json
import shutil
import socket
import getpass
import pathlib
import datetime
import subprocess
import asyncio
import signal
import time
from datetime import timedelta
from typing import Dict, List, Tuple

import requests

from sentient_agent_framework.interface.agent import AbstractAgent
from sentient_agent_framework.interface.request import Query
from sentient_agent_framework.interface.session import Session
from sentient_agent_framework.interface.response_handler import ResponseHandler
from sentient_agent_framework import DefaultServer




def run_cmd(cmd: List[str], timeout: int = 15) -> Tuple[int, str, str]:
    try:
        env = {
            "LC_ALL": "C",
            "LANG": "C",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        }
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            stdin=subprocess.DEVNULL,
        )
        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        return proc.returncode, out, err
    except FileNotFoundError:
        return 127, "", f"command not found: {' '.join(cmd)}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s: {' '.join(cmd)}"


def file_read(path: str, max_bytes: int = 200_000) -> str:
    try:
        p = pathlib.Path(path)
        if not p.exists():
            return f"{path} not found"
        data = p.read_bytes()[:max_bytes]
        return data.decode(errors="replace")
    except Exception as e:
        return f"could not read {path}: {e}"


def which(name: str) -> bool:
    return shutil.which(name) is not None


def now_iso() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize_plaintext(s: str) -> str:
    """
    Make the analysis easy to read in plain text and avoid decorative symbols like asterisks or bullets.
    Also remove markdown header hashes and normalize blank lines.
    Safer: do not strip when line looks like a command or flag.
    """
    lines = s.splitlines()
    cleaned = []
    for line in lines:
        if re.match(r"^\s*([*•·\-–—▪►➤➜])\s+\S", line) and not re.match(r"^\s*-\S", line):
            line = re.sub(r"^\s*([*•·\-–—▪►➤➜])\s+", "", line)
        line = re.sub(r"^\s*#{1,6}\s*", "", line)
        cleaned.append(line.rstrip())
    text = "\n".join(cleaned)
    text = re.sub(r"\n{3,}", "\n\n", text).strip() + "\n"
    return text




def gather_system_info() -> Dict[str, str]:
    info = {
        "timestamp": now_iso(),
        "hostname": socket.gethostname(),
        "user": getpass.getuser(),
        "os_release": file_read("/etc/os-release"),
    }
    _, out, err = run_cmd(["uname", "-a"])
    info["uname"] = out or err

    _, out, err = run_cmd(["uptime", "-p"])
    info["uptime_pretty"] = out or err

    _, out, err = run_cmd(["uname", "-r"])
    info["kernel"] = out or err

    if which("last"):
        _, out, err = run_cmd(["last", "-x", "-n", "10"])
        info["last_reboots"] = out or err
    return info


def gather_update_status() -> Dict[str, str]:
    status = {}
    if which("apt-get"):
        _, out, err = run_cmd(["apt-get", "-s", "upgrade"])
        status["apt_upgrade_simulation"] = out or err
    if which("dnf"):
        _, out, err = run_cmd(["dnf", "check-update"])
        status["dnf_check_update"] = out or err
    elif which("yum"):
        _, out, err = run_cmd(["yum", "check-update"])
        status["yum_check_update"] = out or err
    if which("pacman"):
        _, out, err = run_cmd(["bash", "-lc", "pacman -Qu || true"])
        status["pacman_outdated"] = out or err
    return status


def gather_firewall_status() -> Dict[str, str]:
    fw = {}
    if which("ufw"):
        _, out, err = run_cmd(["ufw", "status", "verbose"])
        fw["ufw_status"] = out or err
        _, out, err = run_cmd(["ufw", "status", "numbered"])
        if out:
            fw["ufw_status_numbered"] = out
    if which("iptables"):
        _, out, err = run_cmd(["iptables", "-S"])
        fw["iptables_rules"] = out or err
    if which("ip6tables"):
        _, out, err = run_cmd(["ip6tables", "-S"])
        fw["ip6tables_rules"] = out or err
    if which("nft"):
        _, out, err = run_cmd(["nft", "list", "ruleset"])
        fw["nft_ruleset"] = out or err
    return fw


def gather_ssh_status() -> Dict[str, str]:
    ssh = {
        "sshd_config": file_read("/etc/ssh/sshd_config", max_bytes=100_000),
    }
    if which("systemctl"):
        _, out, err = run_cmd(["systemctl", "is-enabled", "ssh"])
        if not out and err:
            _, out, err = run_cmd(["systemctl", "is-enabled", "sshd"])
        ssh["systemd_is_enabled"] = out or err

        _, out, err = run_cmd(["systemctl", "status", "ssh"])
        if not out and err:
            _, out, err = run_cmd(["systemctl", "status", "sshd"])
        ssh["systemd_status"] = out or err

    if which("journalctl"):
        rc, out, err = run_cmd(["journalctl", "--no-pager", "-u", "ssh", "-S", "24 hours ago", "-n", "500"])
        if rc != 0 or not out:
            _, out, err = run_cmd(["journalctl", "--no-pager", "-u", "sshd", "-S", "24 hours ago", "-n", "500"])
        ssh["journal_24h"] = out or err
    else:
        ssh["auth_log"] = file_read("/var/log/auth.log")

    if which("ss"):
        _, out, err = run_cmd(["ss", "-tulpen"])
        ssh["listening_sockets"] = out or err
    elif which("netstat"):
        _, out, err = run_cmd(["netstat", "-tulpen"])
        ssh["listening_sockets"] = out or err

    if which("sshd"):
        _, out, err = run_cmd(["sshd", "-T"])
        if out:
            ssh["sshd_effective"] = out

    return ssh


def gather_accounts() -> Dict[str, str]:
    acc = {}
    _, out, err = run_cmd(["bash", "-lc", "getent passwd | awk -F: '{print $1\":\"$3\":\"$7}'"])
    acc["passwd"] = out or err

    _, out, err = run_cmd(["bash", "-lc", "getent group sudo || getent group wheel || true"])
    acc["admin_group"] = out or err

    _, out, err = run_cmd(["bash", "-lc", "ls -l /home/*/.ssh/authorized_keys 2>/dev/null || true"])
    acc["authorized_keys"] = out or err

    _, out, err = run_cmd(["bash", "-lc", "passwd -S root 2>/dev/null || true"])
    acc["root_password_status"] = out or err
    return acc


def gather_security_tools() -> Dict[str, str]:
    tools = {}
    if which("fail2ban-client"):
        _, out, err = run_cmd(["fail2ban-client", "status"])
        tools["fail2ban_status"] = out or err
    if which("apparmor_status"):
        _, out, err = run_cmd(["apparmor_status"])
        tools["apparmor_status"] = out or err
    if which("getenforce"):
        _, out, err = run_cmd(["getenforce"])
        tools["selinux_status"] = out or err
    if which("systemctl"):
        _, out, err = run_cmd(["systemctl", "status", "unattended-upgrades"])
        tools["unattended_upgrades"] = out or err
    return tools


def collect_all_checks() -> Dict[str, Dict[str, str]]:
    return {
        "system": gather_system_info(),
        "updates": gather_update_status(),
        "firewall": gather_firewall_status(),
        "ssh": gather_ssh_status(),
        "accounts": gather_accounts(),
        "security_tools": gather_security_tools(),
    }




SENSITIVE_KEYS = {"hostname", "user", "sshd_config", "journal_24h", "auth_log", "passwd"}

IPv6_RE = r'(?i)\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b'
MAC_RE  = r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'
EMAIL_RE = r'[\w\.-]+@[\w\.-]+'
HOME_RE = r'/(home|Users)/[^/\s]+'
HOSTVAR_RE = r'\b(hostname|HOSTNAME)=[^\s]+'


def _redact(s: str):
    if not isinstance(s, str):
        return s
    s = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '<IP>', s)   # IPv4
    s = re.sub(IPv6_RE, '<IP>', s)                          # IPv6
    s = re.sub(MAC_RE, '<MAC>', s)                          # MAC
    s = re.sub(EMAIL_RE, '<EMAIL>', s)                      # email
    s = re.sub(HOME_RE, r'/\1/<USER>', s)                   # home paths
    s = re.sub(HOSTVAR_RE, r'hostname=<REDACTED>', s)       # hostname var
    s = re.sub(r'^([a-z_][a-z0-9_-]*):(\d+):(\/[^\s]+)$', r'<USER>:\2:\3', s, flags=re.MULTILINE)
    return s


def _extract_minimal(checks: Dict[str, Dict[str, str]]) -> Dict[str, Dict[str, str]]:
    """Keep only what the model needs; redact values."""
    minimal = {"system": {}, "updates": {}, "firewall": {}, "ssh": {}, "accounts": {}, "security_tools": {}}
    sysc = checks.get("system", {})
    minimal["system"] = {
        "timestamp": sysc.get("timestamp", ""),
        "kernel": _redact(sysc.get("kernel", "")),
        "uname": _redact(sysc.get("uname", "")),
        "uptime_pretty": _redact(sysc.get("uptime_pretty", "")),
        "os_release": _redact(sysc.get("os_release", "")),
    }
    upd = checks.get("updates", {})
    minimal["updates"] = {k: _redact(v) for k, v in upd.items()}
    fw = checks.get("firewall", {})
    minimal["firewall"] = {k: _redact(v) for k, v in fw.items()}
    ssh = checks.get("ssh", {})
    cfg = ssh.get("sshd_config", "")
    def _cfg(key, default=""):
        m = re.search(rf'^\s*{key}\s+(.+)$', cfg, flags=re.IGNORECASE | re.MULTILINE)
        return (m.group(1).strip() if m else default)
    minimal["ssh"] = {
        "systemd_is_enabled": _redact(ssh.get("systemd_is_enabled", "")),
        "systemd_status": _redact(ssh.get("systemd_status", "")),
        "listening_sockets": _redact(ssh.get("listening_sockets", "")),
        "PermitRootLogin": _cfg("PermitRootLogin", ""),
        "PasswordAuthentication": _cfg("PasswordAuthentication", ""),
        "Port": _cfg("Port", ""),
        "PubkeyAuthentication": _cfg("PubkeyAuthentication", ""),
        "AllowUsers": _cfg("AllowUsers", ""),
        "AllowGroups": _cfg("AllowGroups", ""),
        "MaxAuthTries": _cfg("MaxAuthTries", ""),
        "LoginGraceTime": _cfg("LoginGraceTime", ""),
    }
    acc = checks.get("accounts", {})
    minimal["accounts"] = {
        "admin_group": _redact(acc.get("admin_group", "")),
        "root_password_status": _redact(acc.get("root_password_status", "")),
    }
    tools = checks.get("security_tools", {})
    minimal["security_tools"] = {k: _redact(v) for k, v in tools.items()}
    return minimal




REMEDIATION_SCHEMA_DESC = """
You MUST return ONLY valid JSON that conforms to this schema:
{
  "title": "string",
  "executive_summary": "short paragraph explaining current security posture",
  "risk_priorities": [
    {"issue_id": "string", "title": "string", "risk": "Critical|High|Medium|Low", "why_it_matters": "string"}
  ],
  "issues": [
    {
      "issue_id": "string",
      "title": "string",
      "risk": "Critical|High|Medium|Low",
      "evidence": "concise summary of evidence you inferred from inputs",
      "impact": "what can go wrong if unfixed",
      "fix": {
        "debian_ubuntu": {
          "steps": ["exact commands line-by-line, idempotent where possible"],
          "verify": ["commands to confirm success"],
          "rollback": ["commands to revert safely"]
        },
        "rhel_centos_fedora": {
          "steps": ["..."],
          "verify": ["..."],
          "rollback": ["..."]
        },
        "arch": {
          "steps": ["..."],
          "verify": ["..."],
          "rollback": ["..."]
        }
      },
      "downtime": "None|<estimated window and what is impacted>",
      "automation": {
        "ansible_task_example": "a minimal, safe Ansible task or role snippet as YAML"
      },
      "references": ["relevant man pages or vendor docs (no decorative bullets)"]
    }
  ],
  "quick_harden_checklist": ["ordered, exact items an SRE can paste into a runbook"],
  "next_steps": ["follow-ups like monitoring or recurring scans"]
}
Rules:
- Be concrete. Use exact file paths, sysctl keys, package names, and systemctl unit names.
- Prefer 'deny by default' firewall examples.
- For SSH: show PermitRootLogin, PasswordAuthentication, PubkeyAuthentication, Port, AllowUsers, and how to reload safely.
- Always provide verify and rollback commands.
- Avoid decorative symbols. No Markdown. No prose outside JSON.
"""

def render_plaintext_from_json(doc: Dict) -> str:
    lines: List[str] = []
    add = lines.append
    g = doc
    add(g.get("title","Linux VPS Security Remediation Report"))
    add("")
    add("Executive Summary")
    add(g.get("executive_summary",""))
    add("")
    add("Risk Priorities")
    for rp in g.get("risk_priorities", []):
        add(f"{rp.get('issue_id','')}: {rp.get('title','')} [{rp.get('risk','')}]")
        add(f"Reason: {rp.get('why_it_matters','')}")
        add("")
    add("Issues and Fixes")
    for i in g.get("issues", []):
        add(f"{i.get('issue_id','')}. {i.get('title','')} [{i.get('risk','')}]")
        if i.get("evidence"):
            add("Evidence")
            add(i["evidence"])
        if i.get("impact"):
            add("Impact")
            add(i["impact"])
        fx = i.get("fix", {})
        for distro, payload in [("debian_ubuntu","Debian/Ubuntu"),
                                ("rhel_centos_fedora","RHEL/CentOS/Fedora"),
                                ("arch","Arch")]:
            if distro in fx:
                add(f"Fix for {payload}")
                for section, title in [("steps","Steps"), ("verify","Verify"), ("rollback","Rollback")]:
                    if fx[distro].get(section):
                        add(title)
                        for cmd in fx[distro][section]:
                            add(cmd)
        if i.get("downtime"):
            add("Downtime")
            add(i["downtime"])
        if i.get("automation", {}).get("ansible_task_example"):
            add("Ansible Example")
            add(i["automation"]["ansible_task_example"])
        if i.get("references"):
            add("References")
            for r in i["references"]:
                add(r)
        add("")
    if g.get("quick_harden_checklist"):
        add("Quick Harden Checklist")
        for item in g["quick_harden_checklist"]:
            add(item)
        add("")
    if g.get("next_steps"):
        add("Next Steps")
        for item in g["next_steps"]:
            add(item)
        add("")
    return sanitize_plaintext("\n".join(lines))



def _fireworks_session():
    s = requests.Session()
    s.trust_env = False 
    return s

def fireworks_analyze(checks: Dict[str, Dict[str, str]]) -> Tuple[str, Dict]:
    """
    Sends the collected evidence to Fireworks Chat Completions for analysis and remediation guidance.
    Returns (rendered_text, remediation_json).
    """
    api_key = os.getenv("FIREWORKS_API_KEY")
    url = "https://api.fireworks.ai/inference/v1/chat/completions"
    model = os.getenv("FIREWORKS_MODEL") or "accounts/fireworks/models/llama-v3p1-70b-instruct"

    minimal_checks = _extract_minimal(checks) if checks else {}

    system_prompt = (
        "You are a Linux security engineer. You will produce a complete remediation plan that fully explains how to fix issues.\n"
        "Return ONLY JSON and strictly follow the provided schema. No extra text."
    )

    user_prompt = (
        "Task: Analyze the following Linux host evidence and produce a COMPLETE remediation plan that fully explains how to fix all security issues.\n"
        + REMEDIATION_SCHEMA_DESC
        + "\nEvidence JSON:\n"
        + json.dumps(minimal_checks, indent=2)[:200000]
    )

    payload = {
        "model": model,
        "temperature": 0.2,
        "max_tokens": 3000,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "n": 1,
        "stream": False,
    }

    headers = {
        "Authorization": f"Bearer {api_key}" if api_key else "",
        "Content-Type": "application/json",
        "User-Agent": "vps-security-agent/1.0",
    }

    if not api_key:
        rendered = (
            "Analysis error\n\n"
            "Reason: missing FIREWORKS_API_KEY\n"
            "Conservative baseline plan\n\n"
            "1. Disable SSH root login and password authentication. Prefer key-based auth.\n"
            "2. Apply pending OS updates and security patches.\n"
            "3. Restrict inbound ports to only required services with a deny by default firewall policy.\n"
            "4. Enable fail2ban or a similar intrusion prevention tool.\n"
            "5. Review admin users and SSH keys, remove anything unused.\n"
        )
        plan = {
            "title": "Baseline Linux VPS Security Remediation",
            "executive_summary": "Automated fallback plan due to missing API key.",
            "risk_priorities": [],
            "issues": [],
            "quick_harden_checklist": [
                "Disable SSH root login and password authentication",
                "Apply OS updates",
                "Set default-deny firewall policy",
                "Enable fail2ban",
                "Audit admin users and SSH keys"
            ],
            "next_steps": ["Re-run analysis with FIREWORKS_API_KEY set"]
        }
        return sanitize_plaintext(rendered), plan

    try:
        # allow-list host
        if not url.startswith("https://api.fireworks.ai/"):
            raise RuntimeError("Refusing to contact non-whitelisted host")
        sess = _fireworks_session()
        resp = sess.post(url, headers=headers, data=json.dumps(payload), timeout=(5, 25))
        resp.raise_for_status()
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        plan = json.loads(content)
        rendered = render_plaintext_from_json(plan)
    except Exception as e:
        rendered = (
            "Analysis error\n\n"
            f"Reason: {e}\n"
            "Conservative baseline plan\n\n"
            "1. Disable SSH root login and password authentication. Prefer key-based auth.\n"
            "2. Apply pending OS updates and security patches.\n"
            "3. Restrict inbound ports to only required services with a deny by default firewall policy.\n"
            "4. Enable fail2ban or a similar intrusion prevention tool.\n"
            "5. Review admin users and SSH keys, remove anything unused.\n"
        )
        plan = {
            "title": "Baseline Linux VPS Security Remediation",
            "executive_summary": "Automated fallback plan due to analysis error.",
            "risk_priorities": [],
            "issues": [],
            "quick_harden_checklist": [
                "Disable SSH root login and password authentication",
                "Apply OS updates",
                "Set default-deny firewall policy",
                "Enable fail2ban",
                "Audit admin users and SSH keys"
            ],
            "next_steps": ["Re-run analysis when connectivity is available"]
        }

    return sanitize_plaintext(rendered), plan



def _telegram_session():
    s = requests.Session()
    s.trust_env = False 
    return s

def _tg_send_text(token: str, chat_id: str, text: str, disable_preview: bool = True):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    sess = _telegram_session()
    chunk_size = 3500  
    chunks = [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)] or [text]
    for chunk in chunks:
        payload = {
            "chat_id": chat_id,
            "text": chunk,
            "disable_web_page_preview": disable_preview,
        }
        resp = sess.post(url, data=payload, timeout=(5, 20))
        resp.raise_for_status()

def _tg_send_document(token: str, chat_id: str, file_path: str, caption: str = None, mime: str = None):
    url = f"https://api.telegram.org/bot{token}/sendDocument"
    sess = _telegram_session()
    if not os.path.exists(file_path):
        return
    if mime is None:
        mime = "application/json" if file_path.endswith(".json") else "text/plain"
    with open(file_path, "rb") as f:
        files = {"document": (os.path.basename(file_path), f, mime)}
        data = {"chat_id": chat_id}
        if caption:
            data["caption"] = caption[:900]
        resp = sess.post(url, data=data, files=files, timeout=(5, 30))
        resp.raise_for_status()




def _secure_open(path: pathlib.Path):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    return io.TextIOWrapper(io.FileIO(fd, 'w'), encoding='utf-8')




class VPSSecurityAgent(AbstractAgent):
    def __init__(self, save_dir: str = "./security_reports", redact_index: bool = True):
        self.save_dir = pathlib.Path(save_dir)
        self.save_dir.mkdir(parents=True, exist_ok=True)
        self.redact_index = redact_index
        try:
            os.chmod(self.save_dir, 0o700)
        except Exception:
            pass

    def _save_report(self, text: str) -> str:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = self.save_dir / f"security_audit_{ts}.txt"
        with _secure_open(path) as f:
            f.write(text)
        return str(path.resolve())

    def _save_json(self, data: Dict) -> str:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = self.save_dir / f"security_audit_{ts}.json"
        with _secure_open(path) as f:
            json.dump(data, f, indent=2)
        return str(path.resolve())

    async def assist(self, session: Session, query: Query, response_handler: ResponseHandler):
        await response_handler.emit_text_block("TITLE", "Linux VPS security audit is starting")
        await response_handler.emit_text_block("INFO", "Collecting system information")
        system = gather_system_info()

        await response_handler.emit_text_block("INFO", "Checking pending updates")
        updates = gather_update_status()

        await response_handler.emit_text_block("INFO", "Inspecting firewall configuration")
        firewall = gather_firewall_status()

        await response_handler.emit_text_block("INFO", "Reviewing SSH configuration and auth events")
        ssh = gather_ssh_status()

        await response_handler.emit_text_block("INFO", "Enumerating accounts and elevated access")
        accounts = gather_accounts()

        await response_handler.emit_text_block("INFO", "Querying security tools status")
        tools = gather_security_tools()

        evidence = {
            "system": system,
            "updates": updates,
            "firewall": firewall,
            "ssh": ssh,
            "accounts": accounts,
            "security_tools": tools,
        }

        await response_handler.emit_json("EVIDENCE_INDEX", {
            "sections": list(evidence.keys()),
            "timestamp": system.get("timestamp", now_iso()),
            "hostname": "<REDACTED>" if self.redact_index else system.get("hostname", ""),
            "user": "<REDACTED>" if self.redact_index else system.get("user", "")
        })

        no_remote = bool(os.getenv("NO_REMOTE","").strip())
        fmt = (os.getenv("OUTPUT_FORMAT","both") or "both").lower()

        if not no_remote:
            await response_handler.emit_text_block("INFO", "Sending evidence to Fireworks for expert analysis")
            analysis_text, analysis_json = await asyncio.to_thread(fireworks_analyze, evidence)
        else:
            await response_handler.emit_text_block("INFO", "Skipping remote analysis (NO_REMOTE=1). Using baseline plan.")
            analysis_text, analysis_json = await asyncio.to_thread(fireworks_analyze, {})  # baseline

        json_path = None
        report_path = None
        if fmt in ("both","json"):
            json_path = self._save_json(analysis_json)
        if fmt in ("both","text"):
            report_path = self._save_report(analysis_text)

        final_stream = response_handler.create_text_stream("FINAL_REPORT")
        for chunk in re.findall(r".{1,600}", analysis_text, flags=re.DOTALL):
            await final_stream.emit_chunk(chunk)
        await final_stream.complete()

        await response_handler.emit_json("RESULT", {"text_report": report_path, "json_report": json_path})

        token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
        if token and chat_id:
            await response_handler.emit_text_block("INFO", "Sending analysis to Telegram")
            try:
                header = "Linux VPS Security Audit\n" + (system.get("timestamp") or now_iso())
                _tg_send_text(token, chat_id, f"{header}\n\n{analysis_text}")
                if report_path:
                    _tg_send_document(token, chat_id, report_path, caption="Security audit report (TXT)")
                if json_path:
                    _tg_send_document(token, chat_id, json_path, caption="Security audit remediation (JSON)")
                await response_handler.emit_text_block("INFO", "Telegram delivery completed")
            except Exception as e:
                await response_handler.emit_text_block("WARN", f"Telegram delivery failed: {e}")
        else:
            await response_handler.emit_text_block(
                "INFO",
                "Telegram not configured (set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to enable)."
            )

        await response_handler.complete("Audit completed successfully")




def run_server(output_dir: str = "./security_reports", redact_index: bool = True):
    agent = VPSSecurityAgent(save_dir=output_dir, redact_index=redact_index)
    server = DefaultServer(agent)    
    server.run()                      


def run_once(no_remote: bool = False, out_format: str = "both", output_dir: str = "./security_reports"):
    agent = VPSSecurityAgent(save_dir=output_dir)
    if no_remote:
        text, data = fireworks_analyze({})
    else:
        evidence = collect_all_checks()
        text, data = fireworks_analyze(evidence)
    paths = []
    txt_path = None
    json_path = None
    if out_format in ("both","text"):
        txt_path = agent._save_report(text); paths.append(txt_path)
    if out_format in ("both","json"):
        json_path = agent._save_json(data); paths.append(json_path)
    print("Saved:", ", ".join(paths))

    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    if token and chat_id:
        try:
            _tg_send_text(token, chat_id, f"Linux VPS Security Audit\n{now_iso()}\n\n{text}")
            if txt_path:  _tg_send_document(token, chat_id, txt_path,  caption="Security audit report (TXT)")
            if json_path: _tg_send_document(token, chat_id, json_path, caption="Security audit remediation (JSON)")
            print("Telegram: sent")
        except Exception as e:
            print(f"Telegram: failed: {e}")




def _parse_every(spec: str) -> timedelta:
    """
    Parse 'every' interval like '30s', '15m', '2h', '1d'.
    Returns datetime.timedelta. Raises ValueError on bad input.
    """
    spec = (spec or "").strip().lower()
    if not spec:
        raise ValueError("Empty interval")
    units = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
    if spec.isdigit(): 
        return timedelta(minutes=int(spec))
    m = re.fullmatch(r"(\d+)\s*([smhd])", spec)
    if not m:
        raise ValueError("Use forms like 30s, 15m, 2h, 1d (or plain minutes, e.g., 15)")
    value, unit = int(m.group(1)), m.group(2)
    return timedelta(**{units[unit]: value})


def _run_periodic(every: timedelta, max_runs: int, no_remote: bool, out_format: str, output_dir: str):
    """
    Loop forever (or up to max_runs) running a scan each 'every' interval.
    Each run also pushes to Telegram if TELEGRAM_* envs are set (handled by run_once()).
    """
    runs = 0
    stop = {"flag": False}

    def _sig_handler(signum, frame):
        stop["flag"] = True

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    while not stop["flag"]:
        runs += 1
        print(f"[scheduler] run #{runs} starting …")
        try:
            run_once(no_remote=no_remote, out_format=out_format, output_dir=output_dir)
        except Exception as e:
            print(f"[scheduler] run #{runs} failed: {e}")
        else:
            print(f"[scheduler] run #{runs} completed.")
        if max_runs and runs >= max_runs:
            print("[scheduler] reached max runs; exiting.")
            break
        # sleep in small chunks so Ctrl-C is responsive
        sleep_left = every.total_seconds()
        while sleep_left > 0 and not stop["flag"]:
            t = 1.0 if sleep_left >= 1.0 else sleep_left
            time.sleep(t)
            sleep_left -= t


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Linux VPS Security Audit Agent")
    parser.add_argument("--once", action="store_true", help="Run one audit locally and exit")
    parser.add_argument("--no-remote", action="store_true", help="Do not call Fireworks; use baseline remediation")
    parser.add_argument("--format", choices=["text","json","both"], default="both", help="Choose output format")
    parser.add_argument("--output-dir", default="./security_reports", help="Directory for reports")
    parser.add_argument("--redact-index", action="store_true", help="Redact hostname/user in emitted index")
    parser.add_argument("--every", help="Run periodically at this interval (e.g., 15m, 2h, 1d). Implies repeated scans.")
    parser.add_argument("--max-runs", type=int, default=0, help="Stop after N runs (default: unlimited).")
    args = parser.parse_args()

    if args.once and args.every:
        parser.error("Use either --once or --every, not both.")

    if args.once:
        if args.no_remote:
            os.environ["NO_REMOTE"] = "1"
        os.environ["OUTPUT_FORMAT"] = args.format
        run_once(no_remote=args.no_remote, out_format=args.format, output_dir=args.output_dir)
    elif args.every:
        if args.no_remote:
            os.environ["NO_REMOTE"] = "1"
        os.environ["OUTPUT_FORMAT"] = args.format
        try:
            interval = _parse_every(args.every)
        except ValueError as ve:
            parser.error(str(ve))
        print(f"[scheduler] will run every {args.every} (format={args.format}, no_remote={args.no_remote})")
        _run_periodic(
            every=interval,
            max_runs=args.max_runs,
            no_remote=args.no_remote,
            out_format=args.format,
            output_dir=args.output_dir
        )
    else:
        run_server(output_dir=args.output_dir, redact_index=args.redact_index)
