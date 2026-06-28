#!/usr/bin/env python3
"""
DEFCON Alert Engine — rules-based alert dispatcher.
Fires Telegram/email notifications when domain thresholds are crossed.
Cooldown prevents alert flooding (default: 2h between non-critical alerts).
"""
import sys, os, json, subprocess, time, smtplib
from pathlib import Path
BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

from src.state import StateManager
from src.constants import DEFCON

# ── Alert Rules ────────────────────────────────────────────────────────────────

RULES = [
    # (field_path, condition_fn, priority, template)
    # Conditions receive the raw value and return True if the rule fires.
    # field_path: dot-notation into state/scores dict

    # --- Geopolitical ---
    {
        "name": "DEFCON 1",
        "field": "current_level",
        "condition": lambda v: v == 1,
        "priority": "critical",
        "template": "💀 DEFCON 1 — WAR IMMINENT. Execute survival protocols NOW.",
        "cooldown_h": 0,  # Never suppress critical
    },
    {
        "name": "DEFCON 2",
        "field": "current_level",
        "condition": lambda v: v == 2,
        "priority": "critical",
        "template": "🚨 DEFCON 2 — Armed forces mobilizing. Review evacuation plans.",
        "cooldown_h": 0,
    },
    {
        "name": "DEFCON 3",
        "field": "current_level",
        "condition": lambda v: v == 3,
        "priority": "high",
        "template": "⚠️ DEFCON 3 — Enhanced vigilance. Heightened readiness.",
        "cooldown_h": 2,
    },
    # --- Weather ---
    {
        "name": "Tornado Warning",
        "field": "scores.weather.detail",
        "condition": lambda v: isinstance(v, str) and "Tornado" in v,
        "priority": "critical",
        "template": "🌪️ TORNADO WARNING — Take cover immediately!",
        "cooldown_h": 0,
    },
    {
        "name": "Heat Advisory",
        "field": "scores.weather.detail",
        "condition": lambda v: isinstance(v, str) and "Heat" in v,
        "priority": "medium",
        "template": "🌡️ Heat Advisory in effect — stay hydrated, check on vulnerable neighbors.",
        "cooldown_h": 6,
    },
    {
        "name": "Winter Storm",
        "field": "scores.weather.detail",
        "condition": lambda v: isinstance(v, str) and "Winter" in v,
        "priority": "high",
        "template": "❄️ Winter Storm Warning — avoid travel, stock supplies.",
        "cooldown_h": 4,
    },
    # --- Biological ---
    {
        "name": "H5N1 Human Case",
        "field": "scores.biological.detail",
        "condition": lambda v: isinstance(v, str) and v not in ("", "not set"),
        "priority": "critical",
        "template": "🦠 Biological alert: {detail}",
        "cooldown_h": 0,
    },
    # --- Cyber ---
    {
        "name": "npm Critical Vulns",
        "field": "scores.cyber.raw",
        "condition": lambda v: v is not None and v > 10,
        "priority": "high",
        "template": "💻 npm audit: {vulns} vulnerabilities detected — patch immediately.",
        "cooldown_h": 12,
    },
    {
        "name": "npm Elevated Vulns",
        "field": "scores.cyber.raw",
        "condition": lambda v: v is not None and 5 < v <= 10,
        "priority": "medium",
        "template": "💻 npm audit: {vulns} vulnerabilities — review and remediate.",
        "cooldown_h": 24,
    },
]

PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
PRIORITY_EMOJI = {"critical": "🔴", "high": "🚨", "medium": "⚠️", "low": "ℹ️"}
LOG_FILE = Path(os.environ.get(
    "DEFCON_LOG_DIR", str(BASE_DIR / "logs")
)) / f"defcon-alerts-{time.strftime('%Y%m%d')}.log"


def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def get_nested(d: dict, path: str):
    """e.g. get_nested(state, 'scores.cyber.raw') → value or None"""
    keys = path.split(".")
    for k in keys:
        if not isinstance(d, dict):
            return None
        d = d.get(k, {})
    return d if d != {} else None


def send_telegram(message: str, priority: str):
    """Send alert via Telegram bot."""
    try:
        state = StateManager()._load()
        cfg = state.get("contacts", {}).get("telegram", {})
        token = cfg.get("bot_token", "")
        chat_id = cfg.get("chat_id", "")
        topic_id = cfg.get("topic_id") or None

        if not token or token == "YOUR_BOT_TOKEN":
            log("Telegram: skipped — no bot token configured")
            return False

        import urllib.request, urllib.parse
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
        }
        if topic_id:
            payload["message_thread_id"] = topic_id

        body = urllib.parse.urlencode(payload).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=body,
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            if result.get("ok"):
                log(f"Telegram: sent ✓")
                return True
            else:
                log(f"Telegram: failed — {result}")
                return False
    except Exception as e:
        log(f"Telegram error: {e}")
        return False


def send_email(subject: str, body: str):
    """Send email via SMTP — configure SMTP_* env vars."""
    host = os.environ.get("SMTP_HOST", "")
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER", "")
    pw = os.environ.get("SMTP_PASS", "")
    to_addr = os.environ.get("SMTP_TO", "")

    if not host or not to_addr:
        log("Email: skipped — SMTP not configured (set SMTP_HOST/SMTP_TO env vars)")
        return False

    try:
        import smtplib
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = user
        msg["To"] = to_addr
        msg.set_content(body)
        with smtplib.SMTP(host, port) as server:
            server.ehlo()
            server.starttls()
            server.login(user, pw)
            server.send_message(msg)
        log(f"Email: sent → {to_addr}")
        return True
    except Exception as e:
        log(f"Email error: {e}")
        return False


def load_cooldowns() -> dict:
    p = LOG_FILE.parent / "alert_cooldowns.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}


def save_cooldowns(data: dict):
    p = LOG_FILE.parent / "alert_cooldowns.json"
    p.write_text(json.dumps(data, indent=2))


def is_in_cooldown(rule_name: str, cooldown_h: float) -> bool:
    if cooldown_h == 0:
        return False
    cooldowns = load_cooldowns()
    last = cooldowns.get(rule_name, 0)
    return (time.time() - last) < (cooldown_h * 3600)


def mark_cooldown(rule_name: str):
    cooldowns = load_cooldowns()
    cooldowns[rule_name] = time.time()
    save_cooldowns(cooldowns)


def resolve_template(template: str, state: dict) -> str:
    """Substitute {field.path} in template with live state values."""
    import re
    def replacer(m):
        path = m.group(1)
        val = get_nested(state, path)
        return str(val) if val is not None else m.group(0)
    return re.sub(r"\{([\w.]+)\}", replacer, template)


# ── Main ──────────────────────────────────────────────────────────────────────

def run_alert_engine():
    log("=== DEFCON Alert Engine START ===")
    state = StateManager()._load()
    current_level = state.get("current_level", 5)
    scores = state.get("scores", {})

    fired = []

    for rule in RULES:
        field = rule["field"]
        raw_val = get_nested(state, field)
        if raw_val is None:
            continue

        try:
            triggers = rule["condition"](raw_val)
        except Exception as e:
            log(f"Rule '{rule['name']}' condition error: {e}")
            continue

        if not triggers:
            continue

        # Check cooldown
        if is_in_cooldown(rule["name"], rule["cooldown_h"]):
            log(f"Rule '{rule['name']}' — in cooldown, skipping")
            continue

        priority = rule["priority"]
        emoji = PRIORITY_EMOJI.get(priority, "ℹ️")
        template = resolve_template(rule["template"], state)
        full_msg = f"{emoji} [{priority.upper()}] {template}"

        log(f"TRIGGERED: {rule['name']} ({priority}) → {template}")

        # Dispatch
        if priority in ("critical", "high"):
            send_telegram(full_msg, priority)
            send_email(
                subject=f"[{priority.upper()}] DEFCON Alert — {rule['name']}",
                body=template,
            )
        elif priority == "medium":
            send_telegram(full_msg, priority)
        # low priority: log only

        mark_cooldown(rule["name"])
        fired.append({"rule": rule["name"], "priority": priority, "msg": template})

    if fired:
        log(f"Alert engine: {len(fired)} alert(s) fired")
        # Update last_alert_sent in state
        StateManager().update({"last_alert_sent": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    else:
        log("Alert engine: no rules triggered.")

    log("=== DEFCON Alert Engine DONE ===")
    return fired


if __name__ == "__main__":
    results = run_alert_engine()
    if results:
        for r in results:
            print(f"  → [{r['priority']}] {r['rule']}: {r['msg']}")
    else:
        print("No alerts triggered.")
