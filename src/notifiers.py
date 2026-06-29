"""DEFCON Alert Notifiers — Telegram, Discord, Slack, PagerDuty, SMTP."""
import json, logging, os, smtplib, time
from email.message import EmailMessage
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode
from src.constants import DEFCON, Priority, AlertEvent

logger = logging.getLogger("defcon.notifiers")

# ── Cooldown ───────────────────────────────────────────────────────────────────

def _cooldown_path():
    from pathlib import Path
    return Path(os.environ.get("DEFCON_LOG_DIR",
               str(Path(__file__).parent.parent / "logs"))) / "alert_cooldowns.json"

def _load_cooldowns() -> dict:
    p = _cooldown_path()
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}

def _save_cooldowns(data: dict):
    p = _cooldown_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2))

def _is_in_cooldown(rule_key: str, cooldown_h: float) -> bool:
    if cooldown_h == 0:
        return False
    cooldowns = _load_cooldowns()
    last = cooldowns.get(rule_key, 0)
    return (time.time() - last) < (cooldown_h * 3600)

def _mark_cooldown(rule_key: str, cooldown_h: float):
    if cooldown_h == 0:
        return
    cooldowns = _load_cooldowns()
    cooldowns[rule_key] = time.time()
    _save_cooldowns(cooldowns)

# ── Telegram ─────────────────────────────────────────────────────────────────

def notify_telegram(alert: AlertEvent) -> bool:
    """Send alert via Telegram bot."""
    bot_token = os.environ.get("DEFCON_TELEGRAM_BOT_TOKEN", "")
    chat_id   = os.environ.get("DEFCON_TELEGRAM_CHAT_ID", "")
    topic_id  = os.environ.get("DEFCON_TELEGRAM_TOPIC_ID", "")

    if not bot_token or bot_token == "YOUR_BOT_TOKEN":
        logger.debug("Telegram: no bot token configured")
        return False

    payload = {
        "chat_id": chat_id,
        "text": f"{alert.priority.emoji} [{alert.priority.name}] DEFCON ALERT\n\n"
                f"<b>{alert.domain.upper()}</b>\n"
                f"{alert.headline}\n\n"
                f"<i>{alert.body[:200]}</i>",
        "parse_mode": "HTML",
    }
    if topic_id:
        payload["message_thread_id"] = topic_id

    try:
        body = urlencode(payload).encode()
        req = Request(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            data=body,
        )
        with urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            if result.get("ok"):
                logger.info("Telegram: sent ✓")
                return True
            logger.warning("Telegram: failed — %s", result)
    except Exception as e:
        logger.error("Telegram error: %s", e)
    return False

# ── Discord ───────────────────────────────────────────────────────────────────

def notify_discord(alert: AlertEvent, webhook_url: str = "") -> bool:
    """Send rich embed alert via Discord webhook."""
    url = webhook_url or os.environ.get("DISCORD_WEBHOOK_URL", "")
    if not url:
        logger.debug("Discord: no webhook URL configured")
        return False

    lvl = DEFCON(alert.level)
    embed = {
        "title": f"{alert.priority.emoji} {alert.domain.upper()} — {lvl.label}",
        "description": f"**{alert.headline}**\n{alert.body[:300]}",
        "color": lvl.discord_color,
        "footer": {"text": "DEFCON Monitor v3.1"},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if alert.source_url:
        embed["url"] = alert.source_url

    payload = json.dumps({"embeds": [embed]}).encode()

    try:
        req = Request(url, data=payload,
                      headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=10) as resp:
            if resp.status in (200, 204):
                logger.info("Discord: sent ✓")
                return True
    except Exception as e:
        logger.error("Discord error: %s", e)
    return False

# ── Slack ─────────────────────────────────────────────────────────────────────

def notify_slack(alert: AlertEvent, webhook_url: str = "") -> bool:
    """Send Slack Block Kit alert via webhook."""
    url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL", "")
    if not url:
        logger.debug("Slack: no webhook URL configured")
        return False

    lvl = DEFCON(alert.level)
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text",
                     "text": f"{alert.priority.emoji} DEFCON {alert.level} Alert",
                     "emoji": True}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Domain:*\n{alert.domain}"},
                {"type": "mrkdwn", "text": f"*Level:*\n{lvl.label}"},
                {"type": "mrkdwn", "text": f"*Priority:*\n{alert.priority.name}"},
            ]
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{alert.headline}*\n{alert.body[:200]}"}
        },
    ]

    payload = json.dumps({"blocks": blocks}).encode()

    try:
        req = Request(url, data=payload,
                      headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=10) as resp:
            if resp.status in (200, 204):
                logger.info("Slack: sent ✓")
                return True
    except Exception as e:
        logger.error("Slack error: %s", e)
    return False

# ── PagerDuty ─────────────────────────────────────────────────────────────────

def notify_pagerduty(alert: AlertEvent, routing_key: str = "") -> bool:
    """Send PagerDuty Events API v2 alert."""
    key = routing_key or os.environ.get("PAGERDUTY_ROUTING_KEY", "")
    if not key:
        logger.debug("PagerDuty: no routing key configured")
        return False

    payload = json.dumps({
        "routing_key": key,
        "event_action": "trigger",
        "payload": {
            "summary": f"DEFCON {alert.level} [{alert.priority.name}] {alert.domain}: {alert.headline}",
            "severity": {"critical": "critical", "high": "error",
                         "medium": "warning", "low": "info"}.get(alert.priority.name.lower(), "info"),
            "source": "DEFCON Monitor",
            "custom_details": {
                "domain": alert.domain,
                "level": alert.level,
                "priority": alert.priority.name,
                "body": alert.body,
                "source_url": alert.source_url,
            }
        }
    }).encode()

    try:
        req = Request(
            "https://events.pagerduty.com/v2/enqueue",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urlopen(req, timeout=10) as resp:
            if resp.status == 202:
                logger.info("PagerDuty: sent ✓")
                return True
    except Exception as e:
        logger.error("PagerDuty error: %s", e)
    return False

# ── Generic Webhook ───────────────────────────────────────────────────────────

def notify_webhook(alert: AlertEvent, webhook_url: str = "") -> bool:
    """POST JSON alert to any generic webhook URL."""
    url = webhook_url or os.environ.get("DEFCON_GENERIC_WEBHOOK_URL", "")
    if not url:
        return False

    payload = json.dumps({
        "domain": alert.domain,
        "level": alert.level,
        "priority": alert.priority.name,
        "headline": alert.headline,
        "body": alert.body,
        "source_url": alert.source_url,
        "indicators": alert.indicators,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }).encode()

    try:
        req = Request(url, data=payload,
                      headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=10) as resp:
            logger.info("Generic webhook: sent ✓")
            return True
    except Exception as e:
        logger.error("Generic webhook error: %s", e)
    return False

# ── SMTP Email ────────────────────────────────────────────────────────────────

def notify_email(subject: str, body: str) -> bool:
    """Send email via SMTP."""
    host = os.environ.get("SMTP_HOST", "")
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER", "")
    pw   = os.environ.get("SMTP_PASS", "")
    to_addr = os.environ.get("SMTP_TO", "")

    if not all([host, user, pw, to_addr]):
        logger.debug("Email: SMTP not fully configured")
        return False

    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"]    = user
        msg["To"]      = to_addr
        msg.set_content(body)
        with smtplib.SMTP(host, port) as server:
            server.ehlo()
            server.starttls()
            server.login(user, pw)
            server.send_message(msg)
        logger.info("Email: sent → %s", to_addr)
        return True
    except Exception as e:
        logger.error("Email error: %s", e)
        return False

# ── Master dispatch ───────────────────────────────────────────────────────────

def dispatch(alert: AlertEvent, cooldown_h: float = 2.0) -> list:
    """
    Send an alert through all configured channels.
    Returns list of (channel, success) tuples.
    """
    key = f"{alert.domain}:{alert.priority.name}"
    if _is_in_cooldown(key, cooldown_h):
        logger.info("Alert '%s' in cooldown — skipping", key)
        return []

    results = []
    if alert.priority == Priority.CRITICAL:
        # Critical → all channels
        results.append(("telegram", notify_telegram(alert)))
        results.append(("discord",  notify_discord(alert)))
        results.append(("slack",    notify_slack(alert)))
        results.append(("pagerduty", notify_pagerduty(alert)))
        results.append(("email",     notify_email(
            f"[CRITICAL] DEFCON {alert.level} — {alert.domain}", alert.body)))
        results.append(("webhook",  notify_webhook(alert)))
    elif alert.priority == Priority.HIGH:
        results.append(("telegram",  notify_telegram(alert)))
        results.append(("discord",   notify_discord(alert)))
        results.append(("webhook",   notify_webhook(alert)))
        results.append(("email",     notify_email(
            f"[HIGH] DEFCON {alert.level} — {alert.domain}", alert.body)))
    elif alert.priority == Priority.MEDIUM:
        results.append(("telegram",  notify_telegram(alert)))
        results.append(("webhook",   notify_webhook(alert)))
    # LOW/INFO → log only

    _mark_cooldown(key, cooldown_h)
    return [(c, s) for c, s in results if s]
