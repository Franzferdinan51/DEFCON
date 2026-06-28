#!/usr/bin/env python3
"""
DEFCON Dashboard — live ASCII terminal display.
Shows current level, score, 6-domain breakdown, trend, and last scan.
"""
import sys, os
from pathlib import Path
BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

from src.constants import DEFCON, DOMAIN_WEIGHT
from src.state import StateManager
import urllib.request, json
from datetime import datetime

CLEAN_NAMES = {
    "defcon": "DEFCON",
    "weather": "Weather",
    "seismic": "Seismic",
    "biological": "Biological",
    "food": "Food",
    "cyber": "Cyber",
}

EMOJI = {1: "💀", 2: "🚨", 3: "⚠️", 4: "📢", 5: "✅"}
TREND = {"▲": "📈", "▼": "📉", "◆": "➡️"}


def color(n: int) -> str:
    """Return ANSI 256-color code for DEFCON level 1-5."""
    codes = {1: "\033[38;5;196m", 2: "\033[38;5;202m",
             3: "\033[38;5;214m", 4: "\033[38;5;226m", 5: "\033[38;5;082m"}
    return codes.get(n, "\033[0m")

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def fetch_clawdwatch_status():
    try:
        req = urllib.request.Request(
            "http://localhost:3444/status",
            headers={"User-Agent": "curl/8.4.0"}
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except Exception:
        return None


def level_bar(value: int, maximum: int, width: int = 20) -> str:
    filled = int(width * value / max(maximum, 1))
    return "█" * filled + "░" * (width - filled)


def threat_color(score: int) -> str:
    if score >= 80: return color(1)
    if score >= 60: return color(2)
    if score >= 40: return color(3)
    if score >= 20: return color(4)
    return color(5)


def main():
    state = StateManager()
    s = state._load()

    level = s.get("current_level", 5)
    score = s.get("threat_score", 0)
    scores = s.get("scores", {})
    history = s.get("history", [])
    threats = s.get("active_threats", [])

    # Trend
    delta = 0
    if len(history) >= 2:
        delta = history[0].get("score", 0) - history[1].get("score", 0)
    trend_sym = "▲" if delta > 0 else "▼" if delta < 0 else "◆"
    trend_icon = TREND.get(trend_sym, "➡️")
    trend_str = f"{trend_icon} {trend_sym}{abs(delta):+d}pt"

    now = datetime.now().strftime("%a %b %d, %Y  %H:%M:%S")
    scan_ts = s.get("last_check", "never")
    if scan_ts and "T" in str(scan_ts):
        scan_ts = str(scan_ts).split("T")[1][:8]

    cw = fetch_clawdwatch_status()
    cw_ver = cw.get("version", "?") if cw else "DOWN"
    cw_up = "✅" if cw else "❌"

    lvl = DEFCON(level)
    sep = "═" * 56

    out = []
    out.append("")
    out.append(f"{BOLD}{sep}{RESET}")
    out.append(f"  {BOLD}🛡  DEFCON THREAT MONITOR  —  {now}{RESET}")
    out.append(f"{BOLD}{sep}{RESET}")
    out.append("")
    out.append(f"  {BOLD}Overall Level :{RESET}  {color(level)}{BOLD}DEFCON {level}{RESET}"
               f"  [{lvl.label}]{RESET}  {trend_str}")
    out.append(f"  {BOLD}Threat Score  :{RESET}  {threat_color(score)}"
               f"{BOLD}{score}/100{RESET}  {level_bar(score, 100)}")
    out.append(f"  {BOLD}Last Scan     :{RESET}  {scan_ts or 'never'}")

    # ── Domain breakdown ──────────────────────────────────────────────────
    out.append(f"\n{BOLD}  Domain Breakdown:{RESET}")
    out.append(f"  {DIM}{'─'*56}{RESET}")

    domain_order = ["defcon", "weather", "seismic", "biological", "food", "cyber"]
    for domain in domain_order:
        info = scores.get(domain, {})
        lvl_int = info.get("level", 5)
        value = info.get("value", 0)
        max_w = DOMAIN_WEIGHT.get(domain, 0)
        detail = info.get("detail", "")

        name = CLEAN_NAMES.get(domain, domain)
        icon = EMOJI.get(lvl_int, "❓")
        lvl_color = color(lvl_int)
        bar = level_bar(value, max_w, 16)

        # Detail line
        if isinstance(detail, list) and len(detail):
            if isinstance(detail[0], dict):
                ev = detail[0].get("event", "") or detail[0].get("place", "")
            else:
                ev = str(detail[0])
            detail_str = f"→ {ev[:36]}"
        elif isinstance(detail, str):
            detail_str = f"→ {detail[:36]}" if detail and detail != "not set" else ""
        else:
            detail_str = ""

        out.append(
            f"  {icon}  {name:<12} {lvl_color}Lv{lvl_int}{RESET}  "
            f"{bar}  {value:>3}/{max_w:>2}  {detail_str}"
        )

    # ── Active threats ───────────────────────────────────────────────────
    if threats:
        out.append(f"\n{BOLD}  Active Threats:{RESET}")
        out.append(f"  {DIM}{'─'*56}{RESET}")
        for t in threats[:5]:
            cat = t.get("category", "?")
            desc = t.get("description", "?")
            lvl_t = t.get("level", "?")
            out.append(f"  ⚠  [{cat.upper()}] DEFCON {lvl_t} — {desc[:44]}")

    # ── System status ─────────────────────────────────────────────────────
    out.append(f"\n{BOLD}  System:{RESET}")
    out.append(f"  {DIM}{'─'*56}{RESET}")
    out.append(f"  {'✅' if cw else '❌'}  ClawdWatch  : {cw_up}  v{cw_ver}")
    out.append(f"  📄  History    : {len(history)} entries")
    out.append(f"  📁  State File : {state.path}")

    # ── DEFCON level guide ────────────────────────────────────────────────
    out.append(f"\n{BOLD}  DEFCON Levels:{RESET}")
    out.append(f"  {DIM}{'─'*56}{RESET}")
    guide = [
        (1, "💀 BLACK",  "War imminent / nuclear conflict"),
        (2, "🚨 RED",   "Armed forces ≤6-hr readiness"),
        (3, "⚠️  ORANGE", "Enhanced vigilance, 15-min stage"),
        (4, "📢 YELLOW", "Intelligence watching, increased ops"),
        (5, "✅ GREEN",  "Normal peacetime posture"),
    ]
    for lvl_i, name, desc in guide:
        c = color(lvl_i)
        marker = "◀──" if lvl_i == level else "    "
        out.append(f"  {marker}  {c}{name:<12}{RESET}  {desc}")

    out.append(f"\n{BOLD}{sep}{RESET}")
    out.append("  Run: python defcon_monitor.py       # full scan")
    out.append("  Run: python defcon_alert.py         # check alerts")
    out.append("  Run: python defcon_health.py        # diagnostics")
    out.append(f"{BOLD}{sep}{RESET}")
    out.append("")

    print("\n".join(out))


if __name__ == "__main__":
    main()
