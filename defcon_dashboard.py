#!/usr/bin/env python3
"""
DEFCON Dashboard v3.1 — 15-domain ASCII terminal display.
"""
import sys as _sys
from pathlib import Path as _Path
_BASE_DIR = _Path(__file__).parent
_SYS_PATH = str(_BASE_DIR)
if _SYS_PATH not in _sys.path:
    _sys.path.insert(0, _SYS_PATH)

from src.constants import DEFCON, DOMAIN_META
from src.state import StateManager

EMOJI = {
    "geopolitical":    "🌍",
    "cyber":           "💻",
    "seismic":         "🌋",
    "weather":         "⛈️",
    "volcano":         "🌋",
    "wildfire":        "🔥",
    "public_health":   "🦠",
    "economic":        "📊",
    "space_weather":   "🌌",
    "maritime":        "✈️",
    "nuclear":         "☢️",
    "biological":       "🧬",
    "food":            "🌾",
    "infrastructure":   "🏗️",
    "disinfo":         "📰",
}

TREND_EMOJI = {"escalating": "📈", "de-escalating": "📉", "stable": "➡️"}

LVL_COLOR = {
    1: "\033[38;5;196m",
    2: "\033[38;5;202m",
    3: "\033[38;5;214m",
    4: "\033[38;5;226m",
    5: "\033[38;5;082m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"


def bar(value: float, maximum: float, width: int = 14) -> str:
    filled = int(width * max(0, min(1, value / max(maximum, 1))))
    return "█" * filled + "░" * (width - filled)


def main():
    state = StateManager()
    s = state._load()

    level     = s.get("current_level", 5)
    score     = s.get("threat_score", 0)
    trend     = s.get("trend", "stable")
    anomalies = s.get("anomaly_domains", [])
    scores    = s.get("scores", {})
    history   = s.get("history", [])[:5]
    threats   = s.get("active_threats", [])[:4]

    # Delta
    delta = 0
    if len(history) >= 2:
        delta = history[0].get("score", 0) - (history[1].get("score") or 0)

    now = _import("datetime").datetime.now().strftime("%a %b %d, %Y  %H:%M:%S")
    scan_ts = s.get("last_check", "never")
    if scan_ts and "T" in str(scan_ts):
        scan_ts = str(scan_ts).replace("T", " ")[:19]

    lvl = DEFCON(level)
    c = LVL_COLOR.get(level, "")
    sep = "═" * 58

    lines = [
        "",
        f"{BOLD}{sep}{RESET}",
        f"  {BOLD}🛡  DEFCON THREAT MONITOR  —  {now}{RESET}",
        f"{BOLD}{sep}{RESET}",
        "",
        f"  {BOLD}Overall Level  :{RESET}  {c}{BOLD}DEFCON {level}{RESET}  [{lvl.label}]{RESET}",
        f"  {BOLD}Threat Score   :{RESET}  {c}{score}/100{RESET}  {bar(score, 100, 22)}",
        f"  {BOLD}Trend           :{RESET}  {TREND_EMOJI.get(trend,'➡️')}  {trend.capitalize()}  {delta:+.0f}pt",
        f"  {BOLD}Last Scan       :{RESET}  {scan_ts or 'never'}",
    ]
    if anomalies:
        lines.append(f"  {BOLD}⚠️  Anomalies    :{RESET}  {', '.join(anomalies)}")

    # ── 15-domain grid ────────────────────────────────────────────────────
    lines += [
        "",
        f"{BOLD}  Domain Breakdown (15 domains):{RESET}",
        f"  {DIM}{'─'*58}{RESET}",
    ]

    domain_order = [
        "geopolitical", "cyber", "public_health", "economic",
        "weather", "seismic", "nuclear", "biological",
        "food", "infrastructure", "space_weather", "volcano",
        "wildfire", "maritime", "disinfo",
    ]

    for did in domain_order:
        info = scores.get(did, {})
        lvl_int = info.get("level", 5)
        val     = info.get("value", 0.0)
        weight  = info.get("weight", DOMAIN_META.get(did, {}).get("weight", 0))
        detail  = info.get("detail", "")
        meta    = DOMAIN_META.get(did, {})
        label   = meta.get("label", did)
        icon    = EMOJI.get(did, "•")
        lc      = LVL_COLOR.get(lvl_int, "")
        b       = bar(val, weight, 12) if weight else "░" * 12
        det_str = f" → {str(detail)[:30]}" if detail and detail not in ("manual", "not set", "" ) else ""
        lines.append(
            f"  {icon}  {label:<17} {lc}Lv{lvl_int}{RESET}  "
            f"{b}  {val:>5.1f}/{weight:<5.0f}{det_str}"
        )

    # ── Active threats ──────────────────────────────────────────────────
    if threats:
        lines += ["", f"{BOLD}  Active Threats:{RESET}", f"  {DIM}{'─'*58}{RESET}"]
        for t in threats:
            cat = t.get("category", "?")
            desc = t.get("description", "?")[:50]
            lvl_t = t.get("level", "?")
            lines.append(f"  ⚠  [{cat.upper()}] DEFCON {lvl_t} — {desc}")

    # ── DEFCON guide ────────────────────────────────────────────────────
    lines += [
        "",
        f"{BOLD}  DEFCON Level Guide:{RESET}",
        f"  {DIM}{'─'*58}{RESET}",
    ]
    guide = [
        (1, "💀 BLACK / COCKED PISTOL",  "War imminent / nuclear conflict underway"),
        (2, "🚨 RED / FAST PACE",          "Armed forces ≤6-hour readiness"),
        (3, "⚠️  ORANGE / ROUND HOUSE",    "Enhanced vigilance; 15-min mobilization"),
        (4, "📢 YELLOW / DOUBLE TAKE",    "Intelligence watching, increased ops"),
        (5, "✅ GREEN / FADE OUT",          "Normal peacetime posture"),
    ]
    for lvl_i, name, desc in guide:
        lc = LVL_COLOR.get(lvl_i, "")
        mrk = "◀──" if lvl_i == level else "    "
        lines.append(f"  {mrk}  {lc}{name:<22}{RESET}  {desc}")

    lines += [
        f"{BOLD}{sep}{RESET}",
        "  Run: python defcon_monitor.py --deep      # full 15-domain scan",
        "  Run: python defcon_monitor.py --daemon 1800  # daemon (30min)",
        "  Run: python defcon_monitor.py --export json  # export history",
        "  Run: python defcon_web.py                  # web dashboard",
        f"{BOLD}{sep}{RESET}",
        "",
    ]
    print("\n".join(lines))


def _import(name):
    return __import__(name)


if __name__ == "__main__":
    main()
