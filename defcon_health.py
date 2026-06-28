#!/usr/bin/env python3
"""
DEFCON System Health Check — validates all integrations and state integrity.
Exit code 0 = all pass, 1 = failures, 2 = degraded.
"""
import sys, os, json, traceback
from pathlib import Path
BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

from src.state import StateManager
from src.fetcher import fetch, fetch_json

passed = []
failed = []
warned = []


def ok(name, detail=""):
    passed.append((name, detail))


def fail(name, detail=""):
    failed.append((name, detail))


def warn(name, detail=""):
    warned.append((name, detail))


def section(title):
    bar = "─" * 52
    print(f"\n{bar}")
    print(f"  {title}")
    print(f"{bar}")


def main():
    print("\n" + "▓" * 52)
    print("  DEFCON SYSTEM HEALTH CHECK  v3.0")
    print("▓" * 52)

    # ── 1. State file ────────────────────────────────────────────────────
    section("STATE FILE")
    try:
        state = StateManager()
        s = state._load()
        schema = s.get("schema_version", "?")
        lvl = s.get("current_level", "?")
        score = s.get("threat_score", "?")
        ok("State file", f"readable — schema {schema}, level={lvl}, score={score}")
    except Exception as e:
        fail("State file", str(e))
        print("  Cannot continue — state file is required.")
        return False

    # ── 2. Level/score consistency ────────────────────────────────────────
    from src.constants import score_to_level
    try:
        level = s.get("current_level", 5)
        score = s.get("threat_score", 0)
        expected = score_to_level(score)
        if expected.value == level:
            ok("Level/score consistency", f"level={level}, score={score} ✓")
        else:
            fail("Level/score consistency",
                 f"score={score} maps to level={expected.value}, "
                 f"but state has level={level}")
    except Exception as e:
        fail("Level/score consistency", str(e))

    # ── 3. ClawdWatch ────────────────────────────────────────────────────
    section("CLAWDWATCH (port 3444)")
    try:
        d = fetch_json("http://localhost:3444/status", timeout=6)
        if d:
            ver = d.get("version", "?")
            regions = d.get("regions", 0)
            feeds = d.get("newsFeeds", 0)
            ok("ClawdWatch /status", f"OK — v{ver}, {regions} regions, {feeds} feeds")
            # DEFCON endpoint
            d2 = fetch_json("http://localhost:3444/defcon", timeout=6)
            if d2:
                lvl = d2.get("level", "?")
                ok("ClawdWatch /defcon", f"level={lvl}")
            else:
                fail("ClawdWatch /defcon", "no response")
        else:
            fail("ClawdWatch", "no response from /status")
    except Exception as e:
        fail("ClawdWatch", str(e))
        warn("ClawdWatch", "optional — monitor continues with defconlevel.com fallback")

    # ── 4. defconlevel.com ────────────────────────────────────────────────
    section("DEFCONLEVEL.COM")
    try:
        result = fetch("https://www.defconlevel.com/current-level", timeout=12)
        if result.success:
            ok("defconlevel.com", f"reachable — {result.status_code} — {result.elapsed_ms:.0f}ms")
        else:
            fail("defconlevel.com", result.error)
    except Exception as e:
        fail("defconlevel.com", str(e))

    # ── 5. NWS / Weather ─────────────────────────────────────────────────
    section("NWS WEATHER (api.weather.gov)")
    zone = os.environ.get("NWS_ZONE", "OHZ061")
    try:
        d = fetch_json(f"https://api.weather.gov/alerts/active?zone={zone}", timeout=10)
        if d is not None:
            count = len(d.get("features", []))
            ok("NWS alerts API", f"zone={zone}, {count} active alert(s)")
        else:
            fail("NWS alerts API", "no data")
    except Exception as e:
        fail("NWS alerts API", str(e))

    # ── 6. USGS Seismic ──────────────────────────────────────────────────
    section("USGS SEISMIC")
    try:
        url = ("https://earthquake.usgs.gov/fdsnws/event/1/query"
               "?format=geojson&minmagnitude=6&orderby=magnitude")
        d = fetch_json(url, timeout=15)
        if d is not None:
            total = len(d.get("features", []))
            ok("USGS earthquake feed", f"{total} M6+ events in feed")
        else:
            warn("USGS earthquake feed", "no data returned")
    except Exception as e:
        warn("USGS earthquake feed", str(e))

    # ── 7. Scripts / module integrity ─────────────────────────────────────
    section("MODULE INTEGRITY")
    for module in ["constants", "state", "fetcher"]:
        try:
            m = __import__(f"src.{module}")
            ok(f"Module src.{module}", "imports OK")
        except Exception as e:
            fail(f"Module src.{module}", str(e))

    for script in ["defcon_monitor.py", "defcon_dashboard.py",
                   "defcon_alert.py", "defcon_web.py"]:
        p = BASE_DIR / script
        if p.exists():
            ok(f"Script {script}", "present")
        else:
            fail(f"Script {script}", "missing")

    # ── 8. History integrity ─────────────────────────────────────────────
    section("HISTORY")
    hist = s.get("history", [])
    if len(hist) == 0:
        warn("History", "empty — run defcon_monitor.py first")
    else:
        ok("History", f"{len(hist)} entries")
        # Check monotonic timestamp order
        timestamps = [h.get("ts", "") for h in hist]
        if timestamps == sorted(timestamps, reverse=True):
            ok("History order", "newest-first ✓")
        else:
            warn("History order", "may not be sorted newest-first")

    # ── 9. Alert contacts ────────────────────────────────────────────────
    section("ALERT CONTACTS")
    contacts = s.get("contacts", {}).get("telegram", {})
    token = contacts.get("bot_token", "")
    if token and token != "YOUR_BOT_TOKEN":
        ok("Telegram bot token", "configured")
    else:
        warn("Telegram bot token", "not set — alerts will be skipped")

    # ── 10. Environment ──────────────────────────────────────────────────
    section("ENVIRONMENT")
    for var in ["DEFCON_STATE_DIR", "NWS_ZONE", "CLAWDWATCH_URL", "DEFCON_LOG_DIR"]:
        val = os.environ.get(var, "")
        if val:
            ok(f"Env {var}", val[:60])
        else:
            warn(f"Env {var}", "not set (using defaults)")

    # ── Summary ──────────────────────────────────────────────────────────
    total = len(passed) + len(failed) + len(warned)
    sep = "─" * 52
    print(f"\n{sep}")
    print(f"  PASS {len(passed)}/{total}   FAIL {len(failed)}/{total}   "
          f"WARN {len(warned)}/{total}")
    print(f"{sep}")

    if failed:
        print("\n  ❌ FAILURES:")
        for name, detail in failed:
            print(f"     • {name}" + (f": {detail}" if detail else ""))

    if warned:
        print("\n  ⚠️  WARNINGS:")
        for name, detail in warned:
            print(f"     • {name}" + (f": {detail}" if detail else ""))

    if not failed:
        print("\n  ✅ ALL SYSTEMS NOMINAL")
        return True
    elif len(failed) <= 2:
        print("\n  🟡 DEGRADED — review failures above")
        return None  # degraded
    else:
        print("\n  🔴 CRITICAL — fix failures before relying on alerts")
        return False


if __name__ == "__main__":
    ok_flag = main()
    sys.exit(0 if ok_flag is True else (1 if ok_flag is False else 2))
