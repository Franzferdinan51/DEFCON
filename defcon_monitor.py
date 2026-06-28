#!/usr/bin/env python3
"""
DEFCON Level Monitor — v3.0
Real-time OSINT threat assessment across 6 domains.
Reads config from config.py — no personal info embedded.
"""
import os, sys, json, logging, re, time, ssl, textwrap
from datetime import datetime, timezone
from pathlib import Path

# ── Project paths ─────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

from src.constants import DEFCON, DOMAIN_WEIGHT, score_to_level
from src.state import StateManager
from src.fetcher import fetch, fetch_json

# ── Logging ────────────────────────────────────────────────────────────────────
LOG_DIR = Path(os.environ.get("DEFCON_LOG_DIR", str(BASE_DIR / "logs")))
LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_DIR / f"defcon-monitor-{datetime.now().strftime('%Y%m%d')}.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("defcon.monitor")


# ── Domain Scanners ────────────────────────────────────────────────────────────

class DefconScanner:
    """ClawdWatch + defconlevel.com OSINT aggregation."""

    CLAWDWATCH_URL = os.environ.get("CLAWDWATCH_URL", "http://localhost:3444")

    def scan(self) -> dict:
        results = {}
        best_level = 5

        # 1. ClawdWatch (if running locally)
        cw_level = self._scan_clawdwatch()
        if cw_level is not None:
            results["clawdwatch"] = {"level": cw_level, "source": "ClawdWatch"}
            best_level = min(best_level, cw_level)

        # 2. defconlevel.com (web scrape)
        dl_level = self._scan_defconlevel_com()
        if dl_level is not None:
            results["defconlevel_com"] = {"level": dl_level, "source": "defconlevel.com"}
            best_level = min(best_level, dl_level)

        return {"level": best_level, "sources": results}

    def _scan_clawdwatch(self):
        try:
            d = fetch_json(f"{self.CLAWDWATCH_URL}/defcon", timeout=8)
            if d:
                lvl = d.get("level", 5)
                log.info("ClawdWatch → DEFCON %s", lvl)
                return lvl
        except Exception as e:
            log.warning("ClawdWatch unavailable: %s", e)
        return None

    def _scan_defconlevel_com(self):
        result = fetch("https://www.defconlevel.com/current-level", timeout=12)
        if not result.success:
            return None
        html_lower = result.content.lower()
        # Look for DEFCON N pattern
        m = re.search(r"defcon\s+(\d)\b", html_lower)
        if m:
            lvl = int(m.group(1))
            log.info("defconlevel.com → DEFCON %s", lvl)
            return lvl
        return None


class WeatherScanner:
    """NWS alerts via api.weather.gov."""

    def scan(self) -> dict:
        zone = os.environ.get("NWS_ZONE", "OHZ061")
        result = fetch_json(f"https://api.weather.gov/alerts/active?zone={zone}", timeout=10)
        if result is None:
            return {"alerts": [], "level": 5}

        features = result.get("features", [])
        active = [f for f in features
                  if f.get("properties", {}).get("event", "") not in ("", "None")]

        level = max(1, 5 - len(active))
        log.info("NWS %s → %s alert(s) → level %s", zone, len(active), level)
        return {
            "alerts": [
                {"event": a.get("properties", {}).get("event", ""),
                 "headline": a.get("properties", {}).get("headline", ""),
                 "severity": a.get("properties", {}).get("severity", "")}
                for a in active[:5]
            ],
            "level": level,
            "zone": zone,
        }


class SeismicScanner:
    """USGS earthquake feed — M6+ events in last 30 days."""

    USGS_URL = (
    "https://earthquake.usgs.gov/fdsnws/event/1/query"
    "?format=geojson&minmagnitude=6&orderby=magnitude"
    )

    def scan(self) -> dict:
        result = fetch_json(self.USGS_URL, timeout=15)
        if result is None:
            return {"events": [], "level": 5}
        features = result.get("features", [])
        major = [f for f in features if f.get("properties", {}).get("mag", 0) >= 6.5]
        level = max(1, 5 - len(major))
        log.info("USGS → %s M6+ events, %s M6.5+ → level %s",
                 len(features), len(major), level)
        return {
            "events": [
                {"mag": f.get("properties", {}).get("mag"),
                 "place": f.get("properties", {}).get("place"),
                 "url": f.get("properties", {}).get("url")}
                for f in features[:10]
            ],
            "level": level,
            "total_m6_plus": len(features),
            "major_count": len(major),
        }


class BiologicalScanner:
    """Manual biological threat level — read from state (set by set-level)."""
    # No public API for H5N1 human cases that is reliable without a paid key.
    # Users set this manually via defcon_set_level.py or the dashboard.

    def scan(self) -> dict:
        state = StateManager()
        bio = state._load().get("scores", {}).get("biological", {})
        level = bio.get("level", 5)
        detail = bio.get("detail", "not set")
        log.info("Biological → level %s (%s)", level, detail)
        return {"level": level, "detail": detail}


class FoodScanner:
    """Manual food/commodity supply threat — read from state."""
    # Food security threats are episodic and don't have a free real-time API.
    # Users set this manually or via cron scraping of FAO/WFP feeds.

    def scan(self) -> dict:
        state = StateManager()
        food = state._load().get("scores", {}).get("food", {})
        level = food.get("level", 5)
        detail = food.get("detail", "not set")
        log.info("Food/Commodity → level %s (%s)", level, detail)
        return {"level": level, "detail": detail}


class CyberScanner:
    """npm audit vulnerability scanner — runs in Node.js project dirs."""

    def scan(self) -> dict:
        import subprocess
        vulns = 0
        # Try to find a package.json and run npm audit
        dirs_to_try = [
            Path(os.environ.get("NODE_PROJECT_DIR", str(BASE_DIR.parent))),
            Path(__file__).parent,
        ]
        for proj_dir in dirs_to_try:
            pkg = proj_dir / "package.json"
            if pkg.exists():
                try:
                    r = subprocess.run(
                        ["npm", "audit", "--json"],
                        cwd=str(proj_dir),
                        capture_output=True, timeout=30,
                    )
                    try:
                        d = json.loads(r.stdout)
                        vulns = d.get("metadata", {}).get(
                            "vulnerabilities", {}).get("total", 0)
                        break
                    except (json.JSONDecodeError, FileNotFoundError):
                        pass
                except Exception:
                    pass

        level = 5 if vulns == 0 else (4 if vulns <= 3 else 3 if vulns <= 7 else 2)
        log.info("npm audit → %s vulns → level %s", vulns, level)
        return {"vulns": vulns, "level": level}


# ── Composite Engine ───────────────────────────────────────────────────────────

class CompositeEngine:
    """
    Converts per-domain levels into a 0-100 composite threat score.
    Score bands: 0-19→DEFCON5, 20-39→DEFCON4, 40-59→DEFCON3,
                 60-79→DEFCON2, 80+ →DEFCON1
    """

    def __init__(self):
        self.weights = {
            "defcon":      32,   # Geopolitical/military — primary driver
            "weather":      20,   # Local NWS alerts
            "seismic":      15,   # M6+ global earthquakes
            "biological":  15,   # Manual H5N1 watch
            "food":        10,   # Manual food security
            "cyber":        8,   # npm audit
        }

    def compute(self, domain_levels: dict) -> tuple[int, DEFCON]:
        """
        domain_levels: {name: level_int (1-5)}
        Returns: (score_0_to_100, DEFCON)
        """
        total = 0
        for domain, lvl in domain_levels.items():
            weight = self.weights.get(domain, 0)
            # Convert level to threat points: 5→0, 4→weight*0.25, 3→weight*0.5, 2→weight*0.75, 1→weight
            pts = (5 - lvl) / 4.0 * weight
            total += pts

        score = min(100, int(total))
        level = score_to_level(score)
        return score, level


# ── Main Scan ─────────────────────────────────────────────────────────────────

def run_scan() -> dict:
    """Run all domain scanners and return composite result."""
    log.info("=== DEFCON Scan START ===")
    t0 = time.perf_counter()
    state = StateManager()

    scanners = {
        "defcon":      DefconScanner(),
        "weather":     WeatherScanner(),
        "seismic":     SeismicScanner(),
        "biological":  BiologicalScanner(),
        "food":        FoodScanner(),
        "cyber":       CyberScanner(),
    }

    domain_levels = {}
    domain_results = {}

    for name, scanner in scanners.items():
        try:
            r = scanner.scan()
            domain_levels[name] = r.get("level", 5)
            domain_results[name] = r
        except Exception as e:
            log.error("Scanner %s failed: %s", name, e)
            domain_levels[name] = 5
            domain_results[name] = {"level": 5, "error": str(e)}

    engine = CompositeEngine()
    score, level = engine.compute(domain_levels)

    elapsed_ms = (time.perf_counter() - t0) * 1000
    log.info(
        "Composite score=%s/100 → DEFCON %s (%s) in %.0fms",
        score, level.value, level.label, elapsed_ms,
    )
    log.info("Domain levels: %s", domain_levels)

    # Persist state
    scores_struct = {}
    for name, lvl in domain_levels.items():
        res = domain_results[name]
        scores_struct[name] = {
            "level": lvl,
            "value": (5 - lvl) * (engine.weights[name] // 4),
            "raw": lvl,
            "max": engine.weights[name],
            "detail": res.get("detail") or res.get("alerts") or res.get("events") or [],
        }

    prev, new_lvl, total = state.update_scores(scores_struct)

    log.info("=== DEFCON Scan DONE — level %s/%s ===", prev, new_lvl)
    return {
        "previous_level": prev,
        "new_level": new_lvl,
        "threat_score": total,
        "domain_levels": domain_levels,
        "elapsed_ms": elapsed_ms,
    }


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print(textwrap.dedent("""\
            DEFCON Level Monitor v3.0
            Usage: python defcon_monitor.py [options]

            Options:
              --scan       Run full composite scan (default)
              --level N    Set DEFCON level manually (1-5)
              --bio N      Set biological threat level (0-15)
              --food N     Set food security level (0-10)
              --status     Print current status from state file
              --dashboard  Print ASCII dashboard to stdout
              --health     Run system health check
            """))
        return

    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "--status":
            state = StateManager()
            s = state._load()
            print(f"Level: {s.get('current_level', '?')}")
            print(f"Score: {s.get('threat_score', '?')}/100")
            print(f"Last:  {s.get('last_check', 'never')}")
            return
        if cmd == "--level" and len(sys.argv) >= 3:
            lvl = int(sys.argv[2])
            state = StateManager()
            state.set_level(lvl, reason="manual override")
            print(f"DEFCON level set to {lvl}")
            return
        if cmd == "--bio" and len(sys.argv) >= 3:
            val = int(sys.argv[2])
            state = StateManager()
            state.set_biological(val, detail="manual override")
            print(f"Biological score set to {val}")
            return
        if cmd == "--food" and len(sys.argv) >= 3:
            val = int(sys.argv[2])
            state = StateManager()
            state.set_food(val, detail="manual override")
            print(f"Food score set to {val}")
            return

    result = run_scan()
    print(f"\n{'─'*50}")
    print(f"  DEFCON {result['new_level']}  |  Score {result['threat_score']}/100")
    print(f"  {'📈 escalating' if result['threat_score'] > 50 else '📉 de-escalating'}")
    print(f"  Domains: {result['domain_levels']}")
    print(f"  Scan: {result['elapsed_ms']:.0f}ms")
    print(f"{'─'*50}\n")


if __name__ == "__main__":
    main()
