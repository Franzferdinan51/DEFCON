#!/usr/bin/env python3
"""DEFCON Monitor v3.4 — 16-domain OSINT composite threat assessment."""
import sys, os, json, logging, time, argparse
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

from src.constants import DEFCON, DomainResult, Priority, AlertEvent, score_to_level
from src.state import StateManager
from src.history import TimelineDB, TrendEngine
from src.notifiers import dispatch

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    handlers=[
        logging.FileHandler(BASE_DIR / "logs" / f"defcon-{datetime.now().strftime('%Y%m%d')}.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("defcon.monitor")


# ── Scanner registry ──────────────────────────────────────────────────────────
DOMAIN_SCANNERS = {
    "geopolitical":    ("src.sources.defcon",          "scan_geopolitical"),
    "weather":         ("src.sources.nws",             "scan_weather"),
    "seismic":          ("src.sources.usgs",            "scan_seismic"),
    "cyber":            ("src.sources.cyber",           "scan_cyber"),
    "public_health":   ("src.sources.public_health",   "scan_public_health"),
    "economic":        ("src.sources.economic",         "scan_economic"),
    "space_weather":   ("src.sources.space_weather",    "scan_space_weather"),
    "volcano":          ("src.sources.volcano",          "scan_volcano"),
    "wildfire":        ("src.sources.wildfire",         "scan_wildfire"),
    "nuclear":          ("src.sources.nuclear",          "scan_nuclear"),
    "food":             ("src.sources.food",             "scan_food"),
    "infrastructure":  ("src.sources.infrastructure",  "scan_infrastructure"),
    "maritime":        ("src.sources.maritime",         "scan_maritime"),
    "disinfo":         ("src.sources.disinfo",          "scan_disinfo"),
    "biological":       ("src.sources.biological",       "scan_biological"),
    "local":           ("src.sources.local_alerts",      "domain_result_local"),
}


# ── Run all domain scanners ───────────────────────────────────────────────────

def run_scanners(args):
    state = StateManager()._load()
    manual = state.get("manual_overrides", {})
    results = {}

    domains_to_run = DOMAIN_SCANNERS.keys()
    if args.domain:
        domains_to_run = [args.domain]

    for domain_id in domains_to_run:
        if domain_id in manual:
            lvl = manual[domain_id].get("level", 5)
            score = manual[domain_id].get("score", 0.0)
            detail = manual[domain_id].get("detail", "manual")
            results[domain_id] = DomainResult(
                domain=domain_id, level=lvl, value=score,
                weight=0, detail=detail,
            )
            log.info("  %s → MANUAL Lv%d (%s)", domain_id, lvl, detail)
            continue

        if domain_id not in DOMAIN_SCANNERS:
            log.warning("  Unknown domain: %s", domain_id)
            continue

        mod_name, fn_name = DOMAIN_SCANNERS[domain_id]
        try:
            mod = __import__(mod_name, fromlist=[fn_name])
            fn = getattr(mod, fn_name)
            kw = {}
            if domain_id == "weather":
                kw["zones"] = args.zones
            if domain_id == "geopolitical":
                kw["clawdwatch_url"] = args.clawdwatch_url
            dr = fn(**kw) if kw else fn()
            results[domain_id] = dr
            log.info("  %s → Lv%d (%.0fpts) — %s",
                     domain_id, dr.level, dr.value, dr.detail[:60])
        except Exception as e:
            log.error("  %s → ERROR: %s", domain_id, e)
            results[domain_id] = DomainResult(
                domain=domain_id, level=5, value=0.0,
                weight=0, detail=f"scanner error: {e}",
            )

    return results


# ── Composite scoring ─────────────────────────────────────────────────────────

def compute_composite(domain_results: dict) -> tuple:
    total = sum(dr.value for dr in domain_results.values())
    score = min(100, int(total))
    level = score_to_level(score)
    return score, level


# ── Alert rules ────────────────────────────────────────────────────────────────

ALERT_RULES = [
    ("geopolitical",    lambda r: r.level <= 2,                    Priority.CRITICAL, "Geopolitical DEFCON %d — major conflict"),
    ("geopolitical",    lambda r: r.level == 3,                    Priority.HIGH,     "Geopolitical DEFCON %d — enhanced vigilance"),
    ("weather",          lambda r: "Tornado" in r.detail,           Priority.CRITICAL, "Tornado Warning in effect — take cover now"),
    ("weather",          lambda r: "Heat" in r.detail,              Priority.MEDIUM,   "Heat Advisory in effect"),
    ("weather",          lambda r: "Winter" in r.detail,            Priority.HIGH,     "Winter Storm Warning in effect"),
    ("cyber",            lambda r: r.level <= 2,                    Priority.HIGH,     "Cyber CISA KEV count elevated — patch immediately"),
    ("public_health",   lambda r: r.level <= 2,                    Priority.CRITICAL, "Public Health outbreak keywords detected"),
    ("nuclear",          lambda r: r.level <= 2,                    Priority.CRITICAL, "Nuclear/radiological incident confirmed"),
    ("wildfire",        lambda r: r.level <= 2,                    Priority.HIGH,    "Wildfire activity elevated — check evacuation routes"),
    ("biological",       lambda r: r.level <= 2,                    Priority.CRITICAL, "Biological threat level elevated"),
    ("seismic",          lambda r: r.level <= 2,                    Priority.HIGH,    "M6+ earthquake activity elevated"),
]


def generate_alerts(domain_results: dict) -> list[AlertEvent]:
    alerts = []
    for domain_id, cond_fn, priority, template in ALERT_RULES:
        dr = domain_results.get(domain_id)
        if dr and cond_fn(dr):
            alerts.append(AlertEvent(
                priority=priority,
                domain=domain_id,
                level=dr.level,
                headline=template % dr.level,
                body=dr.detail,
                source_url=getattr(dr, "source_url", "") or "",
                indicators=getattr(dr, "indicators", []) or [],
            ))
    return alerts


# ── Main scan ─────────────────────────────────────────────────────────────────

def run_scan(args):
    t0 = time.perf_counter()
    log.info("=== DEFCON Scan START (v3.1) ===")

    domain_results = run_scanners(args)
    composite, level = compute_composite(domain_results)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    # Trend + anomaly
    db = TimelineDB()
    te = TrendEngine(db)
    trend, anomaly_domains = te.compute_trend()
    db.insert(
        composite=composite, level=level, trend=trend,
        anomaly=bool(anomaly_domains), confidence=1.0,
        elapsed_ms=elapsed_ms, domain_results=domain_results,
    )

    # Update persistent state
    state = StateManager()
    state.update_scores({
        k: {
            "level": v.level, "value": v.value,
            "weight": v.weight, "detail": v.detail,
            "raw": v.raw_data,
        }
        for k, v in domain_results.items()
    })
    state.update({
        "current_level": level.value,
        "threat_score": composite,
        "trend": trend,
        "anomaly_domains": anomaly_domains,
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "last_check": datetime.now(timezone.utc).isoformat(),
        "version": "3.3.0",
    })

    log.info(
        "Composite=%d/100 → DEFCON %s (%s)  trend=%s  anomalies=%s  [%.0fms]",
        composite, level, level, trend, anomaly_domains, elapsed_ms,
    )

    # Dispatch alerts
    if not args.no_alert:
        for alert in generate_alerts(domain_results):
            results_dispatched = dispatch(alert)
            if results_dispatched:
                log.info("Alert dispatched: %s", results_dispatched)

    return {
        "level": level, "composite": composite,
        "trend": trend, "anomaly_domains": anomaly_domains,
        "elapsed_ms": elapsed_ms, "domain_results": domain_results,
    }


# ── Print summary ─────────────────────────────────────────────────────────────

def print_summary(result):
    lvl = result["level"]
    print(f"\n{'═'*56}")
    print(f"  🛡  DEFCON {lvl.value}  |  {lvl.label}")
    print(f"  Score: {result['composite']}/100  |  Trend: {result['trend']}")
    if result["anomaly_domains"]:
        print(f"  ⚠️  Anomalies: {', '.join(result['anomaly_domains'])}")
    print(f"{'═'*56}")
    for did, dr in result["domain_results"].items():
        meta = {
            "geopolitical": "🌍", "cyber": "💻", "seismic": "🌋",
            "weather": "⛈️", "volcano": "🌋", "wildfire": "🔥",
            "public_health": "🦠", "economic": "📊", "space_weather": "🌌",
            "maritime": "✈️", "nuclear": "☢️", "biological": "🧬",
            "food": "🌾", "infrastructure": "🏗️", "disinfo": "📰",
        }.get(did, "•")
        lvl_colors = {1: "\033[38;5;196m", 2: "\033[38;5;202m",
                      3: "\033[38;5;214m", 4: "\033[38;5;226m", 5: "\033[38;5;082m"}
        c = lvl_colors.get(dr.level, "")
        reset = "\033[0m"
        print(f"  {meta}  {did:<18} {c}Lv{dr.level}{reset} ({dr.score:4.0f}pt)  {dr.detail[:46]}")
    print(f"{'═'*56}")
    print(f"  Scan: {result['elapsed_ms']:.0f}ms")


# ── CLI ──────────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(
    description="DEFCON Monitor v3.1 — 15-domain OSINT threat assessment",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="""\
Examples:
  python defcon_monitor.py                     # Full 15-domain scan
  python defcon_monitor.py --quick             # Quick 5-core-domain scan
  python defcon_monitor.py --domain cyber      # Single domain
  python defcon_monitor.py --zones OHZ061,VAZ053   # Multi-zone weather
  python defcon_monitor.py --daemon 1800      # Every 30 min (daemon)
  python defcon_monitor.py --no-alert         # Skip alerts
  python defcon_monitor.py --export json       # Export history
  python defcon_monitor.py --history 30        # 30-day history view
    """,
)
parser.add_argument("--deep",   action="store_true", help="Full 15-domain scan (default)")
parser.add_argument("--quick", action="store_true", help="Quick scan: geopolitical, weather, seismic, cyber, public_health")
parser.add_argument("--domain", metavar="NAME",    help="Scan single domain only")
parser.add_argument("--zones", metavar="ZONES",  default="OHZ061",
                    help="NWS zone(s), comma-separated (default: OHZ061)")
parser.add_argument("--clawdwatch-url", default="http://localhost:3444",
                    help="ClawdWatch agent URL (default: http://localhost:3444)")
parser.add_argument("--no-alert", action="store_true", help="Skip alert dispatch")
parser.add_argument("--daemon", metavar="SECS", type=int,
                    help="Run in daemon loop, sleeping SECS seconds between scans")
parser.add_argument("--export", choices=["json", "csv"],
                    help="Export timeline history to JSON or CSV")
parser.add_argument("--history", metavar="DAYS", type=int, default=7,
                    help="Days of history to show (default: 7)")
parser.add_argument("--level", metavar="N", type=int,
                    help="Set DEFCON level manually (1-5) — for manual override")
parser.add_argument("--bio", metavar="N", type=int,
                    help="Set biological threat level (0-5) — for manual override")
parser.add_argument("--food-level", metavar="N", type=int,
                    help="Set food security level (0-5) — for manual override")
parser.add_argument("--rules", action="store_true",
                    help="Print DEFCON rules and domain escalation criteria, then exit")
parser.add_argument("--hack-check", action="store_true",
                    help="Run local hack-response protocol and print the IR checklist, then exit")

args = parser.parse_args()


if __name__ == "__main__":
    # ── Manual overrides ──────────────────────────────────────────────────
    if args.level:
        StateManager().set_level(args.level, f"manual override via CLI")
        print(f"DEFCON level set to {args.level}")
        sys.exit(0)

    if args.bio is not None:
        StateManager().set_biological(args.bio, "manual override via CLI")
        print(f"Biological level set to {args.bio}")
        sys.exit(0)

    if args.food_level is not None:
        StateManager().set_food(args.food_level, "manual override via CLI")
        print(f"Food level set to {args.food_level}")
        sys.exit(0)

    # ── Rules display ──────────────────────────────────────────────────────
    if args.rules:
        from rules import DEFCON_LEVELS, DOMAIN_RULES, ESCALATION_PROTOCOL
        print("=" * 60)
        print("  DEFCON LEVEL REFERENCE GUIDE v3.3")
        print("=" * 60)
        for lvl, info in DEFCON_LEVELS.items():
            print(f"\nDEFCON {lvl} — {info['label']}")
            print(f"  Civilian:    {info['civilian']}")
            print(f"  Response:    {info['response_time']}")
            print(f"  Description: {info['description']}")
        print("\n" + "=" * 60)
        print("  DOMAIN-SPECIFIC RULES (what triggers each level)")
        print("=" * 60)
        for domain, rules in DOMAIN_RULES.items():
            print(f"\n[{domain.upper()}]")
            for lvl in range(1, 6):
                crit = rules.get(lvl, [])
                print(f"  DEFCON {lvl}: {' | '.join(crit) if crit else 'Nominal'}")
        print("\n" + "=" * 60)
        print("  ESCALATION PROTOCOL")
        print("=" * 60)
        for lvl, action in ESCALATION_PROTOCOL:
            print(f"  DEFCON {lvl}: {action}")
        sys.exit(0)

    # ── Hack response ─────────────────────────────────────────────────────
    if args.hack_check:
        from scripts.hack_response import phase3_rules, phase3_wireshark, phase4_attacker_intel
        print("=== DEFCON HACK RESPONSE PROTOCOL ===\n")
        phase3_rules()
        print()
        phase3_wireshark()
        print()
        phase4_attacker_intel()
        sys.exit(0)

    # ── Export mode ──────────────────────────────────────────────────────
    if args.export:
        db = TimelineDB()
        export_dir = BASE_DIR / "exports"
        export_dir.mkdir(exist_ok=True)
        if args.export == "json":
            path = export_dir / f"defcon-history-{datetime.now().strftime('%Y%m%d')}.json"
            db.export_json(path, days=args.history)
            print(f"JSON export → {path}")
        elif args.export == "csv":
            path = export_dir / f"defcon-history-{datetime.now().strftime('%Y%m%d')}.csv"
            db.export_csv(path, days=args.history)
            print(f"CSV export → {path}")
        sys.exit(0)

    # ── Daemon mode ──────────────────────────────────────────────────────
    if args.daemon:
        interval = args.daemon
        # Quick mode filter
        if args.quick:
            DOMAIN_SCANNERS_QUICK = {k: DOMAIN_SCANNERS[k] for k in
                ["geopolitical", "weather", "seismic", "cyber", "public_health"]}
            import src.constants
            # monkey-patch for quick mode
            import src.defcon_monitor as dm
            dm.DOMAIN_SCANNERS = DOMAIN_SCANNERS_QUICK

        log.info("Daemon mode: scanning every %ds", interval)
        print(f"DEFCON Monitor daemon — interval {interval}s. Ctrl-C to stop.")
        while True:
            result = run_scan(args)
            print_summary(result)
            time.sleep(interval)

    # ── Normal single scan ───────────────────────────────────────────────
    result = run_scan(args)
    print_summary(result)
