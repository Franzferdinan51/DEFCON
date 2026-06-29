"""Enhanced Economic Scanner v3.2 — BIS, VIX, credit spreads, structured finance, AI debt."""
import logging, time
from src.constants import DomainResult, FINANCIAL_THRESHOLDS, ACTIVE_THREATS, Priority

log = logging.getLogger("defcon.economic")

FRED_SERIES = {
    "vix":        "VIXCLS",
    "yield_10y":  "DGS10",
    "yield_2y":   "DGS2",
    "wti_oil":    "DCOILWTICO",
    "sp500":      "SP500",
    "baa_spread": "BAA",
    "aaa_spread": "AAA",
}

THRESHOLDS = {
    "vix":             {"extreme": 40,  "high": 25,  "medium": 18,  "low": 12},
    "creditspread_ig": {"extreme": 250, "high": 150, "medium": 100, "low": 60},
    "yield_2y10y":    {"extreme": -50, "high": 0,   "medium": 30,  "low": 50},
    "wti_oil":        {"extreme": 140, "high": 110, "medium": 90,  "low": 70},
}


def _fetch_fred(series_id: str) -> float | None:
    """Fetch latest value from FRED CSV — no API key for public series."""
    try:
        from src.fetcher import fetch
        url = f"https://fred.stlouisfed.org/graph/fredgraph.csv?id={series_id}&cosd=2026-06-20&coed=2026-06-28"
        r = fetch(url, timeout=10)
        if r.success:
            for line in reversed(r.content.strip().splitlines()):
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split(",")
                    if len(parts) == 2 and parts[1] and parts[1] != ".":
                        return float(parts[1])
    except Exception as e:
        log.debug(f"FRED {series_id} failed: {e}")
    return None


def _score_indicator(name: str, val: float) -> tuple[int, str]:
    """Return (level 1-5, severity_label) for a financial indicator."""
    t = THRESHOLDS.get(name, {})
    if not t:
        return 5, "info"
    if val >= t.get("extreme", 999): return 1, "extreme"
    if val >= t.get("high",    999): return 2, "high"
    if val >= t.get("medium",  999): return 3, "medium"
    if val >= t.get("low",     999): return 4, "low"
    return 5, "info"


def scan_economic() -> DomainResult:
    """
    Enhanced economic scanner — BIS systemic risk + financial crisis indicators.
    Reads from: CBOE VIX, FRED treasury yields/spreads/oil, and ACTIVE_THREATS.
    Returns DomainResult with financial data, BIS AI-debt alert, and threat list.
    """
    fred, parts, indicators, total, n = {}, [], [], 0.0, 0

    for name, sid in FRED_SERIES.items():
        v = _fetch_fred(sid)
        if v is not None:
            fred[name] = v

    vix = fred.get("vix")
    if vix is not None:
        lvl, sev = _score_indicator("vix", vix)
        total += lvl * 2; n += 1
        indicators.append(f"VIX={vix:.1f} [{sev}]")
        parts.append(f"VIX {vix:.1f}")

    y10 = fred.get("yield_10y"); y2 = fred.get("yield_2y")
    if y10 is not None and y2 is not None:
        try:
            sp = (float(y10) - float(y2)) * 100  # basis points
            lvl, sev = _score_indicator("yield_2y10y", sp)
            total += lvl * 2; n += 1
            indicators.append(f"2y-10y={sp:.0f}bp [{sev}]")
            parts.append(f"YC {sp:.0f}bp")
        except Exception:
            pass

    baa = fred.get("baa_spread"); aaa = fred.get("aaa_spread")
    if baa is not None and aaa is not None:
        try:
            cs = (float(baa) - float(aaa)) * 100  # basis points
            lvl, sev = _score_indicator("creditspread_ig", cs)
            total += lvl * 1.5; n += 1
            indicators.append(f"IG spread={cs:.0f}bp [{sev}]")
            parts.append(f"CS {cs:.0f}bp")
        except Exception:
            pass

    oil = fred.get("wti_oil")
    if oil is not None:
        lvl, sev = _score_indicator("wti_oil", oil)
        total += lvl * 1.0; n += 1
        indicators.append(f"OIL=${oil:.1f} [{sev}]")
        parts.append(f"OIL ${oil:.1f}")

    sp5 = fred.get("sp500")
    if sp5 is not None:
        parts.append(f"SP500={sp5:.0f}")

    avg = total / max(n, 1)
    level = max(1, min(5, int(round(avg))))

    # ── BIS AI-Debt Systemic Alert ─────────────────────────────────────────
    # Check if any economic THREAT is active and elevate the score
    economic_threats = [
        t for t in ACTIVE_THREATS
        if t.get("deficon_domain") == "economic"
        and t.get("severity") in ("CRITICAL", "HIGH", "EXTREME")
    ]
    if economic_threats:
        threat = economic_threats[0]
        level = min(level, 3)
        indicators.insert(0, f"\u26a0 {threat['id']}: {threat['title'][:55]}")
        parts.insert(0, f"\U0001f6a8 BIS ALERT: {threat['title'][:50]}")

    detail = "; ".join(parts[:5]) if parts else "Indicators nominal"
    priority = (
        Priority.CRITICAL if level <= 2
        else Priority.HIGH if level == 3
        else Priority.MEDIUM
    )
    log.info(f"Economic scan: level={level}, fred_keys={list(fred.keys())}")

    return DomainResult(
        domain="economic",
        level=level,
        value=avg,
        weight=5.0,
        detail=detail,
        priority=priority,
        indicators=indicators,
        raw_data={
            "fred": fred,
            "economic_threats": [
                {"id": t["id"], "severity": t["severity"], "title": t["title"]}
                for t in economic_threats
            ],
        },
    )
