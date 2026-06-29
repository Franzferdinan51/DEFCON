"""Economic scanner — CBOE VIX, WTI crude oil, FRED treasury spreads."""
from src.constants import DomainResult
from src.fetcher import fetch, fetch_json

VIX_URL = "https://cdn.cboe.com/api/global/quotes/VMV.json"


def _fred_series(series_id: str) -> float | None:
    """Fetch latest value from FRED CSV (no API key needed for public series)."""
    url = f"https://fred.stlouisfed.org/graph/fredgraph.csv?id={series_id}"
    try:
        r = fetch(url, timeout=10)
        if r.success:
            lines = [l.strip() for l in r.content.strip().splitlines()
                     if l.strip() and not l.startswith("#")]
            if len(lines) >= 2:
                return float(lines[-1].split(",")[1])
    except Exception:
        pass
    return None


def scan_economic() -> DomainResult:
    """Scan VIX, oil prices, and yield curve for economic stress signals."""
    indicators, worst_level, total_score = [], 5, 0.0

    # VIX
    try:
        d = fetch_json(VIX_URL, timeout=8)
        if d and d.get("data"):
            vix = d["data"][0].get("value", 0)
            indicators.append({"source": "CBOE VIX", "value": round(vix, 2)})
            if vix >= 35:
                worst_level = min(worst_level, 2); total_score += 3.0
            elif vix >= 25:
                worst_level = min(worst_level, 3); total_score += 2.0
            elif vix >= 20:
                worst_level = min(worst_level, 4); total_score += 1.0
    except Exception:
        indicators.append({"source": "CBOE VIX", "error": "unreachable"})

    # WTI Crude
    oil = _fred_series("DCOILWTICO")
    if oil:
        indicators.append({"source": "WTI Oil $/bbl", "value": round(oil, 2)})
        if oil >= 120:
            worst_level = min(worst_level, 2); total_score += 1.5
        elif oil >= 100:
            worst_level = min(worst_level, 3); total_score += 1.0

    # Yield curve (10Y-2Y)
    try:
        s10 = _fred_series("DGS10")
        s2  = _fred_series("DGS2")
        if s10 is not None and s2 is not None:
            spread = round(s10 - s2, 3)
            indicators.append({"source": "10Y-2Y Spread", "value": spread})
            if spread <= -0.5:
                worst_level = min(worst_level, 2); total_score += 2.0
            elif spread <= 0:
                worst_level = min(worst_level, 3); total_score += 1.0
    except Exception:
        pass

    score = min(5.0, total_score)
    return DomainResult(
        domain_id="economic",
        level=worst_level,
        score=score,
        weight=5.0,
        detail=f"VIX={'%.1f' % (vix if 'vix' in dir() else 0)}, oil=${oil if 'oil' in dir() else '?'}/bbl",
        indicators=indicators,
        source_name="CBOE VIX + FRED + WTI",
    )
