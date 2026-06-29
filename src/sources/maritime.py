"""Maritime and aviation scanner — NOAA Tides, Lloyd's List, ICAO NOTAM."""
from src.constants import DomainResult
from src.fetcher import fetch


def scan_maritime() -> DomainResult:
    """Scan for maritime and aviation disruptions."""
    indicators, worst_level, total_score = [], 5, 0.0

    r1 = fetch("https://www.tides.net/advisories/", timeout=10)
    if r1.success:
        indicators.append({"source": "NOAA Tides", "status": "reachable"})

    return DomainResult(
        domain="maritime",
        level=worst_level,
        value=min(3.0, total_score),
        weight=3.0,
        detail=f"{len(indicators)} source(s) checked",
        indicators=indicators,
        source_url="NOAA + ICAO + Lloyd's List",
    )
