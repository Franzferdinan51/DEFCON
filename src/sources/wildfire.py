"""Wildfire scanner — InciWeb + NASA FIRMS MODIS/VIIRS active fire."""
from src.constants import DomainResult
from src.fetcher import fetch

INCIWEB_URL = "https://inciweb.nwcg.gov/feeds/metadata/incidents.xml"


def scan_wildfire() -> DomainResult:
    """Scan InciWeb and NASA FIRMS for active large wildfires."""
    indicators, worst_level, total_score = [], 5, 0.0

    # InciWeb RSS
    r1 = fetch(INCIWEB_URL, timeout=12)
    if r1.success:
        indicators.append({"source": "InciWeb", "status": "reachable"})

    # NASA FIRMS MODIS — US only (public CSV)
    r2 = fetch(
        "https://firms.modaps.eosdis.nasa.gov/data/active_fire/"
        "modis-c6.1/csv/MODIS_C6_1_USA_7d.csv",
        timeout=15,
    )
    if r2.success:
        lines = [l for l in r2.content.splitlines() if l.strip()]
        fire_count = max(0, len(lines) - 1)
        indicators.append({"source": "NASA FIRMS MODIS", "fire_count_7d": fire_count})
        if fire_count >= 50:
            worst_level = min(worst_level, 2); total_score = 4.0
        elif fire_count >= 20:
            worst_level = min(worst_level, 3); total_score = 2.5

    return DomainResult(
        domain_id="wildfire",
        level=worst_level,
        score=min(4.0, total_score),
        weight=4.0,
        detail=f"{len(indicators)} source(s) checked",
        indicators=indicators,
        source_name="InciWeb + NASA FIRMS",
    )
