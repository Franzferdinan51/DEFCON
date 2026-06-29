"""Space weather scanner — NOAA SWPC solar/geomagnetic alerts."""
from src.constants import DomainResult
from src.fetcher import fetch

SWPC_URL = "https://www.swpc.noaa.gov/products/solar-geophysical-activity-summary"


def scan_space_weather() -> DomainResult:
    """Scan NOAA SWPC for solar proton events and geomagnetic storms."""
    indicators, worst_level, total_score = [], 5, 0.0

    r = fetch(SWPC_URL, timeout=12)
    if r.success:
        indicators.append({"source": "NOAA SWPC", "status": "reachable"})
        c = r.content.lower()
        if any(kw in c for kw in ["severe geomagnetic", "s3 solar radiation", "radio blackout"]):
            worst_level = min(worst_level, 2); total_score = 4.0
        elif any(kw in c for kw in ["moderate geomagnetic", "minor storm", "watch"]):
            worst_level = min(worst_level, 3); total_score = 2.5
    else:
        indicators.append({"source": "NOAA SWPC", "error": "unreachable"})

    return DomainResult(
        domain_id="space_weather",
        level=worst_level,
        score=min(4.0, total_score),
        weight=4.0,
        detail=f"{len(indicators)} source(s) checked",
        indicators=indicators,
        source_name="NOAA SWPC",
    )
