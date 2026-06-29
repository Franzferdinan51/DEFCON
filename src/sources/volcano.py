"""Volcanic activity scanner — USGS Volcano Hazards Program."""
from src.constants import DomainResult
from src.fetcher import fetch

USGS_VOLC_URL = "https://www.usgs.gov/programs/VHP"


def scan_volcano() -> DomainResult:
    """Scan USGS for volcanic activity alerts."""
    indicators, worst_level, total_score = [], 5, 0.0

    r = fetch(USGS_VOLC_URL, timeout=12)
    if r.success:
        indicators.append({"source": "USGS Volcano", "status": "reachable"})
        c = r.content.lower()
        if any(kw in c for kw in ["eruption", "red alert", "warning", "activity alert"]):
            worst_level = min(worst_level, 1); total_score = 4.0
        elif any(kw in c for kw in ["advisory", "watch", "notice"]):
            worst_level = min(worst_level, 3); total_score = 2.0
    else:
        indicators.append({"source": "USGS Volcano", "error": "unreachable"})

    return DomainResult(
        domain_id="volcano",
        level=worst_level,
        score=min(4.0, total_score),
        weight=4.0,
        detail=f"{len(indicators)} source(s) checked",
        indicators=indicators,
        source_name="USGS Volcano Hazards Program",
    )
