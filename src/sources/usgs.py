"""Seismic scanner — USGS M4+ earthquakes, last 30 days."""
from src.constants import DomainResult
from src.fetcher import fetch_json

USGS_URL = (
    "https://earthquake.usgs.gov/fdsnws/event/1/query"
    "?format=geojson&minmagnitude=4&orderby=magnitude"
)


def scan_seismic() -> DomainResult:
    """Scan USGS for M4+ earthquakes in last 30 days."""
    d = fetch_json(USGS_URL, timeout=15)
    if d is None:
        return DomainResult(
            domain_id="seismic", level=5, score=0.0, weight=8.0,
            detail="USGS feed unavailable", source_name="USGS",
        )

    features = d.get("features", [])
    m6_plus = [f for f in features if f.get("properties", {}).get("mag", 0) >= 6.0]
    m5_plus = [f for f in features if f.get("properties", {}).get("mag", 0) >= 5.0]

    if m6_plus:
        level, score = 1, 8.0
    elif len(m5_plus) >= 3:
        level, score = 2, 6.0
    elif features:
        level, score = 3, 4.0
    else:
        level, score = 5, 0.0

    indicators = [
        {"mag": f.get("properties", {}).get("mag"),
         "place": f.get("properties", {}).get("place", ""),
         "url": f.get("properties", {}).get("url", "")}
        for f in features[:8]
    ]
    return DomainResult(
        domain_id="seismic",
        level=level,
        score=score,
        weight=8.0,
        detail=f"{len(m6_plus)} M6+, {len(m5_plus)} M5+, {len(features)} total M4+",
        raw={"m6_plus": len(m6_plus), "total": len(features)},
        indicators=indicators,
        source_name="USGS Earthquake API",
    )
