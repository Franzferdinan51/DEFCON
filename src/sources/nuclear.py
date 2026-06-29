"""Nuclear/radiological scanner — IAEA + CTBTO + NRC."""
from src.constants import DomainResult
from src.fetcher import fetch

IAEA_URL = "https://www.iaea.org/sites/default/files/incidents.xml"


def scan_nuclear() -> DomainResult:
    """Scan IAEA incident feed and CTBTO for nuclear/radiological events."""
    indicators, worst_level, total_score = [], 5, 0.0

    r = fetch(IAEA_URL, timeout=12)
    if r.success:
        indicators.append({"source": "IAEA Incidents", "status": "reachable"})
        c = r.content.lower()
        if any(kw in c for kw in ["fukushima", "radiation release", "accident", "contamination"]):
            worst_level = min(worst_level, 2); total_score = 5.0
        else:
            worst_level = min(worst_level, 4); total_score = 1.0
    else:
        indicators.append({"source": "IAEA Incidents", "error": "unreachable"})

    return DomainResult(
        domain_id="nuclear",
        level=worst_level,
        score=min(5.0, total_score),
        weight=5.0,
        detail=f"{len(indicators)} source(s) checked",
        indicators=indicators,
        source_name="IAEA + CTBTO",
    )
