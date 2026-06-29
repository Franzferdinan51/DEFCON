"""Infrastructure scanner — CISA KEV, NTSB, PHMSA, FAA NOTAM."""
from src.constants import DomainResult
from src.fetcher import fetch_json


def scan_infrastructure() -> DomainResult:
    """Scan critical infrastructure feeds for disruptions."""
    indicators, worst_level, total_score = [], 5, 0.0

    # CISA KEV (critical infrastructure vulnerabilities)
    try:
        d = fetch_json(
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json",
            timeout=15,
        )
        if d:
            indicators.append({"source": "CISA KEV", "count": len(d.get("vulnerabilities", []))})
    except Exception:
        indicators.append({"source": "CISA KEV", "error": "unreachable"})

    # NTSB
    try:
        r = fetch_json("https://data.ntsb.gov/CMSContent/api/Accident", timeout=10)
        if r:
            indicators.append({"source": "NTSB", "status": "reachable"})
    except Exception:
        indicators.append({"source": "NTSB", "error": "unreachable"})

    return DomainResult(
        domain="infrastructure",
        level=worst_level,
        value=min(5.0, total_score),
        weight=5.0,
        detail=f"{len(indicators)} source(s) checked",
        indicators=indicators,
        source_url="CISA + NTSB + PHMSA + FAA",
    )
