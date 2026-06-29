"""Cyber threat scanner — CISA KEV catalog (free, no API key required)."""
from src.constants import DomainResult
from src.fetcher import fetch_json

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def scan_cyber() -> DomainResult:
    """Scan CISA KEV catalog for known exploited vulnerabilities."""
    indicators, worst_level, total_score = [], 5, 0.0

    try:
        d = fetch_json(CISA_KEV_URL, timeout=20)
        if d:
            vulns = d.get("vulnerabilities", [])
            count = len(vulns)
            indicators.append({"source": "CISA KEV", "count": count})
            if count >= 100:
                worst_level = 1; total_score = 14.0
            elif count >= 50:
                worst_level = 2; total_score = 10.0
            elif count >= 20:
                worst_level = 3; total_score = 7.0
            elif count >= 5:
                worst_level = 4; total_score = 4.0
            else:
                worst_level = 5; total_score = 0.0
        else:
            indicators.append({"source": "CISA KEV", "error": "no data"})
    except Exception as e:
        indicators.append({"source": "CISA KEV", "error": str(e)})

    score = min(14.0, total_score)
    return DomainResult(
        domain_id="cyber",
        level=worst_level,
        score=score,
        weight=14.0,
        detail=f"CISA KEV: {indicators[0].get('count', '?') if indicators else 'unreachable'} known exploited vulns",
        raw={"indicators": indicators},
        indicators=indicators,
        source_name="CISA KEV Catalog",
    )
