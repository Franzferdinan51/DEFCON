"""Disinformation scanner — GDELT Project, NewsAPI."""
from src.constants import DomainResult
from src.fetcher import fetch

GDELT_URL = (
    "https://api.gdeltproject.org/api/v2/doc/doc"
    "?format=json&mode=artlist"
    "&query=conflict+war+military+crisis&maxrecords=10&sort=DateDesc"
)


def scan_disinfo() -> DomainResult:
    """Scan GDELT for conflict/war/disinformation signal."""
    indicators, worst_level, total_score = [], 5, 0.0

    r = fetch(GDELT_URL, timeout=12)
    if r.success:
        indicators.append({"source": "GDELT", "status": "reachable"})
        try:
            import json
            d = json.loads(r.content)
            articles = d.get("articles", [])
            count = len(articles)
            indicators.append({"source": "GDELT", "articles": count})
            if count >= 8:
                worst_level = min(worst_level, 2); total_score = 3.0
            elif count >= 4:
                worst_level = min(worst_level, 3); total_score = 2.0
        except Exception:
            indicators.append({"source": "GDELT", "error": "parse failed"})
    else:
        indicators.append({"source": "GDELT", "error": "unreachable"})

    return DomainResult(
        domain_id="disinfo",
        level=worst_level,
        score=min(3.0, total_score),
        weight=3.0,
        detail=f"{len(indicators)} source(s) checked",
        indicators=indicators,
        source_name="GDELT + NewsAPI",
    )
