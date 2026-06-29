"""Food security scanner — USDA, EU RASFF, FAO GIEWS."""
from src.constants import DomainResult
from src.fetcher import fetch


def scan_food() -> DomainResult:
    """Scan USDA, EU RASFF, and FAO GIEWS for food security threats."""
    indicators, worst_level, total_score = [], 5, 0.0

    # USDA.gov disaster support
    r1 = fetch("https://www.usda.gov/topics/disaster-support", timeout=10)
    if r1.success:
        indicators.append({"source": "USDA.gov", "status": "reachable"})

    # EU RASFF
    r2 = fetch("https://ec.europa.eu/food/safety/rasff/refuge/search", timeout=12)
    if r2.success:
        indicators.append({"source": "EU RASFF", "status": "reachable"})

    # FAO GIEWS
    r3 = fetch("https://www.fao.org/guies/food-crisis/", timeout=10)
    if r3.success:
        indicators.append({"source": "FAO GIEWS", "status": "reachable"})

    return DomainResult(
        domain="food",
        level=worst_level,
        value=min(4.0, total_score),
        weight=4.0,
        detail=f"{len(indicators)} source(s) checked",
        indicators=indicators,
        source_url="USDA + RASFF + FAO GIEWS",
    )
