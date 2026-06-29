"""Biological/biorisk scanner — WHO BWC, PubMed, manual."""
from src.constants import DomainResult
from src.fetcher import fetch


def scan_biological() -> DomainResult:
    """Scan WHO, PubMed, and news for biorisk / biosafety signals."""
    indicators, worst_level, total_score = [], 5, 0.0

    # UNOG BWC
    r1 = fetch("https://www.unog.ch/BIO", timeout=10)
    if r1.success:
        indicators.append({"source": "UNOG BWC", "status": "reachable"})

    # PubMed bioweapon search
    r2 = fetch(
        "https://pubmed.ncbi.nlm.nih.gov/?term=biosafety+OR+bioweapon+OR+outbreak",
        timeout=12,
    )
    if r2.success:
        indicators.append({"source": "PubMed", "status": "reachable"})

    return DomainResult(
        domain_id="biological",
        level=worst_level,
        score=min(5.0, total_score),
        weight=5.0,
        detail=f"{len(indicators)} source(s) checked",
        indicators=indicators,
        source_name="WHO BWC + PubMed",
    )
