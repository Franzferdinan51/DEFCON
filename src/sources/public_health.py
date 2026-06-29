"""Public health scanner — WHO DON, ProMED-mail."""
import re
from src.constants import DomainResult
from src.fetcher import fetch

HIGH_KW = ["influenza", "h5n1", "h7n9", "mpox", "covid", "ebola",
           "marburg", "lassa", "crimean-congo", "nipah", "salmonella", "anthrax"]


def _level_from_text(text: str) -> tuple:
    """Parse disease keywords from raw text → (level, score)."""
    t = text.lower()
    hits = sum(1 for kw in HIGH_KW if kw in t)
    if hits >= 4: return (1, 10.0)
    if hits >= 2: return (2, 7.0)
    if hits >= 1: return (3, 4.0)
    return (5, 0.0)


def scan_public_health() -> DomainResult:
    """Scan WHO Disease Outbreak News and ProMED-mail for disease outbreak signals."""
    all_text, indicators = "", []

    # WHO DON
    r1 = fetch("https://www.who.int/emergencies/disease-outbreak-news", timeout=12)
    if r1.success:
        indicators.append({"source": "WHO DON", "status": "reachable"})
        text1 = re.sub(r"<[^>]+>", " ", r1.content)
        all_text += text1

    # ProMED
    r2 = fetch("https://promedmail.org/feed/post", timeout=12)
    if r2.success:
        indicators.append({"source": "ProMED-mail", "status": "reachable"})
        text2 = re.sub(r"<[^>]+>", " ", r2.content)
        all_text += text2

    if not indicators:
        return DomainResult(
            domain_id="public_health", level=5, score=0.0, weight=10.0,
            detail="All feeds unreachable", source_name="WHO + ProMED",
        )

    lvl, score = _level_from_text(all_text)
    return DomainResult(
        domain_id="public_health",
        level=lvl,
        score=score,
        weight=10.0,
        detail=f"{len(indicators)} source(s) checked",
        indicators=indicators,
        source_name="WHO DON + ProMED-mail",
    )
