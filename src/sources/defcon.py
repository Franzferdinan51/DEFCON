"""Geopolitical scanner — ClawdWatch + defconlevel.com OSINT."""
import re
from src.constants import DomainResult
from src.fetcher import fetch, fetch_json, extract_defcon_from_html, FetchCache

_CACHE = FetchCache(max_age_sec=120)


def scan_geopolitical(clawdwatch_url="http://localhost:3444", zones=None) -> DomainResult:
    """Returns geopolitical DomainResult from ClawdWatch + defconlevel.com."""
    best_level, sources, indicators = 5, {}, []

    # ClawdWatch
    try:
        d = fetch_json(f"{clawdwatch_url}/defcon", timeout=8)
        if d:
            lvl = d.get("level", 5)
            desc = d.get("description", "")[:80]
            sources["clawdwatch"] = {"level": lvl, "desc": desc}
            indicators.append({"source": "ClawdWatch", "level": lvl, "detail": desc})
            best_level = min(best_level, lvl)
    except Exception:
        pass

    # defconlevel.com
    result = fetch("https://www.defconlevel.com/current-level", timeout=12, cache=_CACHE)
    if result.success:
        lvl = extract_defcon_from_html(result.content)
        if lvl:
            sources["defconlevel_com"] = {"level": lvl}
            indicators.append({"source": "defconlevel.com", "level": lvl, "detail": "OSINT estimate"})
            best_level = min(best_level, lvl)

    score = (5 - best_level) * 3.6
    return DomainResult(
        domain_id="geopolitical",
        level=best_level,
        score=score,
        weight=18.0,
        detail=f"DEFCON {best_level} — {len(sources)} source(s)",
        raw={"sources": sources},
        indicators=indicators,
        source_name="ClawdWatch + defconlevel.com",
    )
