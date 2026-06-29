"""Cyber threat scanner v3.2 — CISA KEV + export controls + FLAME/Mythos/Fable tracker."""
from src.constants import DomainResult, ACTIVE_THREATS, Priority

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def scan_cyber() -> DomainResult:
    """
    Enhanced cyber scanner — CISA KEV catalog + AI export control monitoring.
    Tracks: CISA KEV vulnerabilities, FLAME/Mythos/Fable incident, DeepSeek bans,
    US export controls on frontier AI models.
    """
    from src.fetcher import fetch_json
    indicators, total, n = [], 0.0, 0
    worst_level = 5

    # ── CISA KEV Catalog ──────────────────────────────────────────────────
    try:
        d = fetch_json(CISA_KEV_URL, timeout=20)
        if d:
            vulns = d.get("vulnerabilities", [])
            count = len(vulns)
            indicators.append(f"CISA KEV count={count}")
            if count >= 100:   level = 1; total += 4.0
            elif count >= 50:  level = 2; total += 3.0
            elif count >= 20: level = 3; total += 2.0
            elif count >= 5:  level = 4; total += 1.0
            else:             level = 5; total += 0.0
            worst_level = min(worst_level, level); n += 1
    except Exception as e:
        indicators.append(f"CISA KEV error: {e}")

    # ── FLAME/Mythos/Fable Incident ───────────────────────────────────────
    flame_threats = [
        t for t in ACTIVE_THREATS
        if t.get("deficon_domain") == "cyber"
        and t.get("severity") in ("CRITICAL", "HIGH", "EXTREME")
    ]
    if flame_threats:
        threat = flame_threats[0]
        worst_level = min(worst_level, 3)
        total += 3.0; n += 1
        indicators.insert(0, f"\u26a0 {threat['id']}: {threat['title']}")

    # ── DeepSeek / Chinese AI Bans ────────────────────────────────────────
    deepseek_threats = [
        t for t in ACTIVE_THREATS
        if t.get("domain") == "cyber"
        and any(k in t.get("title", "") or k in str(t.get("tags", []))
                for k in ["DeepSeek", "No Adversarial AI Act", "export control"])
    ]
    for t in deepseek_threats:
        worst_level = min(worst_level, 3)
        total += 2.0; n += 1
        indicators.append(f"{t['id']}: {t['title'][:50]}")

    avg = total / max(n, 1)
    level = max(1, min(5, int(round(avg))))

    detail = f"CISA KEV active={len([i for i in indicators if 'CISA' in i])}"
    if flame_threats:
        detail = f"\U0001f525 FLAME ALERT: {flame_threats[0]['title'][:45]} — {detail}"
    if len(indicators) > 1:
        detail += f" (+{len(indicators)-1} more)"

    return DomainResult(
        domain="cyber",
        level=level,
        value=avg,
        weight=4.0,
        detail=detail,
        priority=Priority.CRITICAL if level <= 2 else Priority.HIGH if level == 3 else Priority.MEDIUM,
        indicators=indicators,
        raw_data={
            "cisa_kev_count": len([i for i in indicators if "CISA KEV count=" in str(i)]),
            "flame_threats": [{"id": t["id"], "severity": t["severity"], "title": t["title"]}
                               for t in flame_threats],
            "threats": [
                {"id": t["id"], "severity": t["severity"], "title": t["title"]}
                for t in ACTIVE_THREATS if t.get("deficon_domain") == "cyber"
            ],
        },
    )
