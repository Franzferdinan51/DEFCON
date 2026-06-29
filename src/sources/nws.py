"""Severe weather scanner — NWS alerts across configurable zones."""
from src.constants import DomainResult
from src.fetcher import fetch_json

SEVERITY_MAP = {
    "Extreme": (1, 4.0),
    "Severe":  (2, 3.0),
    "Moderate":(3, 2.0),
    "Minor":   (4, 1.0),
    "Unknown": (5, 0.0),
}

EVENT_WEIGHTS = {
    "Tornado Warning":      (1, 5.0),
    "Flash Flood Warning": (1, 4.0),
    "Hurricane Warning":   (1, 5.0),
    "Typhoon Warning":     (1, 5.0),
    "Extreme Heat Warning":(2, 3.0),
    "Heat Advisory":       (3, 2.0),
    "Winter Storm Warning":(2, 3.0),
    "Blizzard Warning":    (1, 4.0),
    "Severe Thunderstorm": (2, 3.0),
    "Flood Warning":       (2, 2.5),
    "Fire Weather Watch":  (4, 2.0),
    "Volcanic Ash":        (1, 4.0),
}


def scan_weather(zones=None) -> DomainResult:
    """Scan NWS for active alerts. zones: comma-separated NWS zone codes."""
    if zones is None:
        zones = ["OHZ061"]
    elif isinstance(zones, str):
        zones = [z.strip() for z in zones.split(",")]

    all_alerts = []
    for zone in zones:
        d = fetch_json(f"https://api.weather.gov/alerts/active?zone={zone}", timeout=10)
        if d:
            all_alerts.extend(d.get("features", []))

    if not all_alerts:
        return DomainResult(
            domain="weather", level=5, value=0.0, weight=8.0,
            detail="No active alerts",
            source_url="NWS api.weather.gov",
        )

    worst_level, total_score, indicators = 5, 0.0, []
    for alert in all_alerts:
        props = alert.get("properties", {})
        event = props.get("event", "Unknown")
        severity = props.get("severity", "Unknown")
        headline = props.get("headline", "")[:100]

        lvl_ov, weight = SEVERITY_MAP.get(severity, (5, 0.0))
        for key, (evo, ew) in EVENT_WEIGHTS.items():
            if key.lower() in event.lower():
                lvl_ov, weight = evo, ew
                break

        worst_level = min(worst_level, lvl_ov)
        total_score += weight
        indicators.append({"event": event, "severity": severity, "zone": zone, "headline": headline})

    score = min(8.0, total_score)
    return DomainResult(
        domain="weather",
        level=worst_level,
        value=score,
        weight=8.0,
        detail=f"{len(all_alerts)} alert(s) across {len(zones)} zone(s)",
        raw_data={"alerts": all_alerts[:10]},
        indicators=indicators,
        source_url="NWS api.weather.gov",
    )
