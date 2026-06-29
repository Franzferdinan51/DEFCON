"""DEFCON Rules v3.3 — Complete DEFCON 1–5 framework with threat escalation."""
DEFCON_LEVELS = {
    1: {
        "label": "BLACK / COCKED PISTOL",
        "civilian": "Maximum force ready",
        "color": "#FF0000",
        "description": "Maximum readiness. Immediate threat to nation. War or equivalent.",
        "response_time": "IMMEDIATE",
    },
    2: {
        "label": "RED / FAST PACE",
        "civilian": "Armed forces mobilized",
        "color": "#FF5500",
        "description": "Armed conflict imminent or highly likely. Increased readiness.",
        "response_time": "< 15 minutes",
    },
    3: {
        "label": "ORANGE / ROUND HOUSE",
        "civilian": "Increased readiness",
        "color": "#FF8800",
        "description": "General alertness. Situations developing. Heightened surveillance.",
        "response_time": "< 1 hour",
    },
    4: {
        "label": "YELLOW / DOUBLE TAKE",
        "civilian": "Increased intelligence",
        "color": "#FFCC00",
        "description": "Above-normal readiness. Potential threat situations. Watch carefully.",
        "response_time": "< 4 hours",
    },
    5: {
        "label": "GREEN / FADE OUT",
        "civilian": "Normal peacetime",
        "color": "#00AA00",
        "description": "Normal readiness. No credible threat. Routine operations.",
        "response_time": "Routine",
    },
}

DOMAIN_RULES = {
    "geopolitical": {
        1: ["US or NATO allied forces directly engaged in armed conflict",
            "Imminent invasion of US ally", "Major terrorist attack on US soil"],
        2: ["Active war in Europe, Middle East, or Asia with US involvement",
            "US embassy evacuation ordered", "China/Taiwan kinetic action"],
        3: ["4+ active hot wars or major armed conflicts globally",
            "Diplomatic crisis with near-term conflict potential",
            "New conflict zone emerging"],
        4: ["3 active armed conflicts globally",
            "1-2 active proxy wars", "Military exercises near conflict zones"],
        5: ["< 3 active armed conflicts", "Routine UN/NATO operations only"],
    },
    "cyber": {
        1: ["Major nation-state attack on US critical infrastructure (power, water, comms)",
            "Active cyber war in progress", "Widespread ransomware paralyzing multiple sectors"],
        2: ["Confirmed breach of US federal infrastructure by state actor",
            "Active exploitation of critical zero-day (CISA KEV CVSS 10)",
            "Widespread power grid SCADA intrusion"],
        3: ["FLAME-type export controls on frontier AI models",
            "CISA KEV catalog > 50 active exploited vulns",
            "Active AI-related threat campaign targeting US entities"],
        4: ["Elevated CVE activity (CISA KEV > 20 active)",
            "Unusual scanning patterns from known hostile state actors",
            "New critical infrastructure vulnerability under active exploitation"],
        5: ["CISA KEV < 20 active exploited vulns",
            "Routine patching cadence", "No active state-sponsored campaigns"],
    },
    "economic": {
        1: ["Global financial system collapse or sovereign debt default cascade",
            "VIX > 60 (market panic)", "Credit spreads IG > 500 bps",
            "Systemic bank failure"],
        2: ["Market crash imminent (VIX > 40)",
            "Yield curve inverted > 90 days with recession signal",
            "Credit spreads > 300 bps",
            "BIS/IMF formal systemic risk warning"],
        3: ["BIS Annual Report systemic AI debt alert",
            "VIX > 25", "Yield curve flat or mildly inverted",
            "IG credit spreads > 150 bps",
            "Active THREAT-2026-0628-001 (BIS AI Debt Crisis)"],
        4: ["VIX > 20", "IG credit spreads > 100 bps",
            "Oil shock > $110/bbl", "Major AI company earnings miss > 20%"],
        5: ["VIX < 20", "Credit spreads nominal",
            "No central bank warnings", "AI capex within projections"],
    },
    "weather": {
        1: ["Tornado outbreak > EF4, multiple deaths",
            "Hurricane Cat 4+ landfall within 24h",
            "Catastrophic flooding displacing > 100,000"],
        2: ["Tornado warning for your county",
            "Hurricane Cat 2-3 landfall < 48h",
            "Flash flood emergency",
            "SD-style 130+ mph non-tornadic event"],
        3: ["Tornado watch for your area",
            "Severe thunderstorm warning (destructive, >75 mph)",
            "Flash flood watch/warning",
            "Record-breaking heat/cold for region"],
        4: ["NWS advisory for your area",
            "Heat index in dangerous range",
            "Non-severe but unusual weather for season"],
        5: ["No active watches or warnings",
            "Conditions within normal seasonal range"],
    },
    "seismic": {
        1: ["M7.0+ near population center",
            "Tsunami warning issued",
            "Cascadia Subduction Zone M8+ event"],
        2: ["M6.0+ within 100 miles of your location",
            "M5.5+ within 50 miles",
            "Foreshock sequence detected near major fault"],
        3: ["M5.0+ within 50 miles",
            "Unusual swarm detected on major fault",
            "Volcanic unrest with eruption potential"],
        4: ["M4.0+ within regional radius (>50mi)",
            "Magma movement indicators at volcano",
            "Increased seismic activity on known fault"],
        5: ["No significant seismic events",
            "Background seismicity only"],
    },
    "public_health": {
        1: ["WHO PHEIC declared for novel pathogen",
            "Pandemic with > 1% fatality rate emerging",
            "BSL-4 biosafety accident with release"],
        2: ["Novel pathogen spreading across 3+ countries",
            "Active outbreak with epidemic potential in US",
            "Mass casualty biological/chemical attack"],
        3: ["CDC elevated advisory",
            "Active COVID-level or flu outbreak",
            "Drug contamination affecting multiple states"],
        4: ["CDC monitoring advisory",
            "Seasonal flu above baseline",
            "Localized food/water contamination"],
        5: ["No active PHEICs",
            "Routine seasonal illness levels"],
    },
    "local": {
        1: ["WEA — Presidential alert for your area",
            "Nuclear/radiological release — shelter immediately",
            "Tornado warning for your county",
            "Active shooter — shelter in place"],
        2: ["Civil Emergency Message (CEM) for your county",
            "Flash flood warning for your area",
            "Air Quality Index > 300 (hazardous)",
            "AFB emergency broadcast relevant to your location"],
        3: ["NWS Severe Thunderstorm Warning for your county",
            "Heat advisory / excessive heat warning",
            "Air Quality Index > 150 (unhealthy for sensitive)"],
        4: ["NWS advisory or Special Weather Statement",
            "Air Quality Index > 100",
            "Flood watch for your area"],
        5: ["No active alerts for your location",
            "Conditions within normal range"],
    },
    "disinfo": {
        1: ["Deepfake of President/Governor ordering military action",
            "Coordinated election-manipulation disinfo 72h before election",
            "False WEA/EAS alert causing mass panic"],
        2: ["Coordinated inauthentic behavior from state actor spreading war disinfo",
            "Verified deepfake of major news outlet",
            "AI-generated disinfo campaign targeting US infrastructure"],
        3: ["Elevated GDELT conflict volume with disinfo signature",
            "Multiple unverified viral claims with > 1M engagements",
            "AI-generated political disinfo campaign active"],
        4: ["Moderate disinfo activity detected",
            "Some coordinated narratives forming"],
        5: ["Baseline disinfo levels",
            "No active coordinated campaigns"],
    },
}


def get_defcon_description(domain: str, level: int) -> str:
    rules = DOMAIN_RULES.get(domain, {})
    criteria = rules.get(level, rules.get(5, ["No criteria defined"]))
    return "; ".join(criteria) if criteria else "Nominal"


def get_level_color(level: int) -> str:
    return DEFCON_LEVELS.get(level, DEFCON_LEVELS[5])["color"]


def get_level_label(level: int) -> str:
    return DEFCON_LEVELS.get(level, DEFCON_LEVELS[5])["label"]


ESCALATION_PROTOCOL = [
    (1, "IMMEDIATE — Activate emergency response. All hands. Status every 15 min."),
    (2, "URGENT — Activate incident command. Status every 30 min. Notify leadership."),
    (3, "ELEVATED — Increase watch. Brief leadership. Verify intel. Status every 1h."),
    (4, "GUARDED — Heighten awareness. Monitor feeds. Brief if changed."),
    (5, "NORMAL — Routine monitoring. Daily status report."),
]


if __name__ == "__main__":
    import json, sys
    if "--json" in sys.argv:
        out = {"levels": DEFCON_LEVELS, "domains": DOMAIN_RULES,
               "escalation": ESCALATION_PROTOCOL}
        print(json.dumps(out, indent=2))
    else:
        print("=" * 60)
        print("  DEFCON LEVEL REFERENCE GUIDE v3.3")
        print("=" * 60)
        for lvl, info in DEFCON_LEVELS.items():
            print(f"\nDEFCON {lvl} — {info['label']}")
            print(f"  Civilian:    {info['civilian']}")
            print(f"  Response:    {info['response_time']}")
            print(f"  Description: {info['description']}")
        print("\n" + "=" * 60)
        print("  DOMAIN-SPECIFIC RULES")
        print("=" * 60)
        for domain, rules in DOMAIN_RULES.items():
            print(f"\n[{domain.upper()}]")
            for lvl in range(1, 6):
                criteria = rules.get(lvl, [])
                print(f"  DEFCON {lvl}: {' | '.join(criteria) if criteria else 'Nominal'}")
        print("\n" + "=" * 60)
        print("  ESCALATION PROTOCOL")
        print("=" * 60)
        for lvl, action in ESCALATION_PROTOCOL:
            print(f"  DEFCON {lvl}: {action}")

