"""DEFCON Monitor v3.4 — Enhanced constants."""
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

class Priority(IntEnum):
    CRITICAL = 1; HIGH = 2; MEDIUM = 3; LOW = 4; INFO = 5

class DEFCON(IntEnum):
    _1 = 1; _2 = 2; _3 = 3; _4 = 4; _5 = 5
    @property
    def label(self):
        return {1:"BLACK / COCKED PISTOL",2:"RED / FAST PACE",
                3:"ORANGE / ROUND HOUSE",4:"YELLOW / DOUBLE TAKE",
                5:"GREEN / FADE OUT"}[self._value_]
    @property
    def civilian(self):
        return {1:"Maximum force ready",2:"Armed forces mobilized",
                3:"Increased readiness",4:"Increased intelligence",
                5:"Normal peacetime"}[self._value_]

@dataclass
class DomainResult:
    domain: str; level: int=5; value: float=0.0; weight: float=1.0
    detail: str=""; priority: Priority=Priority.INFO
    source_url: str=""
    indicators: list=field(default_factory=list)
    raw_data: dict=field(default_factory=dict)

@dataclass
class ThreatIndicator:
    name: str; level: int; threshold: float; current: float
    severity: str; source: str

@dataclass
class ScanResult:
    timestamp: str; level: int; threat_score: float; trend: str="stable"
    domains: list=field(default_factory=list); alerts: list=field(default_factory=list)
    anomalies: list=field(default_factory=list)
    indicators: list=field(default_factory=list)
    metadata: dict=field(default_factory=dict)

@dataclass
class AlertEvent:
    priority:    Priority
    domain:      str
    level:       int
    headline:    str
    body:        str
    source_url:  str = ""
    indicators:  list=field(default_factory=list)

def score_to_level(score: float) -> int:
    """Convert numeric threat score (0–100) to DEFCON level (1–5)."""
    if score >= 90: return 1
    if score >= 70: return 2
    if score >= 50: return 3
    if score >= 30: return 4
    return 5

DOMAIN_META = {
    "geopolitical":   {"label":"Geopolitical","emoji":"🌐","weight":5,"color":"#ff4444"},
    "cyber":          {"label":"Cyber","emoji":"💻","weight":4,"color":"#ff8800"},
    "seismic":        {"label":"Seismic","emoji":"🌋","weight":3,"color":"#ffaa00"},
    "weather":        {"label":"Weather","emoji":"⛈️","weight":3,"color":"#ffcc00"},
    "volcano":        {"label":"Volcano","emoji":"🌋","weight":2,"color":"#ffdd44"},
    "wildfire":       {"label":"Wildfire","emoji":"🔥","weight":2,"color":"#ff9900"},
    "public_health":  {"label":"Public Health","emoji":"🦠","weight":4,"color":"#ee4444"},
    "economic":       {"label":"Economic","emoji":"📊","weight":5,"color":"#CCAA00"},
    "space_weather":  {"label":"Space Weather","emoji":"🌌","weight":2,"color":"#aaaaff"},
    "maritime":       {"label":"Maritime","emoji":"🚢","weight":2,"color":"#44aaff"},
    "nuclear":        {"label":"Nuclear","emoji":"☢️","weight":4,"color":"#44ff44"},
    "biological":     {"label":"Biological","emoji":"🧬","weight":4,"color":"#ee4444"},
    "food":           {"label":"Food","emoji":"🌾","weight":3,"color":"#aaff44"},
    "infrastructure": {"label":"Infrastructure","emoji":"🏗️","weight":3,"color":"#888888"},
    "disinfo":        {"label":"Disinformation","emoji":"📰","weight":2,"color":"#ff44aa"},
    "local":          {"label":"Local (Your Area)","emoji":"🏠","weight":3,"color":"#44ffaa"},
}

FINANCIAL_THRESHOLDS = {
    "vix":             {"extreme":40,"high":25,"medium":18,"low":12},
    "creditspread_ig": {"extreme":250,"high":150,"medium":100,"low":60},
    "creditspread_hy": {"extreme":800,"high":500,"medium":350,"low":200},
    "sofr_overnight":  {"extreme":6.0,"high":5.5,"medium":5.3,"low":5.0},
    "yield_2y10y":    {"extreme":-50,"high":0,"medium":30,"low":50},
    "oed_sp500":      {"extreme":25,"high":15,"medium":8,"low":3},
    "dxy":             {"extreme":115,"high":108,"medium":103,"low":98},
    "wti_oil":        {"extreme":140,"high":110,"medium":90,"low":70},
    "td10y":          {"extreme":5.5,"high":5.0,"medium":4.5,"low":3.5},
}

ACTIVE_THREATS = [
    {
        "id": "THREAT-2026-0628-001", "date": "2026-06-28", "severity": "CRITICAL",
        "domain": "economic",
        "title": "BIS Annual Report 2026 — AI Data Center Debt Systemic Risk",
        "actors": ["BIS","Bank of Canada","ECB"],
        "summary": "BIS, BoC, and ECB simultaneously warn US AI data center debt poses global financial stability risk. 75B+ in late-2025 bond/loan issuance. 600B projected private credit to AI. Structured finance (9B+) held by pensions/insurers. Bank of Canada forcing sales of data center securities. Default cascade risk if AI utilization misses projections.",
        "primary_src": "https://www.bis.org/publ/arpdf/ar2026e.htm",
        "tags": ["AI","data-center","BIS","systemic-risk","pensions","insurance"],
        "deficon_domain": "economic", "threat_score_impact": 25,
    },
    {
        "id": "THREAT-2026-0628-002", "date": "2026-06-12", "severity": "HIGH",
        "domain": "cyber",
        "title": "US Commerce Export Controls — Claude Mythos 5 + Fable 5 (FLAME Incident)",
        "actors": ["US Commerce Dept","Howard Lutnick","Anthropic","Amazon","Andy Jassy"],
        "summary": "First-ever US export control on a released AI model. Amazon CEO Andy Jassy reported jailbreak exposing offensive cyber vulnerabilities. Global access suspended June 12-13. Partially restored June 25-28 for ~100 vetted US institutions. Foreign nationals still blocked. Creates precedent: US now treats frontier AI software like controlled munitions.",
        "primary_src": "https://x.com/stretchcloud/status/2070738897429205321",
        "tags": ["Anthropic","Claude","Mythos","Fable","export-control","AI-governance","FLAME"],
        "deficon_domain": "cyber", "threat_score_impact": 15,
    },
    {
        "id": "THREAT-2026-0628-003", "date": "2026-06-28", "severity": "HIGH",
        "domain": "economic",
        "title": "Blackstone $BX Positioning — Ready to Dump Data Centers on Pensions in Default",
        "actors": ["Blackstone","BX","ORCL","SOXX","DRAM"],
        "summary": "Blackstone positioned to offload empty/underutilized data centers back to pension funds in a default scenario. ORCL, SOXX, and DRAM semiconductor stocks flagged as exposed. 30B Meta Louisiana data center financing. Hyperscaler capex spiral with questionable utilization rates. Pension funds are end-buyers of last resort.",
        "primary_src": "https://x.com/rdd147/status/2071339539646533902",
        "tags": ["Blackstone","BX","data-center","pensions","default","AI-debt","systemic"],
        "deficon_domain": "economic", "threat_score_impact": 10,
    },
]

LEVEL_BANDS = [
    (80,1,"EXTREME — CRISIS MODE"),
    (60,2,"HIGH — ACCELERATED READINESS"),
    (40,3,"ELEVATED — INCREASED ALERT"),
    (20,4,"GUARDED — ABOVE NORMAL"),
    ( 0,5,"LOW — NORMAL CONDITIONS"),
]
