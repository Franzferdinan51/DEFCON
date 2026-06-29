"""DEFCON Level Monitor — Constants, Domains, and Enumerations."""
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


# ═══════════════════════════════════════════════════════════════════════════════
# DEFCON Level Enumeration
# ═══════════════════════════════════════════════════════════════════════════════

class DEFCON(IntEnum):
    """U.S. Military DEFCON levels — lower number = more severe."""

    UNKNOWN   = 0
    DEFCON_5 = 5  # FADE OUT    — Normal peacetime readiness
    DEFCON_4 = 4  # DOUBLE TAKE — Above-normal, increased intel
    DEFCON_3 = 3  # ROUND HOUSE — Forces stage for 15-min mobilization
    DEFCON_2 = 2  # FAST PACE   — Armed forces ready within 6 hours
    DEFCON_1 = 1  # COCKED PISTOL — War imminent / ongoing nuclear conflict

    @property
    def label(self) -> str:
        return {
            0: "UNKNOWN", 1: "BLACK / COCKED PISTOL",
            2: "RED / FAST PACE",      3: "ORANGE / ROUND HOUSE",
            4: "YELLOW / DOUBLE TAKE", 5: "GREEN / FADE OUT",
        }.get(self.value, "?")

    @property
    def civilian(self) -> str:
        return {
            0: "Unable to determine — monitor official channels",
            1: "Immediate shelter / war survival preparations",
            2: "Review evacuation routes; prepare 72-hr kit",
            3: "Review emergency plan; confirm supplies; monitor news",
            4: "Stay informed; review household emergency plan",
            5: "Normal activities; maintain basic preparedness",
        }.get(self.value, "?")

    @property
    def emoji(self) -> str:
        return {0: "❓", 1: "💀", 2: "🚨", 3: "⚠️", 4: "📢", 5: "✅"}.get(self.value, "❓")

    @property
    def ansi_color(self) -> str:
        """ANSI 256 foreground color code."""
        return {0: "15", 1: "196", 2: "202", 3: "214", 4: "226", 5: "82"}.get(self.value, "15")

    @property
    def discord_color(self) -> int:
        """Discord embed color (integer)."""
        return {0: 0x888888, 1: 0xEE4444, 2: 0xFF6600, 3: 0xFFAA00, 4: 0xFFCC00, 5: 0x44DD88}.get(self.value, 0)


def score_to_level(score: int) -> DEFCON:
    """Convert 0–100 composite threat score to DEFCON level."""
    if score < 20: return DEFCON.DEFCON_5
    if score < 40: return DEFCON.DEFCON_4
    if score < 60: return DEFCON.DEFCON_3
    if score < 80: return DEFCON.DEFCON_2
    return DEFCON.DEFCON_1


# ═══════════════════════════════════════════════════════════════════════════════
# 15 Threat Domains
# ═══════════════════════════════════════════════════════════════════════════════

DOMAIN_META = {
    # ── id, label, emoji, weight (max pts), color ──────────────────────────
    "geopolitical":  {"label": "Geopolitical",   "emoji": "🌍", "weight": 18, "color": "#FF4444"},
    "cyber":         {"label": "Cyber / CISA",    "emoji": "💻", "weight": 14, "color": "#9966FF"},
    "seismic":       {"label": "Earthquake",      "emoji": "🌋", "weight":  8, "color": "#FF8800"},
    "weather":       {"label": "Severe Weather",  "emoji": "⛈️",  "weight":  8, "color": "#4488FF"},
    "volcano":       {"label": "Volcanic Activity","emoji": "🌋", "weight":  4, "color": "#FF5500"},
    "wildfire":      {"label": "Wildfire",        "emoji": "🔥", "weight":  4, "color": "#FF2200"},
    "public_health": {"label": "Public Health",   "emoji": "🦠", "weight": 10, "color": "#00CC88"},
    "economic":      {"label": "Economic",         "emoji": "📊", "weight":  5, "color": "#CCAA00"},
    "infrastructure":{"label": "Infrastructure",  "emoji": "🏗️", "weight":  5, "color": "#AAAAAA"},
    "space_weather": {"label": "Space Weather",    "emoji": "🌌", "weight":  4, "color": "#AA44FF"},
    "maritime":      {"label": "Maritime/Aviation","emoji": "✈️", "weight":  3, "color": "#00AACC"},
    "nuclear":        {"label": "Nuclear/Rad",     "emoji": "☢️", "weight":  5, "color": "#CCFF00"},
    "biological":     {"label": "Biological",       "emoji": "🧬", "weight":  5, "color": "#00FF88"},
    "food":           {"label": "Food Security",    "emoji": "🌾", "weight":  4, "color": "#DDAA44"},
    "disinfo":        {"label": "Disinformation",   "emoji": "📰", "weight":  3, "color": "#888888"},
}


# ═══════════════════════════════════════════════════════════════════════════════
# Alert Priority
# ═══════════════════════════════════════════════════════════════════════════════

class Priority(IntEnum):
    CRITICAL = 0
    HIGH     = 1
    MEDIUM   = 2
    LOW      = 3
    INFO     = 4

    @property
    def emoji(self) -> str:
        return {0: "🔴", 1: "🚨", 2: "⚠️", 3: "🟡", 4: "ℹ️"}.get(self.value, "ℹ️")


# ═══════════════════════════════════════════════════════════════════════════════
# Domain Result Dataclass
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class DomainResult:
    """Result from a single domain scanner."""
    domain_id:   str
    level:       int          = 5   # 1=critical, 5=clear
    score:       float        = 0.0 # raw domain score (0–weight)
    weight:      float        = 0.0 # max possible for this domain
    detail:      str          = ""
    raw:         object       = None  # source-specific data
    indicators:  list         = field(default_factory=list)  # sub-indicators
    anomaly:     bool          = False  # flagged by trend engine
    z_score:     float         = 0.0
    trend:       str           = "→"   # ↑ ↓ →
    source_name: str           = ""
    source_url:  str           = ""
    fetched_at: str            = ""   # ISO timestamp

    @property
    def score_pct(self) -> float:
        """Score as percentage of max weight."""
        if self.weight <= 0:
            return 0.0
        return min(100.0, (self.score / self.weight) * 100)


@dataclass
class ScanResult:
    """Full composite scan result across all domains."""
    level:         DEFCON
    composite:     float       # 0–100
    domain_results: dict[str, DomainResult]
    trend:         str         # "escalating" | "stable" | "de-escalating"
    anomaly_domains: list[str]
    confidence:    float       = 1.0
    elapsed_ms:    float       = 0.0
    fetched_at:    str         = ""
    history_entries: int       = 0


@dataclass
class AlertEvent:
    """A single alert event to be dispatched."""
    priority:    Priority
    domain:      str
    level:       int
    headline:    str
    body:        str
    source_url:  str = ""
    indicators:  list = field(default_factory=list)
    raw:         object = None
