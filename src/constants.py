"""Constants and enumerations for DEFCON levels."""
from enum import IntEnum


class DEFCON(IntEnum):
    """U.S. Military DEFCON levels — lower number = more severe."""

    UNKNOWN = 0
    DEFCON_5 = 5  # FADE OUT — Normal peacetime readiness
    DEFCON_4 = 4  # DOUBLE TAKE — Above-normal, increased intel
    DEFCON_3 = 3  # ROUND HOUSE — Forces stage for 15-min mobilization
    DEFCON_2 = 2  # FAST PACE — Armed forces ready within 6 hours
    DEFCON_1 = 1  # COCKED PISTOL — War imminent / ongoing nuclear conflict

    @property
    def label(self) -> str:
        labels = {
            0: "UNKNOWN",
            1: "BLACK / COCKED PISTOL",
            2: "RED / FAST PACE",
            3: "ORANGE / ROUND HOUSE",
            4: "YELLOW / DOUBLE TAKE",
            5: "GREEN / FADE OUT",
        }
        return labels.get(self.value, "?")

    @property
    def civilian(self) -> str:
        guidance = {
            0: "Unable to determine — monitor official channels",
            1: "Immediate shelter / war survival preparations",
            2: "Review evacuation routes; prepare 72-hr kit",
            3: "Review emergency plan; confirm supplies; monitor news",
            4: "Stay informed; review household emergency plan",
            5: "Normal activities; maintain basic preparedness",
        }
        return guidance.get(self.value, "?")

    @property
    def emoji(self) -> str:
        e = {0: "❓", 1: "💀", 2: "🚨", 3: "⚠️", 4: "📢", 5: "✅"}
        return e.get(self.value, "❓")

    @property
    def color(self) -> str:
        """ANSI 256 foreground color."""
        c = {0: "15", 1: "196", 2: "202", 3: "214", 4: "226", 5: "82"}
        return c.get(self.value, "15")

    @property
    def score_weight(self) -> int:
        """Points contributed to composite threat score (0-100)."""
        w = {5: 0, 4: 8, 3: 16, 2: 24, 1: 32, 0: 0}
        return w.get(self.value, 0)


# ── Composite score ──────────────────────────────────────────────────────────
DOMAIN_MAX = {
    "defcon":      32,
    "weather":     20,
    "seismic":     15,
    "biological":  15,
    "food":        10,
    "cyber":        8,
}
DOMAIN_WEIGHT = {
    "defcon":      32,
    "weather":     20,
    "seismic":     15,
    "biological":  15,
    "food":        10,
    "cyber":        8,
}

SCORE_RANGES = {
    5: (0,  20),
    4: (20, 40),
    3: (40, 60),
    2: (60, 80),
    1: (80, 101),
}


def score_to_level(score: int) -> DEFCON:
    """Convert 0-100 composite score to DEFCON level."""
    for level, (lo, hi) in SCORE_RANGES.items():
        if lo <= score < hi:
            return DEFCON(level)
    return DEFCON.DEFCON_1
