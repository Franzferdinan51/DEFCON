"""State manager — load/save defcon-state.json with schema validation."""
import json, os, copy
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DEFAULT_STATE = {
    "schema_version": "3.3",
    "version": "3.4.0",
    "current_level": 5,
    "threat_score": 0,
    "trend": "stable",
    "anomaly_domains": [],
    "last_updated": None,
    "last_check": None,
    "scores": {},
    "manual_overrides": {},
    "active_threats": [],
    "history": [],
    "confidence": 0.0,
    "sources_missed": [],
    "last_alert_sent": None,
    "monitoring": {
        "defcon": True, "weather": True, "seismic": True,
        "biological": True, "food": True, "cyber": True,
    },
    "contacts": {
        "telegram": {
            "bot_token": "YOUR_BOT_TOKEN",
            "chat_id": "YOUR_CHAT_ID",
            "topic_id": None,
        }
    },
    "locations": {
        "weather_zone": "OHZ061",
        "city": "YOUR_CITY",
        "state": "YOUR_STATE",
    },
    "alerts": {
        "cooldown_hours": 2,
        "rules": {
            "defcon_2":  {"level_lte": 2,  "priority": "critical"},
            "defcon_3":  {"level_lte": 3,  "priority": "high"},
            "tornado":   {"event_contains": "Tornado", "priority": "critical"},
            "heat":      {"event_contains": "Heat", "priority": "medium"},
            "h5n1":      {"event_contains": "H5N1", "priority": "critical"},
            "npm_vulns": {"vulns_gt": 5, "priority": "high"},
        },
    },
}


class StateManager:
    """Thread-safe read/write access to defcon-state.json."""

    def __init__(self, path: Optional[Path] = None):
        if path is None:
            base = os.environ.get(
                "DEFCON_STATE_DIR",
                str(Path.home() / ".openclaw" / "memory")
            )
            path = Path(base) / "defcon-state.json"
        self.path = Path(path)
        self._ensure_dir()
        self._ensure_exists()

    def _ensure_dir(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _ensure_exists(self):
        if not self.path.exists():
            self._save(copy.deepcopy(DEFAULT_STATE))

    def _load(self) -> dict:
        try:
            with open(self.path) as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return copy.deepcopy(DEFAULT_STATE)

    def _save(self, state: dict) -> None:
        with open(self.path, "w") as f:
            json.dump(state, f, indent=2)

    # ── Read operations ───────────────────────────────────────────────────────

    def get(self, key: str, default=None):
        return self._load().get(key, default)

    def get_level(self) -> int:
        return self._load().get("current_level", 5)

    def get_score(self) -> int:
        return self._load().get("threat_score", 0)

    def get_history(self, limit: int = 30) -> list:
        return self._load().get("history", [])[:limit]

    # ── Write operations ──────────────────────────────────────────────────────

    def update(self, updates: dict) -> None:
        state = self._load()
        state.update(updates)
        self._save(state)

    def update_scores(self, scores: dict) -> None:
        state = self._load()
        prev = state.get("current_level", 5)
        prev_score = state.get("threat_score", 0)
        total = sum(s.get("value", 0) for s in scores.values())
        level = self._calc_level(total)

        state["scores"] = scores
        state["threat_score"] = total
        state["current_level"] = level
        state["last_updated"] = datetime.now(timezone.utc).isoformat()
        state["last_check"] = datetime.now(timezone.utc).isoformat()
        state["confidence"] = 1.0 - (len(state.get("sources_missed", [])) / 6.0)

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "score": total,
            "delta": total - prev_score,
        }
        state.setdefault("history", []).insert(0, entry)
        state["history"] = state["history"][:100]

        self._save(state)
        return prev, level, total

    def set_level(self, level: int, reason: str = "") -> None:
        state = self._load()
        state["current_level"] = level
        state["last_updated"] = datetime.now(timezone.utc).isoformat()
        state["last_reason"] = reason
        self._save(state)

    def add_threat(self, threat: dict) -> None:
        state = self._load()
        state.setdefault("active_threats", []).insert(0, threat)
        state["active_threats"] = state["active_threats"][:20]
        self._save(state)

    def clear_threat(self, threat_id: str) -> None:
        state = self._load()
        state["active_threats"] = [
            t for t in state.get("active_threats", []) if t.get("id") != threat_id
        ]
        self._save(state)

    def set_biological(self, value: int, detail: str = "") -> None:
        state = self._load()
        state["scores"]["biological"] = {
            "value": value, "raw": value, "max": 15, "detail": detail
        }
        self._save(state)

    def set_food(self, value: int, detail: str = "") -> None:
        state = self._load()
        state["scores"]["food"] = {
            "value": value, "raw": value, "max": 10, "detail": detail
        }
        self._save(state)

    @staticmethod
    def _calc_level(score: int) -> int:
        if score < 20: return 5
        if score < 40: return 4
        if score < 60: return 3
        if score < 80: return 2
        return 1
