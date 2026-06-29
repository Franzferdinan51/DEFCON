"""
Timeline & Trend Engine — SQLite-backed history with anomaly detection.
Tracks every scan, computes Z-scores, flags anomalies, and exports CSV/JSON.
"""
import json, sqlite3, time, os, statistics
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional, Any
from dataclasses import dataclass, field, asdict
from src.constants import DEFCON, DomainResult

DB_PATH = Path(os.environ.get(
    "DEFCON_DB_DIR",
    str(Path.home() / ".openclaw" / "memory")
)) / "defcon_timeline.db"


@dataclass
class TimelineEntry:
    """A single scan event stored in the timeline."""
    id:            int = 0
    ts:            str = ""       # ISO 8601
    level:         int = 5
    composite:     float = 0.0
    trend:         str  = "stable"
    anomaly:       bool = False
    confidence:    float = 1.0
    elapsed_ms:    float = 0.0
    domains_json:  str  = "{}"   # JSON-encoded domain results


def _dict_factory(cursor, row):
    return dict(zip([d[0] for d in cursor.description], row))


class TimelineDB:
    """SQLite timeline — stores every scan for trend + anomaly analysis."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS timeline (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts           TEXT NOT NULL,
                    level        INTEGER NOT NULL,
                    composite    REAL NOT NULL,
                    trend        TEXT NOT NULL DEFAULT 'stable',
                    anomaly      INTEGER NOT NULL DEFAULT 0,
                    confidence   REAL NOT NULL DEFAULT 1.0,
                    elapsed_ms   REAL NOT NULL DEFAULT 0.0,
                    domains_json TEXT NOT NULL DEFAULT '{}'
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timeline_ts ON timeline(ts DESC)")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS domain_scores (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    timeline_id  INTEGER NOT NULL,
                    domain       TEXT NOT NULL,
                    level        INTEGER NOT NULL,
                    score        REAL NOT NULL,
                    weight       REAL NOT NULL,
                    z_score      REAL NOT NULL DEFAULT 0.0,
                    anomaly      INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY(timeline_id) REFERENCES timeline(id) ON DELETE CASCADE
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domain_ts ON domain_scores(domain, timeline_id)")

    def insert(self, composite: float, level: int, trend: str,
               anomaly: bool, confidence: float, elapsed_ms: float,
               domain_results: dict[str, DomainResult]) -> int:
        """Insert a scan result and return its row ID."""
        domains_json = json.dumps({
            k: {"level": v.level, "score": v.score,
                "weight": v.weight, "z_score": v.z_score,
                "anomaly": v.anomaly, "detail": v.detail}
            for k, v in domain_results.items()
        })
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("""
                INSERT INTO timeline (ts, level, composite, trend, anomaly, confidence, elapsed_ms, domains_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (datetime.now(timezone.utc).isoformat(), level, composite,
                  trend, int(anomaly), confidence, elapsed_ms, domains_json))
            timeline_id = cur.lastrowid
            for domain, dr in domain_results.items():
                conn.execute("""
                    INSERT INTO domain_scores (timeline_id, domain, level, score, weight, z_score, anomaly)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (timeline_id, domain, dr.level, dr.score, dr.weight, dr.z_score, int(dr.anomaly)))
        return timeline_id

    def get_history(self, days: int = 30, limit: int = 500) -> list[dict]:
        """Return scan history for the last N days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = _dict_factory
            rows = conn.execute("""
                SELECT id, ts, level, composite, trend, anomaly, confidence, elapsed_ms
                FROM timeline
                WHERE ts >= ?
                ORDER BY ts DESC
                LIMIT ?
            """, (cutoff, limit)).fetchall()
        return rows

    def get_domain_series(self, domain: str, days: int = 30) -> list[dict]:
        """Return score time-series for one domain."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = _dict_factory
            rows = conn.execute("""
                SELECT t.ts, d.score, d.z_score, d.anomaly, d.level
                FROM domain_scores d
                JOIN timeline t ON d.timeline_id = t.id
                WHERE d.domain = ? AND t.ts >= ?
                ORDER BY t.ts ASC
            """, (domain, cutoff)).fetchall()
        return rows

    def get_trend(self, domain: str, days: int = 7) -> dict:
        """Compute 7-day rolling statistics for a domain."""
        series = self.get_domain_series(domain, days=days)
        if len(series) < 3:
            return {"trend": "insufficient_data", "count": len(series)}
        scores = [r["score"] for r in series]
        mean = statistics.mean(scores)
        stdev = statistics.stdev(scores) if len(scores) > 1 else 0.0
        recent = scores[-3:]
        older = scores[:-3] if len(scores) > 3 else []
        direction = ""
        if len(older) >= 2:
            recent_avg = statistics.mean(recent)
            older_avg = statistics.mean(older)
            direction = "↑" if recent_avg > older_avg + stdev else ("↓" if recent_avg < older_avg - stdev else "→")
        return {
            "trend": direction or "→",
            "mean": round(mean, 3),
            "stdev": round(stdev, 3),
            "min": min(scores),
            "max": max(scores),
            "count": len(scores),
            "recent_avg": round(statistics.mean(recent), 3) if recent else 0,
        }

    def detect_anomalies(self, domain: str, window: int = 30, z_thresh: float = 2.0) -> list[dict]:
        """
        Detect anomalies using Z-score.
        Flags entries where the score is >z_thresh standard deviations from the rolling mean.
        """
        series = self.get_domain_series(domain, days=window)
        if len(series) < 6:
            return []
        scores = [r["score"] for r in series]
        mean = statistics.mean(scores)
        stdev = statistics.stdev(scores) if len(scores) > 1 else 0.0
        if stdev == 0:
            return []
        anomalies = []
        for r in series:
            z = (r["score"] - mean) / stdev
            if abs(z) >= z_thresh:
                anomalies.append({**r, "z_score": round(z, 3), "mean": round(mean, 3)})
        return anomalies

    def export_csv(self, path: Path, days: int = 30):
        """Export full history as CSV."""
        rows = self.get_history(days=days, limit=5000)
        if not rows:
            return
        import csv
        keys = ["id", "ts", "level", "composite", "trend", "anomaly", "confidence", "elapsed_ms"]
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            w.writerows(rows)

    def export_json(self, path: Path, days: int = 30):
        """Export full history + domain details as JSON."""
        rows = self.get_history(days=days, limit=5000)
        for row in rows:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = _dict_factory
                domains = conn.execute("""
                    SELECT domain, level, score, weight, z_score, anomaly
                    FROM domain_scores WHERE timeline_id = ?
                """, (row["id"],)).fetchall()
                row["domains"] = {d["domain"]: d for d in domains}
        path.write_text(json.dumps(rows, indent=2, default=str))


class TrendEngine:
    """
    Analyzes history to determine composite trend direction.
    Uses rate-of-change across all domains + Z-score spike detection.
    """

    def __init__(self, db: TimelineDB):
        self.db = db

    def compute_trend(self) -> tuple[str, list[str]]:
        """
        Returns ('escalating' | 'de-escalating' | 'stable', list of anomalous domain IDs).
        """
        recent = self.db.get_history(days=7)
        if len(recent) < 2:
            return "stable", []

        # Look at last N entries vs prior N
        mid = min(3, len(recent) // 2)
        recent_scores = [r["composite"] for r in recent[:mid]]
        older_scores  = [r["composite"] for r in recent[mid:mid*2]] if len(recent) > mid*2 else [r["composite"] for r in recent[mid:]]

        recent_avg = statistics.mean(recent_scores)
        older_avg  = statistics.mean(older_scores) if older_scores else recent_avg
        diff = recent_avg - older_avg

        # Anomaly domains
        anomalous = []
        for domain in [
            "geopolitical", "cyber", "public_health", "weather",
            "seismic", "economic", "nuclear", "biological"
        ]:
            anomalies = self.db.detect_anomalies(domain, window=14)
            if anomalies:
                anomalous.append(domain)

        if diff >= 5:
            return "escalating", anomalous
        elif diff <= -5:
            return "de-escalating", anomalous
        return "stable", anomalous

    def weekly_summary(self) -> dict:
        """Return a 7-day aggregate summary."""
        rows = self.db.get_history(days=7)
        if not rows:
            return {}
        scores = [r["composite"] for r in rows]
        return {
            "scans": len(rows),
            "avg_score": round(statistics.mean(scores), 1),
            "max_score": max(scores),
            "min_score": min(scores),
            "trend": self.compute_trend()[0],
            "anomaly_domains": self.compute_trend()[1],
            "start_ts": rows[-1]["ts"],
            "end_ts": rows[0]["ts"],
        }
