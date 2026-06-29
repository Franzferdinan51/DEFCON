"""Local Alerts Scanner v3.3 — NWS API + SPC outlook + USGS local for configured location."""
import json, logging, ssl, urllib.request, time, re
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.parent
CONFIG_FILE = BASE_DIR / "config" / "locations.yaml"
CACHE_FILE  = BASE_DIR / "logs" / "local_cache.json"
CACHE_TTL   = 300

log = logging.getLogger("defcon.local")

# ── Minimal YAML loader (no PyYAML dependency) ────────────────────────────────
def _yaml_load(path: Path) -> dict:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    data, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"^(\S[^:]*):\s*(.*)", line.rstrip())
        if not m:
            if cur and line.startswith(" ") and isinstance(data.get(cur), str):
                data[cur] += " " + line.strip()
            continue
        key, val = m.group(1), m.group(2).strip()
        if val in ("{", "["):
            data[key] = []; cur = key
        elif key in data and isinstance(data[key], list):
            data[key].append(val); cur = key
        else:
            data[key] = val; cur = None
    return data

def _load_config() -> dict:
    """Load personal location from config/locations.yaml — falls back to Huber Heights OH."""
    try:
        cfg = _yaml_load(CONFIG_FILE)
        p = cfg.get("personal", {})
        return {
            "name":        p.get("name",        "Huber Heights, OH"),
            "lat":         float(p.get("lat",    39.8423)),
            "lon":         float(p.get("lon",   -84.0088)),
            "nws_zone":    p.get("nws_zone",  "OHZ005"),
            "nws_office":  p.get("nws_office","ILN"),
            "county":      p.get("county",      "Miami"),
            "county_fips": p.get("county_fips","39109"),
        }
    except Exception as e:
        log.warning(f"Location config error: {e}")
        return {
            "name": "Huber Heights, OH", "lat": 39.8423, "lon": -84.0088,
            "nws_zone": "OHZ005", "nws_office": "ILN",
            "county": "Miami", "county_fips": "39109",
        }

def _fetch_json(url: str, timeout: int = 10) -> dict | None:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "DEFCON-Monitor/3.3"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return json.loads(r.read())
    except Exception as e:
        log.debug(f"Fetch error {url}: {e}")
        return None

def _nws_alerts(lat: float, lon: float) -> list[dict]:
    """Active NWS alerts via Weather.gov API v3 for lat/lon."""
    data = _fetch_json(
        f"https://api.weather.gov/points/{lat:.4f},{lon:.4f}/alerts", timeout=8)
    if not data:
        return []
    return [
        {
            "event":    p.get("event", ""),
            "severity": p.get("severity", ""),
            "onset":    p.get("onset", ""),
            "expires":  p.get("expires", ""),
            "headline": p.get("headline", ""),
            "area":     p.get("areaDesc", ""),
            "desc":     (p.get("description") or "")[:200],
        }
        for p in (f.get("properties", {}) for f in data.get("features", []))
        if p.get("status") != "Exercise"
    ]

def _nws_current_obs(lat: float, lon: float) -> dict:
    """Current conditions from NWS API."""
    pt = _fetch_json(
        f"https://api.weather.gov/points/{lat:.4f},{lon:.4f}", timeout=8)
    if not pt:
        return {}
    props = pt.get("properties", {})
    obs   = props.get("currentObservation", {})
    return {
        "temp":    obs.get("temperature"),
        "wind":    obs.get("windString"),
        "rh":      obs.get("relativeHumidity"),
        "station":  props.get("stationIdentifier"),
    }

def _spc_day1() -> list[dict]:
    """SPC Day-1 convective outlook as GeoJSON."""
    data = _fetch_json(
        "https://www.spc.noaa.gov/products/outlook/day1otlk_cat.lyr.geojson",
        timeout=8)
    if not data:
        return []
    results = []
    for f in data.get("features", []):
        p = f.get("properties", {})
        if p.get("dtp") == "1":
            results.append({
                "risk":  p.get("type", "Unknown"),
                "label": p.get("name", ""),
                "geo":   str(f.get("geometry", ""))[:80],
            })
    return results

def _usgs_local(lat: float, lon: float,
                min_mag: float = 1.5, radius_km: float = 250) -> list[dict]:
    """USGS M1.5+ within 250 km via FDSN API."""
    data = _fetch_json(
        f"https://earthquake.usgs.gov/fdsnws/event/1/query"
        f"?latitude={lat}&longitude={lon}&maxradiuskm={radius_km}"
        f"&minmagnitude={min_mag}&format=geojson&orderby=magnitude&limit=10",
        timeout=12,
    )
    if not data:
        return []
    out = []
    for q in data.get("features", []):
        props = q.get("properties", {})
        c     = q.get("geometry", {}).get("coordinates", [])
        out.append({
            "mag":   props.get("mag"),
            "place": props.get("place"),
            "time":  props.get("time"),
            "url":   props.get("url"),
            "lon":   c[0] if c else None,
            "lat":   c[1] if c and len(c) > 1 else None,
            "depth": c[2] if c and len(c) > 2 else None,
        })
    return out

# ── Scoring ─────────────────────────────────────────────────────────────────
_EVENT = {
    "Tornado Warning":              (1, 15),
    "Tornado Watch":               (3,  7),
    "Flash Flood Warning":          (2, 10),
    "Flood Warning":               (3,  6),
    "Severe Thunderstorm Warning":  (2,  8),
    "Severe Thunderstorm Watch":    (4,  4),
    "Heat Advisory":               (3,  4),
    "Excessive Heat Warning":      (2,  8),
    "Winter Storm Warning":         (2,  8),
    "Blizzard Warning":            (1, 15),
    "Special Weather Statement":    (4,  2),
    "Air Quality Alert":           (3,  5),
    "Civil Emergency Message":     (1, 18),
    "Tsunami Warning":            (1, 25),
    "Shelter in Place":          (1, 20),
}

def _score_alerts(alerts: list) -> tuple:
    if not alerts:
        return 5, 0.0, []
    worst, total, descs = 5, 0.0, []
    for a in alerts:
        e   = a.get("event", "")
        sev = a.get("severity", "").upper()
        lvl, pts = 5, 1.0
        for k, (lv, sc) in _EVENT.items():
            if k.lower() in e.lower():
                lvl, pts = lv, sc; break
        if sev == "EXTREME":
            lvl = max(1, lvl-1); pts *= 1.5
        elif sev == "SEVERE":
            lvl = max(1, lvl-1); pts *= 1.2
        worst = min(worst, lvl); total = min(20.0, total + pts)
        descs.append(f"{e} [{sev}]")
    return worst, total, descs

def _score_quakes(quakes: list) -> tuple:
    if not quakes:
        return 5, 0.0, []
    worst, total, descs = 5, 0.0, []
    for q in quakes:
        m = q.get("mag") or 0
        if   m >= 6.0: lvl, sc = 1, 20
        elif m >= 5.0: lvl, sc = 2, 12
        elif m >= 4.0: lvl, sc = 3,  8
        elif m >= 2.5: lvl, sc = 4,  4
        else:             lvl, sc = 5,  1
        worst = min(worst, lvl); total = min(20.0, total + sc)
        descs.append(f"M{m:.1f} — {q.get('place','')}")
    return worst, total, descs

# ── Main scan ────────────────────────────────────────────────────────────────
def scan_local() -> dict:
    """
    Full local alert scan for the configured location.
    Returns raw data dict (no DomainResult — caller builds that).
    """
    from src.constants import Priority
    loc = _load_config()
    lat, lon = loc["lat"], loc["lon"]

    alerts  = _nws_alerts(lat, lon)
    current = _nws_current_obs(lat, lon)
    spc     = _spc_day1()
    quakes  = _usgs_local(lat, lon)

    alvl, asc, adesc = _score_alerts(alerts)
    slvl, ssc, sdesc = _score_quakes(quakes)

    local_level = min(alvl, slvl)
    local_score = min(20.0, asc + ssc * 0.5)

    priority = (
        Priority.CRITICAL if local_level <= 1
        else Priority.HIGH   if local_level == 2
        else Priority.MEDIUM if local_level == 3
        else Priority.LOW
    )

    indicators = []
    if alerts:  indicators.append(f"{len(alerts)} NWS alert(s)")
    if quakes: indicators.append(f"{len(quakes)} USGS event(s) within 250km")
    if spc:    indicators.append(f"SPC Day1: {len(spc)} risk area(s)")
    if not indicators:
        indicators.append("No active local alerts")

    parts = []
    if alerts:
        for a in alerts[:2]:
            parts.append(f"{a['event']} [{a['severity']}]")
    else:
        parts.append("No active NWS alerts")
    if quakes:
        parts.append(f"{len(quakes)} quake(s)")
    if current.get("temp"):
        parts.append(f"{current['temp']}F")

    return {
        "location":    loc,
        "alerts":      alerts,
        "alert_level": alvl,
        "alert_score": asc,
        "alert_descs": adesc,
        "seismic":     quakes,
        "seis_level":  slvl,
        "seis_score":  ssc,
        "seis_descs":  sdesc,
        "local_level": local_level,
        "local_score": local_score,
        "priority":    priority,
        "indicators":  indicators,
        "detail":      " | ".join(parts),
        "spc_outlook": spc,
        "current":     current,
    }

def domain_result_local():
    """Build DomainResult for the local domain."""
    from src.constants import DomainResult
    d = scan_local()
    return DomainResult(
        domain    = "local",
        level     = d["local_level"],
        value     = d["local_score"],
        weight    = 3.0,
        detail    = d["detail"],
        priority  = d["priority"],
        indicators = d["indicators"],
        raw_data  = {
            "location": d["location"]["name"],
            "alerts":  d["alerts"],
            "seismic": d["seismic"],
            "spc":     d["spc_outlook"],
            "current": d["current"],
        },
    )
