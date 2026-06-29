#!/usr/bin/env python3
"""
DEFCON Web Dashboard — Flask-based real-time monitoring UI.
Run:  python defcon_web.py [--host 0.0.0.0] [--port 5000]
"""
import sys, os, json
from pathlib import Path
BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

from src.state import StateManager
from src.constants import DEFCON, DOMAIN_WEIGHT

try:
    from flask import Flask, render_template_string, jsonify, redirect
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

app = Flask(__name__)
app.template_folder = str(BASE_DIR / "templates")


# ── HTML Template (inline — no separate files needed) ────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DEFCON Monitor</title>
  <style>
    :root {
      --bg: #080810;
      --card: #10101c;
      --border: #1e1e30;
      --text: #d0d0e0;
      --muted: #666680;
      --green: #44dd88;
      --yellow: #f0cc44;
      --orange: #f08030;
      --red: #ee4444;
      --dim-red: #aa2222;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Segoe UI', 'SF Pro', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
    }
    .hero {
      padding: 32px 24px 24px;
      border-bottom: 2px solid var(--border);
      background: linear-gradient(180deg, #0d0d1a 0%, var(--bg) 100%);
      text-align: center;
    }
    .level-display {
      font-size: 5em;
      font-weight: 900;
      line-height: 1;
      letter-spacing: -4px;
      text-shadow: 0 0 60px currentColor;
    }
    .level-1 { color: var(--red); }
    .level-2 { color: #f06030; }
    .level-3 { color: var(--orange); }
    .level-4 { color: var(--yellow); }
    .level-5 { color: var(--green); }
    .label { font-size: 1.4em; font-weight: 600; margin-top: 8px; opacity: 0.8; }
    .score-bar {
      width: 100%;
      max-width: 500px;
      height: 12px;
      background: var(--border);
      border-radius: 6px;
      margin: 20px auto 0;
      overflow: hidden;
    }
    .score-fill {
      height: 100%;
      border-radius: 6px;
      transition: width 0.6s ease;
    }
    .container { max-width: 900px; margin: 0 auto; padding: 20px; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
      gap: 14px;
      margin-top: 20px;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px 18px;
    }
    .card-title {
      font-size: 0.75em;
      text-transform: uppercase;
      letter-spacing: 1.5px;
      color: var(--muted);
      margin-bottom: 8px;
    }
    .card-value { font-size: 1.5em; font-weight: 700; }
    .card-detail { font-size: 0.8em; color: var(--muted); margin-top: 4px; }
    .trend { font-size: 1em; margin-top: 12px; }
    .trend.up { color: var(--red); }
    .trend.down { color: var(--green); }
    .trend.flat { color: var(--muted); }
    .footer {
      text-align: center;
      padding: 24px;
      font-size: 0.75em;
      color: var(--muted);
      border-top: 1px solid var(--border);
    }
    .refresh {
      display: inline-block;
      padding: 6px 16px;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      cursor: pointer;
      font-size: 0.85em;
      text-decoration: none;
    }
    .refresh:hover { background: var(--border); }
    .updated { font-size: 0.8em; color: var(--muted); margin-top: 10px; }
    .nav { margin-top: 10px; font-size: 0.85em; }
    .nav a { color: var(--muted); text-decoration: none; margin: 0 8px; }
    .nav a:hover { color: var(--text); }
    .defcon-levels {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      margin-top: 12px;
    }
    .defcon-pill {
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 0.75em;
      font-weight: 700;
    }
    .pill-1 { background: #2a0a0a; color: #ff6060; border: 1px solid #440000; }
    .pill-2 { background: #2a1400; color: #f08030; border: 1px solid #442200; }
    .pill-3 { background: #2a1800; color: #f0a030; border: 1px solid #443300; }
    .pill-4 { background: #242000; color: #c0b020; border: 1px solid #333300; }
    .pill-5 { background: #0a2010; color: #40cc70; border: 1px solid #113322; }
    .active-pill { box-shadow: 0 0 8px currentColor; transform: scale(1.1); }
  </style>
</head>
<body>
  <div class="hero">
    <div class="level-display level-{{ level }}">DEFCON {{ level }}</div>
    <div class="label">{{ label }}</div>
    <div style="margin-top:8px;font-size:0.9em;color:var(--muted);">{{ description }}</div>
    <div class="score-bar">
      <div class="score-fill level-{{ level }}" style="width:{{ score_pct }}%; background: currentColor;"></div>
    </div>
    <div style="margin-top:6px;font-size:0.85em;color:var(--muted);">
      Threat Score: {{ score }}/100
    </div>
    <div class="trend {{ trend_class }}">{{ trend }}</div>
    <div class="updated">Last scan: {{ last_check }}</div>
    <div class="nav">
      <a href="/">Dashboard</a>
      <a href="/api/state">API / JSON</a>
      <a href="/history">History</a>
    </div>
  </div>

  <div class="container">
    <h3 style="margin-bottom:6px;">Domain Status</h3>
    <div class="grid">
      {% for domain, info in domains.items() %}
      <div class="card">
        <div class="card-title">{{ domain }}</div>
        <div class="card-value level-{{ info.level }}">Lv {{ info.level }}</div>
        <div class="card-detail">{{ info.detail }}</div>
      </div>
      {% endfor %}
    </div>

    {% if active_threats %}
    <h3 style="margin:24px 0 8px;">Active Threats</h3>
    {% for t in active_threats %}
    <div class="card" style="border-left:3px solid var(--red);">
      <div class="card-title">{{ t.category }}</div>
      <div>{{ t.description }}</div>
    </div>
    {% endfor %}
    {% endif %}

    <h3 style="margin:24px 0 8px;">DEFCON Level Guide</h3>
    <div class="defcon-levels">
      <span class="defcon-pill pill-1 {% if level == 1 %}active-pill{% endif %}">1 — WAR</span>
      <span class="defcon-pill pill-2 {% if level == 2 %}active-pill{% endif %}">2 — RED</span>
      <span class="defcon-pill pill-3 {% if level == 3 %}active-pill{% endif %}">3 — ORANGE</span>
      <span class="defcon-pill pill-4 {% if level == 4 %}active-pill{% endif %}">4 — YELLOW</span>
      <span class="defcon-pill pill-5 {% if level == 5 %}active-pill{% endif %}">5 — GREEN</span>
    </div>
    <p style="font-size:0.8em;color:var(--muted);margin-top:10px;">
      OSINT estimate only — not an official government signal.
    </p>
  </div>

  <div class="footer">
    DEFCON Monitor v3.0 &nbsp;|&nbsp; Data sources: defconlevel.com, api.weather.gov, USGS
    <br>
    <a href="/" class="refresh" style="margin-top:8px;">Refresh</a>
  </div>
</body>
</html>"""


@app.route("/")
def dashboard():
    if not HAS_FLASK:
        return "Flask is required. Install: pip install flask", 500

    state = StateManager()._load()
    level = state.get("current_level", 5)
    score = state.get("threat_score", 0)
    scores = state.get("scores", {})
    history = state.get("history", [])
    threats = state.get("active_threats", [])

    lvl_enum = DEFCON(level)

    # Trend
    delta = 0
    if len(history) >= 2:
        delta = history[0].get("score", 0) - history[1].get("score", 0)
    trend_label = "📈 Escalating" if delta > 0 else "📉 De-escalating" if delta < 0 else "➡️ Stable"
    trend_class = "up" if delta > 0 else "down" if delta < 0 else "flat"

    # Domain details
    domain_map = {
        "defcon": ("DEFCON Level", "clawdwatch / defconlevel.com"),
        "weather": ("Weather", "NWS api.weather.gov"),
        "seismic": ("Seismic", "USGS Earthquake API"),
        "biological": ("Biological", "manual"),
        "food": ("Food Security", "manual"),
        "cyber": ("Cyber", "npm audit"),
    }

    domains = {}
    for name, (label, src) in domain_map.items():
        info = scores.get(name, {})
        lvl_int = info.get("level", 5)
        detail = info.get("detail", src)
        if isinstance(detail, list):
            detail = json.dumps(detail)[:60]
        domains[name] = {"level": lvl_int, "detail": detail or src}

    last_check = state.get("last_check", "never")
    if "T" in str(last_check):
        last_check = str(last_check).replace("T", " ")[:19]

    return render_template_string(
        DASHBOARD_HTML,
        level=level,
        label=lvl_enum.label,
        description=lvl_enum.civilian,
        value=score,
        score_pct=min(100, score),
        trend=trend_label,
        trend_class=trend_class,
        last_check=last_check,
        domains=domains,
        active_threats=threats[:5],
    )


@app.route("/api/state")
def api_state():
    """Return full state as JSON."""
    state = StateManager()._load()
    return jsonify({
        "level": state.get("current_level"),
        "score": state.get("threat_score"),
        "scores": state.get("scores"),
        "last_check": state.get("last_check"),
        "history": state.get("history", [])[:20],
        "threats": state.get("active_threats", []),
    })


@app.route("/history")
def history_page():
    if not HAS_FLASK:
        return "Flask required.", 500
    state = StateManager()._load()
    history = state.get("history", [])[:50]
    rows = []
    for h in history:
        ts = h.get("ts", "")
        if "T" in str(ts):
            ts = str(ts).replace("T", " ")[:19]
        rows.append(f"<tr><td>{ts}</td><td>DEFCON {h.get('level','?')}</td>"
                    f"<td>{h.get('score','?')}</td><td>{h.get('delta','?')}</td></tr>")
    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>DEFCON History</title>
<style>
  body{{font-family:system-ui;background:#080810;color:#d0d0e0;padding:24px;}}
  table{{width:100%;border-collapse:collapse;}}
  th,td{{padding:8px 12px;border-bottom:1px solid #1e1e30;text-align:left;}}
  th{{color:#666680;text-transform:uppercase;font-size:0.75em;letter-spacing:1px;}}
</style></head>
<body>
<h2>DEFCON History</h2>
<table><thead><tr><th>Timestamp</th><th>Level</th><th>Score</th><th>Delta</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table>
<p><a href="/" style="color:#666680;">← Dashboard</a></p>
</body></html>"""
    return html


def main():
    if not HAS_FLASK:
        print("ERROR: Flask is required.")
        print("  pip install flask")
        print("  python defcon_web.py")
        return

    host = "0.0.0.0"
    port = 5000
    for arg in sys.argv[1:]:
        if arg.startswith("--host="):
            host = arg.split("=", 1)[1]
        elif arg.startswith("--port="):
            port = int(arg.split("=", 1)[1])

    print(f"DEFCON Dashboard → http://{host}:{port}/")
    print(f"  API endpoint: http://{host}:{port}/api/state")
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
