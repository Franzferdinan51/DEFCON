#!/usr/bin/env python3
"""DEFCON Monitor v4.0 — Enhanced Web Dashboard with async scanning."""
import os, sys, time, threading, json, signal, argparse
from datetime import datetime, timezone
from flask import Flask, render_template_string, jsonify

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

try:
    from defcon_monitor import run_scan
except ImportError as e:
    print(f"[ERROR] Import failed: {e}")
    sys.exit(1)

# ─── Configuration ──────────────────────────────
PORT = int(os.environ.get("DEFCON_WEB_PORT", 5051))
REFRESH_INTERVAL = int(os.environ.get("DEFCON_REFRESH_SEC", 60))
MAX_HISTORY = 60

# ─── Flask App ──────────────────────────────────
app = Flask(__name__, static_folder="static")

# ─── State ──────────────────────────────────────
class AppState:
    def __init__(self):
        self.data = {}
        self.history = []
        self.scanning = False
        self.last_scan_time = None
        self.scan_duration = 0
        self.lock = threading.Lock()
        self._scan_thread = None
        self._running = False
    
    def start_background_scan(self):
        """Start periodic background scanning."""
        if self._running:
            return
        self._running = True
        def scan_loop():
            while self._running:
                try:
                    data, duration = run_scan()
                    with self.lock:
                        self.data = data
                        self.last_scan_time = datetime.now(timezone.utc)
                        self.scan_duration = duration
                        entry = {
                            "time": self.last_scan_time.isoformat(),
                            "overall_score": round(sum(d["score"] for d in data.values()) / len(data), 1) if data else 0,
                            "domains_scanned": len(data),
                            "duration_s": round(duration, 1)
                        }
                        self.history.append(entry)
                        if len(self.history) > MAX_HISTORY:
                            self.history = self.history[-MAX_HISTORY:]
                except Exception as e:
                    print(f"[SCAN ERROR] {e}")
                time.sleep(REFRESH_INTERVAL)
        t = threading.Thread(target=scan_loop, daemon=True)
        t.start()
        self._scan_thread = t
    
    def stop(self):
        """Stop background scanning."""
        self._running = False
    
    def force_scan(self):
        """Run a scan immediately (blocking)."""
        with self.lock:
            self.scanning = True
        try:
            data, duration = run_scan()
            with self.lock:
                self.data = data
                self.last_scan_time = datetime.now(timezone.utc)
                self.scan_duration = duration
                entry = {
                    "time": self.last_scan_time.isoformat(),
                    "overall_score": round(sum(d["score"] for d in data.values()) / len(data), 1) if data else 0,
                    "domains_scanned": len(data),
                    "duration_s": round(duration, 1)
                }
                self.history.append(entry)
        finally:
            with self.lock:
                self.scanning = False

state = AppState()

# ─── HTML Template ──────────────────────────────
DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DEFCON Monitor — Threat Dashboard</title>
<link rel="stylesheet" href="/static/style.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
</head>
<body>
<div id="app">
    <!-- Header -->
    <header class="header">
        <div class="header-left">
            <h1>🛡️ DEFCON MONITOR</h1>
            <span class="subtitle">Multi-Domain Threat Assessment System</span>
        </div>
        <div class="header-right">
            <span id="status-badge" class="badge badge-scanning">⏳ Scanning...</span>
            <button class="btn btn-sm" onclick="forceRefresh()">⟳ Refresh Now</button>
        </div>
    </header>

    <!-- Overall Level -->
    <section class="overall-section">
        <div class="overall-card">
            <div class="level-display" id="overall-level"></div>
            <div class="score-display" id="overall-score"></div>
            <div class="threat-name" id="threat-name"></div>
        </div>
    </section>

    <!-- Distribution Bar -->
    <section class="distribution-section">
        <h3>Threat Level Distribution</h3>
        <div class="dist-bar-container">
            <div class="dist-bar" id="dist-bar"></div>
        </div>
        <div class="dist-legend" id="dist-legend"></div>
    </section>

    <!-- Charts Row -->
    <section class="charts-row">
        <div class="chart-card">
            <h3>📊 Domain Score Radar</h3>
            <canvas id="radarChart"></canvas>
        </div>
        <div class="chart-card">
            <h3>📈 Trend (Last 20 Scans)</h3>
            <canvas id="trendChart"></canvas>
        </div>
    </section>

    <!-- Domain Cards -->
    <section class="domains-section">
        <h3>Domain Results</h3>
        <div class="domains-grid" id="domains-grid"></div>
    </section>

    <!-- Alerts & History -->
    <section class="bottom-row">
        <div class="alerts-panel">
            <h3>🔔 Recent Alerts</h3>
            <div id="alerts-feed" class="alerts-list"></div>
        </div>
        <div class="history-panel">
            <h3>📋 Scan History (Last 10)</h3>
            <table id="history-table">
                <thead><tr><th>Time</th><th>Avg Score</th><th>Domains</th><th>Duration</th></tr></thead>
                <tbody id="history-body"></tbody>
            </table>
        </div>
    </section>

    <!-- Footer -->
    <footer class="footer">
        <span id="last-updated">Last updated: Never</span>
        <span id="scan-info"></span>
        <button class="btn btn-xs" onclick="exportJSON()">📥 Export JSON</button>
    </footer>
</div>

<script>
const LEVELS = {1:{color:'#ff0000',name:'DEFCON 1'},2:{color:'#ff6600',name:'DEFCON 2'},3:{color:'#ffcc00',name:'DEFCON 3'},4:{color:'#ffff00',name:'DEFCON 4'},5:{color:'#00ff00',name:'DEFCON 5'}};
const THREAT_NAMES = {1:'NUCLEAR WARFARE',2:'NEAR IMPENDING NUCLEAR WARFARE',3:'GLOBAL THREAT',4:'INCREASED INTELLIGENCE',5:'NORMAL CYCLE'};

let radarChart, trendChart;

function initCharts(){
    const radarCtx = document.getElementById('radarChart');
    if(radarCtx) {
        radarChart = new Chart(radarCtx.getContext('2d'), {
            type: 'radar',
            data: { labels: [], datasets: [{label:'Score (0-100)',data:[],backgroundColor:'rgba(255,204,0,0.2)',borderColor:'#ffcc00',pointBackgroundColor:'#ffcc00'}]},
            options: {
                responsive:true, maintainAspectRatio:false,
                scales:{ r:{min:0,max:100,ticks:{stepSize:20},grid:{color:'rgba(255,255,255,0.1)'},angleLines:{color:'rgba(255,255,255,0.1)'}},},
                plugins:{legend:{display:false}}
            }
        });
    }
    const trendCtx = document.getElementById('trendChart');
    if(trendCtx) {
        trendChart = new Chart(trendCtx.getContext('2d'), {
            type: 'line',
            data: { labels:[], datasets:[{label:'Avg Score',data:[],borderColor:'#ffcc00',backgroundColor:'rgba(255,204,0,0.1)',fill:true,tension:0.3,pointRadius:3}]},
            options: {
                responsive:true, maintainAspectRatio:false,
                scales:{ y:{min:0,max:100,ticks:{color:'#888'},grid:{color:'rgba(255,255,255,0.05)'}}, x:{ticks:{display:false},grid:{display:false}}},
                plugins:{legend:{display:false}}
            }
        });
    }
}

function getLevel(score){
    if(score>=80)return 1; if(score>=60)return 2; if(score>=40)return 3; if(score>=20)return 4; return 5;
}
function getLevelColor(score){
    const l=getLevel(score);
    return LEVELS[l]?LEVELS[l].color:'#888';
}

async function fetchData(){
    try{
        const resp=await fetch('/api/data');
        if(!resp.ok)throw new Error('API error');
        return await resp.json();
    }catch(e){console.error('Fetch failed:',e);return null;}
}

function renderDashboard(data){
    if(!data)return;
    const domains=data.domains||{};
    const history=data.history||[];
    
    // Overall level
    const scores=Object.values(domains).map(d=>d.score);
    const avgScore=scores.length?Math.round(scores.reduce((a,b)=>a+b,0)/scores.length*10)/10:0;
    const overallLevel=getLevel(avgScore);
    const lvlInfo=LEVELS[overallLevel];
    
    document.getElementById('overall-level').innerHTML=`<span style="color:${lvlInfo.color}">${lvlInfo.name}</span>`;
    document.getElementById('overall-score').textContent=`Score: ${avgScore}/100`;
    document.getElementById('threat-name').textContent=THREAT_NAMES[overallLevel]||'';
    
    // Status badge
    const isScanning=data.scanning;
    const badge=document.getElementById('status-badge');
    if(isScanning){badge.className='badge badge-scanning';badge.textContent='⏳ Scanning...';}
    else{badge.className='badge badge-ready';badge.textContent=`✅ Updated ${data.last_scan_time?'just now':'Never'}`;}
    
    // Distribution bar
    const dist=[0,0,0,0,0];
    scores.forEach(s=>{const l=getLevel(s);dist[4-l]++;});
    const total=scores.length||1;
    const colors=['#ff0000','#ff6600','#ffcc00','#ffff00','#00ff00'];
    let barHTML='',legendHTML='';
    for(let i=0;i<5;i++){
        const pct=(dist[i]/total*100).toFixed(1);
        if(pct>0){barHTML+=`<div class="dist-segment" style="width:${pct}%;background:${colors[i]}"></div>`;}
        legendHTML+=`<span class="legend-item"><span class="dot" style="background:${colors[4-i]}"></span>Lv${i+1}: ${dist[i]}</span>`;
    }
    document.getElementById('dist-bar').innerHTML=barHTML||'<div class="dist-segment" style="width:100%;background:#333"></div>';
    document.getElementById('dist-legend').innerHTML=legendHTML;
    
    // Radar chart — update data only, never destroy
    if(radarChart && Object.keys(domains).length){
        const labels=Object.keys(domains);
        const values=labels.map(k=>domains[k].score);
        radarChart.data.labels=labels;
        radarChart.data.datasets[0].data=values;
        radarChart.update('none'); // No animation to prevent "falling" effect
    }
    
    // Trend chart — update data only, never destroy
    if(trendChart && history.length){
        const recent=history.slice(-20);
        trendChart.data.labels=recent.map((_,i)=>`#${i+1}`);
        trendChart.data.datasets[0].data=recent.map(h=>h.overall_score);
        trendChart.update('none'); // No animation to prevent "falling" effect
    }
    
    // Domain cards
    const grid=document.getElementById('domains-grid');
    grid.innerHTML='';
    for(const[name,domain] of Object.entries(domains)){
        const lvl=getLevel(domain.score);
        const color=LEVELS[lvl].color;
        const card=document.createElement('div');
        card.className='domain-card';
        card.style.borderLeftColor=color;
        card.innerHTML=`
            <div class="dc-header">
                <span class="dc-name">${domain.icon||'📡'} ${name}</span>
                <span class="dc-level" style="color:${color}">${LEVELS[lvl].name}</span>
            </div>
            <div class="dc-body">
                <div class="dc-score-bar"><div class="dc-score-fill" style="width:${domain.score}%;background:${color}"></div></div>
                <div class="dc-info">Score: ${domain.score}/100 | Value: ${domain.value}</div>
            </div>`;
        grid.appendChild(card);
    }
    
    // Alerts
    const alertsDiv=document.getElementById('alerts-feed');
    alertsDiv.innerHTML='';
    const alerts=[];
    for(const[name,domain] of Object.entries(domains)){
        if(domain.score>=40){
            alerts.push(`<div class="alert-item alert-warn"><strong>${name}</strong> — ${LEVELS[getLevel(domain.score)].name} (${domain.score}/100)</div>`);
        }
    }
    if(!alerts.length) alerts.push('<div class="alert-item">✅ All domains within normal parameters</div>');
    alertsDiv.innerHTML=alerts.join('');
    
    // History table
    const tbody=document.getElementById('history-body');
    tbody.innerHTML='';
    history.slice().reverse().slice(0,10).forEach(h=>{
        const tr=document.createElement('tr');
        tr.innerHTML=`<td>${h.time?new Date(h.time).toLocaleTimeString():'-'}</td><td>${h.overall_score}</td><td>${h.domains_scanned}</td><td>${h.duration_s}s</td>`;
        tbody.appendChild(tr);
    });
    
    // Footer
    document.getElementById('last-updated').textContent=`Last updated: ${data.last_scan_time?new Date(data.last_scan_time).toLocaleTimeString():'Never'}`;
    if(data.scan_duration){document.getElementById('scan-info').textContent=`Scan took ${(data.scan_duration*1000).toFixed(0)}ms`;}else{document.getElementById('scan-info').textContent='';}
}

async function forceRefresh(){
    try{
        const resp=await fetch('/api/refresh',{method:'POST'});
        if(resp.ok){renderDashboard(await resp.json());}
    }catch(e){console.error(e);}
}

function exportJSON(){
    fetch('/api/data').then(r=>r.json()).then(d=>{
        const blob=new Blob([JSON.stringify(d,null,2)],{type:'application/json'});
        const a=document.createElement('a');
        a.href=URL.createObjectURL(blob);a.download=`defcon_export_${Date.now()}.json`;a.click();
    });
}

// Init charts once on page load (persistent instances)
initCharts();

// Initial data fetch and render
fetchData().then(renderDashboard);

// Auto-refresh every 60 seconds
setInterval(()=>{fetchData().then(renderDashboard).catch(e=>console.error('Auto-refresh failed:',e));},60000);
</script>
</body>
</html>'''

# ─── API Routes ──────────────────────────────
@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/data')
def api_data():
    with state.lock:
        data = {
            'domains': state.data,
            'history': state.history[-20:],
            'scanning': state.scanning,
            'last_scan_time': state.last_scan_time.isoformat() if state.last_scan_time else None,
            'scan_duration': state.scan_duration
        }
    return jsonify(data)

@app.route('/api/refresh', methods=['POST'])
def api_refresh():
    """Force an immediate scan (blocking)."""
    threading.Thread(target=state.force_scan, daemon=True).start()
    # Return current cached data immediately
    with state.lock:
        return jsonify({
            'domains': state.data,
            'history': state.history[-20:],
            'scanning': True,
            'last_scan_time': state.last_scan_time.isoformat() if state.last_scan_time else None,
            'scan_duration': state.scan_duration
        })

# ─── Startup ──────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=PORT)
    args = parser.parse_args()
    
    print(f"🛡️  DEFCON Monitor v4.0")
    print(f"   Dashboard: http://localhost:{args.port}")
    print(f"   Refresh interval: {REFRESH_INTERVAL}s")
    print(f"   Starting background scan...")
    
    # Run initial scan
    state.force_scan()
    
    # Start background scanning
    state.start_background_scan()
    
    app.run(host='0.0.0.0', port=args.port, debug=False)

if __name__ == '__main__':
    main()
