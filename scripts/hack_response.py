
#!/usr/bin/env python3
"""DEFCON Hack Response Protocol v3.3 - local PC incident response.
Run immediately if your PC is compromised. Works offline. No internet needed.
Output: C:\\DEFCON_HACK\\{timestamp}\\
Usage:
  python hack_response.py --collect   Full auto collection
  python hack_response.py --report    Show latest report
  python hack_response.py --rules     Show 5-phase IR protocol
"""
import os, sys, json, logging, subprocess, platform, socket
from pathlib import Path
from datetime import datetime, timezone

OUT_DIR = Path(os.environ.get("DEFCON_HACK_DIR", "C:\\DEFCON_HACK"))
TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
OUT = OUT_DIR / TS
OUT.mkdir(parents=True, exist_ok=True)
LOGF = OUT / "hack_response.log"
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s",
    handlers=[logging.FileHandler(LOGF), logging.StreamHandler()])
log = logging.getLogger("hack")

def run(cmd, label=""):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return r.stdout + r.stderr
    except Exception as e:
        return "ERROR: " + str(e)

def phase1_collect():
    log.info("=== PHASE 1: DETECT & COLLECT ===")
    reports = {}
    reports["systeminfo.txt"] = run("systeminfo")
    reports["netstat.txt"] = run("netstat -ano")
    reports["tasks.txt"] = run("tasklist /v")
    reports["services.txt"] = run("sc query state= all")
    reports["drivers.txt"] = run("driverquery /v")
    reports["hosts.txt"] = run("type C:\\Windows\\System32\\drivers\\etc\\hosts")
    reports["arp.txt"] = run("arp -a")
    reports["ipconfig.txt"] = run("ipconfig /all")
    reports["firewall.txt"] = run("netsh advfirewall show allprofiles")
    reports["users.txt"] = run("net user")
    reports["admin.txt"] = run("net localgroup Administrators")
    reports["hostname.txt"] = socket.gethostname()
    reports["platform.txt"] = platform.platform()
    for fname, data in reports.items():
        (OUT / fname).write_text(data, errors="replace")
    log.info("Collected %d system reports to %s", len(reports), OUT)

def phase2_assess():
    log.info("=== PHASE 2: ASSESS ===")
    suspicious = []
    ioc_patterns = ["mimikatz", "pwdump", "metasploit", "cobalt strike",
                   "revshell", "powersploit", "empire", "pupy", "koadic",
                   "keylogger", "hookredirect", "processinject"]
    for f in OUT.iterdir():
        if not f.is_file(): continue
        txt = f.read_text(errors="replace").lower()
        for kw in ioc_patterns:
            if kw in txt:
                suspicious.append(f.name + ": IOC '" + kw + "'")
    if suspicious:
        log.warning("SUSPICIOUS: %d items found", len(suspicious))
        for s in suspicious: log.warning("  %s", s)
    else:
        log.info("No common IOCs found")
    (OUT / "assessment.json").write_text(json.dumps({
        "ts": TS, "suspicious": suspicious,
        "hostname": socket.gethostname()
    }, indent=2))
    log.info("Assessment: %s", OUT)

# ── Phase 3: Wireshark PCAP analysis ────────────────────────────────────
TSHARK_PATHS = ["C:\\Program Files\\Wireshark\\tshark.exe",
                "C:\\Program Files (x86)\\Wireshark\\tshark.exe",
                "/usr/bin/tshark","/usr/local/bin/tshark"]

def find_tshark():
    for p in TSHARK_PATHS:
        if Path(p).exists(): return p
    return None

def phase3_wireshark():
    print("\n" + "="*55)
    print("  PHASE 3: WIRESHARK / PCAP ANALYSIS")
    print("="*55)
    tshark = find_tshark()
    if not tshark:
        print("\n  [tshark NOT found — install Wireshark and add to PATH]")
        print("  Download: https://wireshark.org/download.html")
        print("  Add to PATH: setx PATH \"%PATH%;C:\\Program Files\\Wireshark\"")
        return
    print("\n  [tshark found: " + tshark + "]")
    print("\n  QUICK WIRESHARK FILTERS — copy and run in Wireshark:")
    print("  https://wiki.wireshark.org/DisplayFilters")
    print("\n  COMMON ATTACK FILTERS:")
    print("    tcp.port == 4444              # Metasploit default")
    print("    tcp.port == 5555              # Meterpreter default")
    print("    tcp.port == 31337             # Elite/C2")
    print("    tcp.port == 8080 && tcp.flags  # Backdoor C2")
    print("    http.request.uri contains cmd  # Shells")
    print("    dns.qry.name contains tor     # TOR DNS")
    print("    data.len > 1000              # Data exfil")
    print("    tcp.analysis.retransmission   # Beaconing")
    print("    tcp.flags.syn == 1 && tcp.flags.ack == 0  # SYN scan")
    print("\n  LIVE CAPTURE (5 min, save to file):")
    print("    tshark -i eth0 -a duration:300 -w capture.pcap")
    print("  CAPTURE SPECIFIC IP ONLY:")
    print("    tshark -i eth0 -f 'host 1.2.3.4' -w capture.pcap")
    print("  EXTRACT HTTP URLs FROM PCAP:")
    print("    tshark -r capture.pcap -Y http.request -T fields -e ip.src -e http.request.uri")
    print("  EXTRACT DNS QUERIES:")
    print("    tshark -r capture.pcap -Y dns -T fields -e ip.src -e dns.qry.name")
    print("  SHOW ALL UNIQUE IPs:")
    print("    tshark -r capture.pcap -q -z ips,stats")
    print("  PACKET STATS:")
    print("    capinfos capture.pcap")
    print("\n  RECOMMENDED CAPTURE FILTER (honeypot monitoring):")
    print("    not broadcast and not multicast and not arp")
    print("  SAVE TO: C:\\DEFCON_HACK\\{timestamp}\\packets.pcap")
    print("\n" + "="*55)

# ── Phase 4: Attacker intel ───────────────────────────────────────────────
BAD_IP_RANGES = ["185.220.101","92.63.197","89.248.167","45.33.32",
                 "162.142.125","167.94.138","198.51.100","203.0.113"]

def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except: return "ERROR"

def geoip(ip):
    if any(ip.startswith(b) for b in ["192.168.","10.","172.","127."]):
        return {"ip": ip, "country": "PRIVATE", "org": "Local LAN"}
    try:
        import ssl, urllib.request
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        url = "http://ip-api.com/json/" + ip
        req = urllib.request.Request(url, headers={"User-Agent": "DEFCON-Intel/3.4"})
        with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
            d = json.loads(r.read())
        if d.get("status") == "success":
            return {"ip": ip, "country": d.get("country",""), "city": d.get("city",""),
                    "org": d.get("org",""), "asn": d.get("as","")}
    except: pass
    return {"ip": ip, "country": "UNKNOWN", "org": "lookup failed"}

def phase4_attacker_intel():
    print("\n" + "="*55)
    print("  PHASE 4: ATTACKER INTELLIGENCE COLLECTION")
    print("="*55)
    print("\n  [1] Extracting external connections from netstat...")
    netstat_out = run("netstat -ano")
    external_ips = []
    for line in netstat_out.splitlines():
        line = line.strip()
        if not line or line.startswith(("Active","Proto","  TCP","  UDP")): continue
        parts = line.split()
        if len(parts) >= 4:
            remote = parts[2]
            ip = remote.split(":")[0]
            if ip and not any(ip.startswith(b) for b in ["192.168.","10.","172.","127.","0."]):
                if ip not in external_ips: external_ips.append(ip)
    print("  Found " + str(len(external_ips)) + " unique external IPs")
    print("\n  [2] Geo-IP attribution (ip-api.com):")
    attributed = []
    for ip in external_ips[:15]:
        g = geoip(ip)
        is_bad = any(ip.startswith(b) for b in BAD_IP_RANGES)
        flag = " *** KNOWN BAD RANGE ***" if is_bad else ""
        print("    " + ip + "  " + g.get("country","?") + "  " + g.get("org","?")[:40] + flag)
        attributed.append({"ip": ip, "geo": g, "bad": is_bad})
    sus = [a for a in attributed if a.get("bad") or a["geo"].get("country") not in ("United States","Canada","")]
    if sus:
        print("\n  RED FLAGS — suspicious IPs:")
        for s in sus: print("    " + s["ip"] + "  " + s["geo"].get("country","?") + "  " + s["geo"].get("org","?"))
    print("\n  [3] Recommended firewall blocks:")
    for s in sus[:10]:
        print("    netsh advfirewall firewall add rule name=\"DEFCON_BLOCK_" + s["ip"] + "\" dir=in action=block remoteip=" + s["ip"])
    print("\n  [4] Full attacker intel tool:")
    print("    python scripts/attacker_intel.py    # Full WHOIS, Shodan, VirusTotal")
    print("\n  [5] VirusTotal free lookup:")
    print("    https://virustotal.com/gui/ip-address/" + (sus[0]["ip"] if sus else "ATTACKER_IP"))
    print("\n  [6] AbuseIPDB (for foreign IPs):")
    print("    https://www.abuseipdb.com/check/" + (sus[0]["ip"] if sus else "ATTACKER_IP"))
    print("\n  [7] Shodan (what services is attacker running?):")
    print("    https://www.shodan.io/host/" + (sus[0]["ip"] if sus else "ATTACKER_IP"))
    print("\n" + "="*55)

def phase3_rules():
    print("\n" + "="*60)
    print("  DEFCON HACK RESPONSE — 5-PHASE IR PROTOCOL")
    print("="*60)
    phases = [
        ("1 DETECT & COLLECT", [
            "Disconnect from network NOW (WiFi + Ethernet)",
            "Run: python hack_response.py --collect",
            "Collects: systeminfo, netstat, tasks, drivers, hosts, firewall",
            "Output saved to C:\\DEFCON_HACK\\{timestamp}\\"]),
        ("2 CONTAIN & ISOLATE", [
            "Kill suspicious processes: taskkill /PID {pid} /F",
            "Enable firewall: netsh advfirewall set allprofiles state on",
            "Revoke sessions: logoff {sessionid}",
            "Preserve evidence — do NOT delete anything yet",
            "Scope blast radius: which systems are affected?"]),
        ("3 ERADICATE & HARDEN", [
            "Full antivirus scan (Windows Defender + Malwarebytes)",
            "Reset ALL compromised credentials",
            "Patch OS and all software to latest",
            "Audit admin group membership",
            "Remove any persistence mechanisms found"]),
        ("4 RECOVER & RESTORE", [
            "Restore from known-good backup (pre-compromise date)",
            "Verify backup is clean before restoring",
            "Reset all passwords system-wide (scope-dependent)",
            "Enable advanced monitoring on restored systems"]),
        ("5 POST-INCIDENT", [
            "Conduct full incident review",
            "Update DEFCON threat log with new IOCs",
            "Document attacker TTPs (MITRE ATT&CK)",
            "Notify law enforcement if data exfil (FBI IC3, CISA)",
            "Update your IR plan with lessons learned"]),
    ]
    for name, steps in phases:
        print("\n  [" + name + "]")
        for s in steps: print("    - " + s)
    print("\n  AUTHORITIES:")
    print("    FBI IC3:    ic3.gov")
    print("    CISA:       cisa.gov/report")
    print("    NSA:        spylabs.gov (for nation-state intrusions)")

def main():
    import argparse
    p = argparse.ArgumentParser(description="DEFCON Hack Response")
    p.add_argument("--collect", action="store_true", help="Run auto collection + assessment")
    p.add_argument("--assess", action="store_true", help="Assess latest collection")
    p.add_argument("--rules", action="store_true", help="Show IR protocol")
    p.add_argument("--wireshark", action="store_true", help="Wireshark PCAP analysis guide")
    p.add_argument("--attacker", action="store_true", help="Attacker intel collection + geo-IP")
    args = p.parse_args()
    if args.collect:
        phase1_collect(); phase2_assess()
        print("Collection complete: " + str(OUT))
    elif args.assess:
        phase2_assess()
    elif args.wireshark:
        phase3_wireshark()
    elif args.attacker:
        phase4_attacker_intel()
    else:
        phase3_rules()
        print("\nUsage: python hack_response.py --collect")
        print("       python hack_response.py --wireshark")
        print("       python hack_response.py --attacker")

if __name__ == "__main__": main()
