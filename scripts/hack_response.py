
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

OUT_DIR
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
    args = p.parse_args()
    if args.collect:
        phase1_collect(); phase2_assess()
        print("Collection complete: " + str(OUT))
    elif args.assess:
        phase2_assess()
    else:
        phase3_rules()
        print("\nUsage: python hack_response.py --collect")

if __name__ == "__main__": main()
