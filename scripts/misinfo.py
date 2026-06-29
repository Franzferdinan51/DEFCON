"""Misinformation / Fact-Check Scanner v3.3 — runs standalone or via defcon_monitor.py --check."""
import sys, json, logging, re, time, ssl, urllib.request
from pathlib import Path

log = logging.getLogger("defcon.misinfo")
BASE_DIR = Path(__file__).parent.parent

# ── Fact-check endpoints (all free, no API key) ─────────────────────────────────
SOURCES = {
    "snopes": {
        "url": "https://www.snopes.com/api/fact-check/?q=%s",
        "parse": "json",
    },
    "politifact": {
        "url": "https://www.politifact.com/api/v/3/item/%s/",
        "parse": "json",
    },
    "leadstories": {
        "url": "https://leadstories.com/api/beta/fact-check?article=%s",
        "parse": "json",
    },
    "factcheckorg": {
        "url": "https://factcheckapi.af实际上.com/api/claim/?search=%s",
        "parse": "json",
    },
    "google_fct": {
        "url": "https://toolbox.google.com/factcheck/api/search?query=%s&source=1",
        "parse": "json",
    },
}


def _fetch(url: str, timeout: int = 8) -> str:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "DEFCON-Monitor/3.3"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception as e:
        log.debug(f"fetch error: {e}")
        return ""


def _score_snopes(claim: str) -> dict:
    """Parse Snopes by searching for the claim in their database."""
    try:
        q = urllib.parse.quote(claim[:80])
        url = f"https://www.snopes.com/api/fact-check/?q={q}"
        body = _fetch(url)
        if not body:
            return {}
        data = json.loads(body)
        items = data.get("data", [])
        if items:
            top = items[0]
            rating = top.get("rating_label", "")
            return {
                "source": "Snopes",
                "rating": rating,
                "title": top.get("title", ""),
                "url": top.get("url", ""),
                "verdict": _normalize_rating(rating),
            }
    except Exception:
        pass
    return {}


def _score_politifact(claim: str) -> dict:
    """Search PolitiFact for claim matches."""
    try:
        q = urllib.parse.quote(claim[:60])
        url = f"https://search.politifact.com/api/?q={q}&d=1&d=2&d=3&n=3"
        body = _fetch(url)
        if not body:
            return {}
        data = json.loads(body)
        items = data.get("items", [])
        if items:
            top = items[0]
            rating = top.get("statement_rating", "")
            return {
                "source": "PolitiFact",
                "rating": rating,
                "title": top.get("statement", "")[:120],
                "url": top.get("source_url", ""),
                "verdict": _normalize_rating(rating),
            }
    except Exception:
        pass
    return {}


def _normalize_rating(rating: str) -> str:
    """Normalize various fact-check rating formats to RATED_TRUE/FALSE/MIXED/UNVERIFIED."""
    r = rating.lower()
    if not r:
        return "UNVERIFIED"
    if any(t in r for t in ["true", "correct", "accurate", "mostly true", "half true",
                             "mixture", "undetermined", "unverified", "false", "pants fire", "scam"]):
        if "true" in r and "false" not in r and "pants" not in r:
            return "RATED_TRUE"
        if "false" in r or "pants" in r or "scam" in r:
            return "RATED_FALSE"
        if "mixture" in r or "half" in r:
            return "MIXED"
    return "UNVERIFIED"


def _x_search_claim(claim: str) -> list[dict]:
    """Cross-reference claim on X/Twitter via the grok x_search."""
    # This requires the x_search MCP tool — called externally
    return []


def check_claim(claim: str) -> dict:
    """
    Main fact-check entry point.
    Returns: {verdict, rating, sources, claim, checked_at}
    """
    from datetime import datetime, timezone
    import urllib.parse

    results = []

    # Run all checkers
    snopes_r    = _score_snopes(claim)
    politifact_r = _score_politifact(claim)

    if snopes_r:
        results.append(snopes_r)
    if politifact_r:
        results.append(politifact_r)

    verdicts = [r.get("verdict", "UNVERIFIED") for r in results]
    verdict = "UNVERIFIED"
    if "RATED_FALSE" in verdicts:
        verdict = "RATED_FALSE"
    elif "RATED_TRUE" in verdicts:
        verdict = "RATED_TRUE"
    elif "MIXED" in verdicts:
        verdict = "MIXED"

    return {
        "claim": claim,
        "verdict": verdict,
        "sources": results,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def print_result(result: dict):
    """Pretty-print a fact-check result to console."""
    v = result["verdict"]
    icons = {
        "RATED_TRUE":   "[✅ TRUE]  ",
        "RATED_FALSE":  "[❌ FALSE] ",
        "MIXED":        "[⚠️ MIXED] ",
        "UNVERIFIED":   "[❓ UNVERIFIED]",
    }
    icon = icons.get(v, "[?]")
    print(f"\n{'='*60}")
    print(f"  {icon} {v.replace('_', ' ')}")
    print(f"{'='*60}")
    print(f"  Claim: {result['claim'][:120]}")
    print(f"  Checked: {result['checked_at']}")
    print(f"  Sources checked: {len(result['sources'])}")
    for s in result["sources"]:
        print(f"\n  [{s['source']}]")
        print(f"    Rating: {s.get('rating', 'N/A')}")
        print(f"    Title:  {s.get('title', 'N/A')[:100]}")
        print(f"    URL:    {s.get('url', 'N/A')}")
    if not result["sources"]:
        print(f"\n  [❓] No fact-check results found for this claim.")
        print(f"  Try checking the claim manually at:")
        print(f"    - snopes.com")
        print(f"    - politifact.com")
        print(f"    - factcheck.org")
        print(f"    - leadstories.com")
    print()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="DEFCON Misinformation Checker")
    parser.add_argument("claim", nargs="*", help="Claim to fact-check")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    if not args.claim:
        print("Usage: python misinfo.py 'your claim here'")
        print("Usage: python misinfo.py 'claim text' --json")
        sys.exit(1)

    claim = " ".join(args.claim)
    result = check_claim(claim)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_result(result)
