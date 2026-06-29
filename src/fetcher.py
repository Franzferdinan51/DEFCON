"""
HTTP Fetcher — production-grade web client with retry, TLS, UA rotation, caching.
"""
import json, logging, time, ssl, hashlib, re
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

logger = logging.getLogger("defcon.fetcher")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
]

HEADERS_BASE = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}


@dataclass
class FetchResult:
    url: str
    success: bool
    content: str = ""
    status_code: int = 0
    error: str = ""
    elapsed_ms: float = 0.0
    from_cache: bool = False
    etag: str = ""
    cache_max_age_sec: int = 0


class FetchCache:
    """Simple disk-backed HTTP cache (RFC 7234 inspired)."""

    def __init__(self, cache_dir: Optional[Path] = None, max_age_sec: int = 300):
        self.cache_dir = cache_dir or (Path(__file__).parent.parent / ".cache")
        self.max_age_sec = max_age_sec
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _key(self, url: str) -> Path:
        h = hashlib.sha256(url.encode()).hexdigest()[:16]
        return self.cache_dir / f"{h}.http_cache"

    def get(self, url: str) -> Optional[FetchResult]:
        """Return cached result if fresh, else None."""
        p = self._key(url)
        if not p.exists():
            return None
        try:
            import email.utils
            meta, content = p.read_text().split("\n\n", 1)
            lines = meta.split("\n")
            cached_at = float([l for l in lines if l.startswith("X-Cached-At:")][0].split(":", 1)[1])
            etag = [l for l in lines if l.startswith("ETag:")][0].split(":", 1)[1].strip()
            age = time.time() - cached_at
            if age > self.max_age_sec:
                return None
            return FetchResult(url=url, success=True, content=content,
                               from_cache=True, etag=etag, cache_max_age_sec=int(age))
        except Exception:
            return None

    def set(self, url: str, result: FetchResult, etag: str = ""):
        p = self._key(url)
        try:
            p.write_text(
                f"X-Cached-At: {time.time()}\n"
                f"ETag: {etag}\n"
                f"Status: {result.status_code}\n\n"
                f"{result.content}"
            )
        except Exception:
            pass


def fetch(
    url: str,
    timeout: int = 15,
    max_retries: int = 3,
    retry_delay: float = 2.0,
    verify_ssl: bool = True,
    ua_index: int = 0,
    cache: Optional[FetchCache] = None,
    if_none_match: str = "",
) -> FetchResult:
    """
    Fetch a URL with retries, exponential backoff, rotating User-Agent.

    Cache: pass a FetchCache() instance to enable RFC-7234 style caching.
    """
    # ── Check cache ──────────────────────────────────────────────────────
    if cache:
        cached = cache.get(url)
        if cached:
            cached.from_cache = True
            logger.debug("cache HIT: %s (%.0fs old)", url, cached.cache_max_age_sec)
            return cached

    headers = dict(HEADERS_BASE)
    headers["User-Agent"] = USER_AGENTS[ua_index % len(USER_AGENTS)]
    if if_none_match:
        headers["If-None-Match"] = if_none_match

    for attempt in range(1, max_retries + 1):
        t0 = time.perf_counter()
        try:
            req = Request(url, headers=headers)
            ctx: Optional[ssl.SSLContext] = None
            if not verify_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            with urlopen(req, timeout=timeout, context=ctx) as resp:
                raw = resp.read()
                encoding = resp.headers.get_content_charset() or "utf-8"
                try:
                    content = raw.decode(encoding)
                except UnicodeDecodeError:
                    content = raw.decode("utf-8", errors="replace")

                elapsed_ms = (time.perf_counter() - t0) * 1000
                etag = resp.headers.get("ETag", "")
                result = FetchResult(
                    url=url, success=True, content=content,
                    status_code=resp.status, elapsed_ms=elapsed_ms, etag=etag,
                )
                if cache:
                    cache.set(url, result, etag)
                logger.debug("fetch [%s] %s → HTTP %d (%.0fms)",
                             attempt, url, resp.status, elapsed_ms)
                return result

        except HTTPError as e:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            err = f"HTTP {e.code} {e.reason}"
            if e.code == 304 and if_none_match:
                # Not Modified — treat as cache hit
                return FetchResult(url=url, success=True, content="",
                                   status_code=304, elapsed_ms=elapsed_ms, from_cache=True)
            if attempt == max_retries:
                return FetchResult(url=url, success=False, error=err,
                                   elapsed_ms=elapsed_ms, status_code=e.code)
            logger.warning("fetch [%s] %s → %s", attempt, url, err)

        except Exception as e:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            err = str(e)
            logger.warning("fetch [%s] %s → %s", attempt, url, err)
            if attempt == max_retries:
                return FetchResult(url=url, success=False, error=err, elapsed_ms=elapsed_ms)

        if attempt < max_retries:
            wait = retry_delay * (2 ** (attempt - 1))
            time.sleep(wait)

    return FetchResult(url=url, success=False, error="max retries exceeded")


def fetch_json(url: str, **kwargs) -> Optional[dict]:
    """Fetch and parse JSON from a URL. Falls back to text extraction."""
    result = fetch(url, **kwargs)
    if not result.success:
        return None
    try:
        return json.loads(result.content)
    except json.JSONDecodeError:
        return None


def extract_defcon_from_html(html: str) -> Optional[int]:
    """Parse DEFCON level from defconlevel.com HTML."""
    html_lower = html.lower()
    # defcon N
    m = re.search(r"\bdefcon\s+(\d)\b", html_lower)
    if m and 1 <= int(m.group(1)) <= 5:
        return int(m.group(1))
    # data-level, level-N, defcon-level-N
    m = re.search(r"(?:defcon[-_]?level|data[-_]?level)[-_]?(\d)", html_lower)
    if m and 1 <= int(m.group(1)) <= 5:
        return int(m.group(1))
    return None
