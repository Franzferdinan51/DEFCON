"""HTTP fetcher — robust fetch with retries, UA rotation, TLS, and timeout."""
import json, re, logging, time, ssl
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("defcon.fetcher")

# Rotating User-Agent strings — avoids trivial bot blocking
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 "
    "Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 "
    "Firefox/128.0",
]


@dataclass
class FetchResult:
    url: str
    success: bool
    content: str = ""
    status_code: int = 0
    error: str = ""
    elapsed_ms: float = 0.0


def fetch(
    url: str,
    timeout: int = 15,
    max_retries: int = 3,
    retry_delay: float = 3.0,
    verify_ssl: bool = True,
    ua_index: int = 0,
) -> FetchResult:
    """
    Fetch a URL with retries, exponential backoff, and rotating User-Agent.

    Args:
        url: Target URL
        timeout: Request timeout in seconds
        max_retries: Number of retry attempts on failure
        retry_delay: Base delay between retries (doubles each attempt)
        verify_ssl: Whether to verify TLS certificates
        ua_index: Index into USER_AGENTS pool

    Returns:
        FetchResult with content or error details
    """
    ua = USER_AGENTS[ua_index % len(USER_AGENTS)]

    for attempt in range(1, max_retries + 1):
        t0 = time.perf_counter()
        try:
            req = Request(url, headers={
                "User-Agent": ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
            })
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
                logger.debug("fetch [%s] %s → HTTP %d (%.0fms)",
                             attempt, url, resp.status, elapsed_ms)
                return FetchResult(
                    url=url, success=True, content=content,
                    status_code=resp.status, elapsed_ms=elapsed_ms,
                )

        except HTTPError as e:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            err = f"HTTP {e.code} {e.reason}"
            logger.warning("fetch [%s] %s → %s", attempt, url, err)
            if attempt == max_retries:
                return FetchResult(url=url, success=False, error=err,
                                   elapsed_ms=elapsed_ms, status_code=e.code)

        except URLError as e:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            err = f"URL error: {e.reason}"
            logger.warning("fetch [%s] %s → %s", attempt, url, err)
            if attempt == max_retries:
                return FetchResult(url=url, success=False, error=err,
                                   elapsed_ms=elapsed_ms)

        except Exception as e:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            err = str(e)
            logger.error("fetch [%s] %s → %s", attempt, url, err)
            if attempt == max_retries:
                return FetchResult(url=url, success=False, error=err,
                                   elapsed_ms=elapsed_ms)

        # Exponential backoff before retry
        if attempt < max_retries:
            wait = retry_delay * (2 ** (attempt - 1))
            logger.debug("retry %s in %.1fs", url, wait)
            time.sleep(wait)

    # Should not reach here
    return FetchResult(url=url, success=False, error="max retries exceeded")


def fetch_json(url: str, **kwargs) -> Optional[dict]:
    """Fetch and parse JSON from a URL."""
    result = fetch(url, **kwargs)
    if not result.success:
        return None
    try:
        return json.loads(result.content)
    except json.JSONDecodeError:
        return None


def fetch_defcon_from_page(html: str) -> Optional[int]:
    """
    Extract DEFCON level from defconlevel.com HTML.

    Strategy:
      1. Look for structured meta tags / JSON data
      2. Look for "DEFCON N" in page text
      3. Look for level-N CSS class / data attributes
    """
    # Remove HTML comments to avoid false matches
    html_clean = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)
    html_lower = html_clean.lower()

    # Strategy 1: explicit "defcon N" near keywords
    m = re.search(
        r'defcon\s+<[^>]*>\s*(\d)\b|'
        r'\bdefcon\s+(\d)\b|'
        r'"level"\s*:\s*"?(\d)"?.*?(?:defcon|source)',
        html_lower
    )
    if m:
        for g in m.groups():
            if g and g.isdigit() and 1 <= int(g) <= 5:
                return int(g)

    # Strategy 2: defcon-N pattern in CSS classes or IDs
    m = re.search(r'defcon[_-]?level[_-]?(\d)', html_lower)
    if m:
        lvl = int(m.group(1))
        if 1 <= lvl <= 5:
            return lvl

    # Strategy 3: Look for a numeric level near "current" and "defcon"
    patterns = [
        r'current.*?(?:defcon|level).*?(\d)',
        r'(?:defcon|level).*?current.*?(\d)',
    ]
    for pat in patterns:
        m = re.search(pat, html_lower)
        if m:
            g = m.group(1)
            if g.isdigit() and 1 <= int(g) <= 5:
                return int(g)

    return None
