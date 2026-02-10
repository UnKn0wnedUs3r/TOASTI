import re
from typing import Set, Dict, Optional, List
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


# --- Regex patterns to mine endpoints from JS/HTML ---

# Relative API paths in quotes, like "/rest/...", "/api/...", "/graphql"
RE_REL_API = re.compile(
    r"""(?:"|')(/(?:rest|api|graphql)[^"' \n\r\t<>()]*)(?:"|')""",
    re.IGNORECASE
)

# Absolute URLs in quotes
RE_ABS_URL = re.compile(
    r"""(?:"|')(https?://[^"' \n\r\t<>()]+)(?:"|')""",
    re.IGNORECASE
)

# Sometimes endpoints appear without quotes (rare but happens)
RE_BARE_API = re.compile(
    r"""(/(?:rest|api|graphql)[A-Za-z0-9_\-./?=&%:+~#@]+)""",
    re.IGNORECASE
)


def _same_origin(a: str, b: str) -> bool:
    try:
        pa = urlparse(a)
        pb = urlparse(b)
        return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)
    except Exception:
        return False


def _is_http_url(u: str) -> bool:
    try:
        p = urlparse(u)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def _extract_script_srcs(page_url: str, html: str) -> List[str]:
    soup = BeautifulSoup(html, "lxml")
    srcs: List[str] = []

    for s in soup.find_all("script"):
        src = s.get("src")
        if not src:
            continue
        full = urljoin(page_url, src)
        if _is_http_url(full):
            srcs.append(full)

    return srcs


def _extract_inline_scripts(html: str) -> List[str]:
    soup = BeautifulSoup(html, "lxml")
    chunks: List[str] = []
    for s in soup.find_all("script"):
        if s.get("src"):
            continue
        txt = s.get_text() or ""
        if txt.strip():
            chunks.append(txt)
    return chunks


def _mine_endpoints_from_text(base_url: str, text: str) -> Set[str]:
    """
    Mine likely API endpoints from any text blob (HTML/JS).
    Returns absolute URLs (via urljoin for relative endpoints).
    """
    found: Set[str] = set()

    # Relative API paths -> full URL
    for m in RE_REL_API.findall(text):
        found.add(urljoin(base_url, m))

    for m in RE_BARE_API.findall(text):
        found.add(urljoin(base_url, m))

    # Absolute URLs (filter to same-origin later)
    for u in RE_ABS_URL.findall(text):
        if _is_http_url(u):
            found.add(u)

    return found


def discover_openapi_specs(page_url: str, html: str) -> Set[str]:
    """
    Discover likely OpenAPI/Swagger spec URLs from the HTML.
    Useful for sites like petstore/swagger UI.
    """
    found: Set[str] = set()
    soup = BeautifulSoup(html, "lxml")

    candidates = set()

    # Look for direct references in HTML (best-effort)
    for m in re.findall(r"""(https?://[^"' ]+swagger[^"' ]+)""", html, re.IGNORECASE):
        candidates.add(m)

    # Try common spec paths (best-effort)
    for p in ["/swagger.json", "/openapi.json", "/api-docs", "/v2/api-docs", "/swagger/v1/swagger.json"]:
        candidates.add(urljoin(page_url, p))

    for c in candidates:
        if _is_http_url(c):
            found.add(c)

    return found


def discover_api_endpoints(client, page_url: str, html: str, js_cache: Optional[Dict[str, str]] = None) -> Set[str]:
    """
    SPA/API endpoint discovery (no hardcoded app seeds):
      - mine HTML
      - mine inline scripts
      - fetch and mine external JS bundles (same-origin only)
      - return same-origin full URLs to endpoints
    """
    base = page_url
    js_cache = js_cache if js_cache is not None else {}

    endpoints: Set[str] = set()

    # Mine the HTML itself
    endpoints |= _mine_endpoints_from_text(base, html)

    # Inline scripts
    for chunk in _extract_inline_scripts(html):
        endpoints |= _mine_endpoints_from_text(base, chunk)

    # External JS bundles (scripts)
    script_urls = _extract_script_srcs(base, html)

    for js_url in script_urls:
        # Only pull same-origin JS by default (avoids downloading CDNs forever)
        if not _same_origin(base, js_url):
            continue

        if js_url in js_cache:
            js_text = js_cache[js_url]
        else:
            try:
                status, js_text, _, _ = client.request("GET", js_url)
                if status >= 400 or not js_text:
                    continue
                js_cache[js_url] = js_text
            except Exception:
                continue

        endpoints |= _mine_endpoints_from_text(base, js_text)

    # Filter: keep same-origin only
    endpoints = {u for u in endpoints if _is_http_url(u) and _same_origin(base, u)}

    return endpoints
