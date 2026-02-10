from urllib.parse import urljoin, urlparse, urldefrag, parse_qs
from typing import List, Dict, Any, Set, Tuple
from bs4 import BeautifulSoup
import json

from core.http import HTTPClient
from core.crawl import extract_forms
from core.discovery_api import discover_api_endpoints, discover_openapi_specs
from core.openapi import parse_openapi_targets


SKIP_EXT = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
    ".css", ".map",
    ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv",
    ".woff", ".woff2", ".ttf", ".eot",
}


def _looks_like_file(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in SKIP_EXT)


def _same_host(a: str, b: str) -> bool:
    """
    Redirect-safe host comparison.
    Treat demo.testfire.net vs www.demo.testfire.net as same host.
    """
    na = urlparse(a).netloc.lower()
    nb = urlparse(b).netloc.lower()

    if na.startswith("www."):
        na = na[4:]
    if nb.startswith("www."):
        nb = nb[4:]

    return na == nb


def _normalize_url(base: str, href: str) -> str | None:
    if not href:
        return None
    href = href.strip()

    if href.startswith("#") or href.startswith("mailto:") or href.startswith("javascript:"):
        return None

    u = urljoin(base, href)
    u, _ = urldefrag(u)
    return u


def extract_links(page_url: str, html: str) -> List[str]:
    soup = BeautifulSoup(html, "lxml")
    out: List[str] = []
    for a in soup.find_all("a"):
        u = _normalize_url(page_url, a.get("href"))
        if u:
            out.append(u)
    return out


def _looks_like_json(body: str) -> bool:
    """
    Best-effort JSON detection so pure API endpoints (e.g. httpbin /get)
    can become scan targets even without HTML links/forms.
    """
    if not body:
        return False
    s = body.lstrip()
    if not (s.startswith("{") or s.startswith("[")):
        return False
    if "<html" in s[:400].lower():
        return False
    try:
        json.loads(s[:50000])
        return True
    except Exception:
        return False


def crawl_site(
    client: HTTPClient,
    start_url: str,
    depth: int = 1,
    max_pages: int = 50,
    same_host_only: bool = True,
    spa_fast: bool = False,
) -> Dict[str, Any]:

    # SPA fast mode: only the shell page is usually useful
    if spa_fast:
        depth = 0
        max_pages = min(max_pages, 3)

    visited: Set[str] = set()
    queue: List[Tuple[str, int]] = [(start_url, 0)]

    pages: List[Dict[str, Any]] = []
    forms_index: List[Dict[str, Any]] = []

    discovered_api_endpoints: Set[str] = set()
    openapi_targets: List[Dict[str, Any]] = []

    # NEW: URLs that already contain query strings (?a=b&c=d)
    discovered_query_urls: Set[str] = set()

    # cache for JS fetching in discover_api_endpoints
    js_cache: Dict[str, str] = {}

    # prevent re-fetching the same spec multiple times
    fetched_specs: Set[str] = set()

    # NEW: root_url becomes the first successfully fetched final_url (redirect-safe)
    root_url: str = start_url
    root_set = False

    while queue and len(visited) < max_pages:
        url, d = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        if _looks_like_file(url):
            continue

        try:
            status, body, elapsed, final_url = client.request("GET", url)
        except Exception:
            continue

        # lock root host based on final_url of first successful fetch
        if not root_set:
            root_url = final_url
            root_set = True

        # NEW: record query-param URLs for classic apps
        try:
            p = urlparse(final_url)
            if p.query:
                qs = parse_qs(p.query)
                if qs:  # only if it has real keys
                    discovered_query_urls.add(final_url)
        except Exception:
            pass

        # If this is a pure JSON/API endpoint, treat it as an API target too
        if _looks_like_json(body):
            discovered_api_endpoints.add(final_url)

        # Forms (server-rendered)
        try:
            forms = extract_forms(final_url, body)
        except Exception:
            forms = []

        for f in forms:
            forms_index.append({
                "source_page": final_url,
                "method": f["method"],
                "action": f["action"],
                "fields": f["fields"],
                "hidden": f.get("hidden", {}) or {},
            })

        # Links
        try:
            links = extract_links(final_url, body)
        except Exception:
            links = []

        # API endpoints from JS mining (kept)
        try:
            api_endpoints = discover_api_endpoints(client, final_url, body, js_cache=js_cache)
        except Exception:
            api_endpoints = set()

        for api in api_endpoints:
            discovered_api_endpoints.add(api)

        # Swagger/OpenAPI spec discovery
        try:
            spec_urls = discover_openapi_specs(final_url, body)
        except Exception:
            spec_urls = set()

        for spec_url in spec_urls:
            if spec_url in fetched_specs:
                continue
            fetched_specs.add(spec_url)

            try:
                _, spec_body, _, _ = client.request("GET", spec_url)
                spec = json.loads(spec_body)
                openapi_targets.extend(parse_openapi_targets(final_url, spec))
            except Exception:
                pass

        pages.append({
            "url": final_url,
            "status": status,
            "elapsed": round(elapsed, 4),
            "links": links[:200],
            "api_endpoints": list(api_endpoints),
        })

        # Continue crawling links
        if d + 1 <= depth:
            for link in links:
                if same_host_only and not _same_host(root_url, link):
                    continue
                if link not in visited:
                    queue.append((link, d + 1))

    return {
        "start_url": start_url,
        "pages_crawled": len(pages),
        "pages": pages,
        "forms_index": forms_index,
        "api_endpoints": sorted(discovered_api_endpoints),
        "openapi_targets": openapi_targets,
        "query_urls": sorted(discovered_query_urls),  # NEW
    }
