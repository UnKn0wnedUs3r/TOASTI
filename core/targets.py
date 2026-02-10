from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs


@dataclass
class Target:
    source_page: str
    url: str
    method: str
    params: List[str]
    hidden: Dict[str, str]
    is_json: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _same_origin(base_url: str, other_url: str) -> bool:
    try:
        a = urlparse(base_url)
        b = urlparse(other_url)
        return (a.scheme, a.netloc) == (b.scheme, b.netloc)
    except Exception:
        return False


def _guess_from_path(path: str) -> Tuple[str, List[str], bool]:
    """
    SPA/API guessing tuned to NOT break common echo APIs like httpbin.
    Returns: (method, param_candidates, is_json)
    """
    p = (path or "").lower()

    # httpbin common endpoints
    if p.endswith("/get") or p.endswith("/anything"):
        return "GET", ["test", "q", "query", "search", "term"], False
    if p.endswith("/post"):
        return "POST", ["input", "test", "q"], False
    if p.endswith("/put"):
        return "PUT", ["input", "test", "q"], False
    if p.endswith("/patch"):
        return "PATCH", ["input", "test", "q"], False
    if p.endswith("/delete"):
        return "DELETE", ["q", "test"], False

    # GraphQL
    if "/graphql" in p:
        return "POST", ["query", "variables", "operationName"], True

    # Search-like endpoints
    if any(k in p for k in ["search", "query", "find", "filter"]):
        return "GET", ["q", "query", "search", "term", "keyword", "test"], False

    # Auth endpoints
    if any(k in p for k in ["login", "auth", "signin", "sign-in"]):
        return "POST", ["email", "username", "user", "password", "pass"], True

    # Generic REST/API
    if any(k in p for k in ["/rest", "/api"]):
        return "GET", ["q", "search", "id", "page", "limit", "test"], False

    # Fallback
    return "GET", ["q", "test", "input"], False


def build_targets_from_forms_index(
    forms_index: List[Dict[str, Any]],
    api_endpoints: Optional[List[str]] = None,
    openapi_targets: Optional[List[Dict[str, Any]]] = None,
    base_url: Optional[str] = None,
    query_urls: Optional[List[str]] = None,  # NEW
) -> List[Target]:
    targets: List[Target] = []
    seen = set()

    # 1) HTML forms (KEEP EXACT fields like before)
    for f in forms_index or []:
        method = (f.get("method") or "GET").upper().strip()
        url = f.get("action")
        if not url:
            continue

        params = list(f.get("fields", []) or [])
        hidden = f.get("hidden", {}) or {}
        source_page = f.get("source_page", "") or ""

        key = ("form", method, url, tuple(params), tuple(sorted(hidden.items())), False)
        if key in seen:
            continue
        seen.add(key)

        targets.append(Target(
            source_page=source_page,
            url=url,
            method=method,
            params=params,
            hidden=hidden,
            is_json=False
        ))

    # 2) OpenAPI targets (SAFE FIX: accept "params" or "fields")
    for t in openapi_targets or []:
        url = t.get("url")
        if not url:
            continue

        method = (t.get("method") or "GET").upper().strip()

        # Some code emits "fields" instead of "params". Support both.
        raw_params = t.get("params", None)
        if raw_params is None:
            raw_params = t.get("fields", [])

        params = list(raw_params or [])
        is_json = bool(t.get("is_json", False))
        source_page = t.get("source_page", "openapi") or "openapi"

        key = ("openapi", method, url, tuple(params), is_json)
        if key in seen:
            continue
        seen.add(key)

        targets.append(Target(
            source_page=source_page,
            url=url,
            method=method,
            params=params,
            hidden={},
            is_json=is_json
        ))

    # 3) SPA/API discovered endpoints (KEEP SPA FIX)
    for url in api_endpoints or []:
        if not url:
            continue

        if base_url and (not _same_origin(base_url, url)):
            continue

        path = urlparse(url).path or ""
        method, param_candidates, is_json = _guess_from_path(path)

        key = ("api", method, url, tuple(param_candidates), is_json)
        if key in seen:
            continue
        seen.add(key)

        targets.append(Target(
            source_page="api_discovery",
            url=url,
            method=method,
            params=param_candidates,
            hidden={},
            is_json=is_json
        ))

    # 4) NEW: Targets from crawled URLs that already contain query params
    # This is what classic apps like testfire rely on heavily.
    for u in query_urls or []:
        if not u:
            continue

        if base_url and (not _same_origin(base_url, u)):
            continue

        try:
            parsed = urlparse(u)
            qs = parse_qs(parsed.query)
            params = sorted(qs.keys())
            if not params:
                continue

            endpoint = parsed._replace(query="", fragment="").geturl()

            key = ("query", "GET", endpoint, tuple(params))
            if key in seen:
                continue
            seen.add(key)

            targets.append(Target(
                source_page="query_discovery",
                url=endpoint,
                method="GET",
                params=params,
                hidden={},
                is_json=False
            ))
        except Exception:
            continue

    return targets
