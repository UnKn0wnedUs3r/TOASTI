from typing import Any, Dict, List
from urllib.parse import urljoin


def _safe_get(d: Dict[str, Any], *keys, default=None):
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def parse_openapi_targets(base_url: str, spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Convert an OpenAPI/Swagger spec dict into Toasti target dicts.

    Output item:
      {
        "source_page": base_url,
        "url": full_url,
        "method": "GET|POST|PUT|DELETE|PATCH",
        "fields": [param names],
        "hidden": {},
        "is_json": bool
      }

    Supports:
      - OpenAPI v2 (Swagger 2.0)
      - OpenAPI v3
    """
    targets: List[Dict[str, Any]] = []

    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return targets

    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue

        for method, op in ops.items():
            m = str(method).upper()
            if m not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                continue
            if not isinstance(op, dict):
                continue

            full_url = urljoin(base_url, path)

            fields: List[str] = []
            is_json = False

            # --- Parameters (v2 & v3) ---
            params = op.get("parameters") or []
            if isinstance(params, list):
                for p in params:
                    if not isinstance(p, dict):
                        continue
                    name = p.get("name")
                    loc = p.get("in")
                    if isinstance(name, str) and name.strip():
                        # Skip path params because you can't inject them without templating the URL
                        if loc == "path":
                            continue
                        fields.append(name)

                    # v2: "in": "body" implies JSON/body
                    if loc == "body":
                        is_json = True

            # --- requestBody (v3) ---
            if "requestBody" in op:
                is_json = True
                rb = op.get("requestBody") or {}
                content = _safe_get(rb, "content", default={})
                if isinstance(content, dict):
                    # keep is_json True if any JSON-ish content type exists
                    if any(ct in content for ct in ("application/json", "application/*+json")):
                        is_json = True

            # If no params defined, keep a small fallback set
            if not fields:
                fields = ["q", "search", "name", "input"]

            # Deduplicate & stable order
            fields = sorted(set(fields))

            # Only treat as JSON if the method is body-capable
            json_for_method = is_json and m in ("POST", "PUT", "PATCH")

            targets.append({
                "source_page": base_url,
                "url": full_url,
                "method": m,
                "fields": fields,
                "hidden": {},
                "is_json": json_for_method,
            })

    return targets
