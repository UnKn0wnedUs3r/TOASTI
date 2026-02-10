from __future__ import annotations

import uuid
from typing import Any, Dict, List, Tuple, Optional

from core.http import HTTPClient
from core.targets import Target


def _dedupe_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Ensure uniqueness by (url, method, param).
    Keep first occurrence.
    """
    seen: set[Tuple[str, str, str]] = set()
    out: List[Dict[str, Any]] = []

    for r in results or []:
        t = r.get("target", {}) or {}
        url = str(t.get("url", "") or "")
        method = str(t.get("method", "") or "").upper()
        param = str(r.get("param", "") or "")
        key = (url, method, param)

        if key in seen:
            continue
        seen.add(key)
        out.append(r)

    return out


def reflection_probe(
    client: HTTPClient,
    targets: List[Target],
    include_all: bool = False,
) -> List[Dict[str, Any]]:
    """
    Reflection detection:
      - baseline request
      - inject unique marker into each parameter
      - reflected if marker appears in injected response but not baseline

    If include_all=False: return only reflected findings (like before).
    If include_all=True: return ALL probes (reflected YES/NO).
    """
    results: List[Dict[str, Any]] = []

    for t in targets:
        # Baseline request (no injected params)
        try:
            base_status, base_body, _, base_final_url = client.request(t.method, t.url)
        except Exception:
            # if include_all, still record that baseline failed for this target params
            for param in (t.params or []):
                results.append({
                    "target": {
                        "url": t.url,
                        "method": t.method,
                        "source_page": t.source_page,
                        "is_json": bool(t.is_json),
                    },
                    "param": param,
                    "reflected": False,
                    "error": "baseline_request_failed",
                })
            continue

        for param in (t.params or []):
            marker = f"TOASTI_REFLECT_{uuid.uuid4().hex[:10]}"
            status = 0
            body = ""
            final_url = t.url
            error: Optional[str] = None

            try:
                if t.method in ("GET", "DELETE"):
                    status, body, _, final_url = client.request(
                        t.method,
                        t.url,
                        params={param: marker},
                    )
                else:
                    if t.is_json:
                        status, body, _, final_url = client.request(
                            t.method,
                            t.url,
                            json={param: marker},
                        )
                    else:
                        data = {}
                        if t.hidden:
                            data.update(t.hidden)
                        data[param] = marker

                        status, body, _, final_url = client.request(
                            t.method,
                            t.url,
                            data=data,
                        )
            except Exception:
                error = "probe_request_failed"

            reflected = (marker in (body or "")) and (marker not in (base_body or "")) if not error else False

            entry: Dict[str, Any] = {
                "target": {
                    "url": t.url,
                    "method": t.method,
                    "final_url": final_url,
                    "baseline_final_url": base_final_url,
                    "baseline_status": base_status,
                    "status": status,
                    "is_json": bool(t.is_json),
                    "source_page": t.source_page,
                },
                "param": param,
                "marker": marker,
                "reflected": reflected,
            }

            if error:
                entry["error"] = error

            results.append(entry)

    results = _dedupe_results(results)

    if include_all:
        return results

    # default behavior: only return reflected ones
    return [r for r in results if r.get("reflected") is True]
