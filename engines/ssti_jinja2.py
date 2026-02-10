import random
import string
from typing import Dict, Any, List, Tuple

from core.http import HTTPClient
from core.targets import Target


def _rand_token(n: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _rand_marker() -> str:
    return "toasti_" + _rand_token(10)


def _send_target(client: HTTPClient, t: Target, values: Dict[str, str]) -> Tuple[int, str, float, str]:
    """
    Sends requests correctly for:
    - GET/DELETE -> params
    - POST/PUT/PATCH -> body
      - JSON if t.is_json
      - form data otherwise
    """
    method = (t.method or "GET").upper().strip()

    payload: Dict[str, Any] = {}
    payload.update(t.hidden or {})
    payload.update(values or {})

    if method in ("GET", "DELETE"):
        return client.request(method, t.url, params=payload)

    if getattr(t, "is_json", False):
        return client.request(method, t.url, json=payload)

    return client.request(method, t.url, data=payload)


def _detect_eval(body: str, expected: str) -> bool:
    return expected in (body or "")


def _make_three_unique_probes(marker: str) -> List[Dict[str, str]]:
    """
    Build 3 *different* Jinja2 expression types with unique expected outputs:
      1) random arithmetic: {{A*B}} -> number
      2) string concat: {{'x' ~ 'y'}} -> xy
      3) filter transform: {{'token'|upper}} -> TOKEN
    Each payload is prefixed with marker to help anchor detection.
    """
    probes: List[Dict[str, str]] = []

    # Probe 1: arithmetic
    a = random.randint(23, 97)
    b = random.randint(29, 89)
    expr1 = f"{{{{{a}*{b}}}}}"
    expected1 = str(a * b)
    payload1 = f"{marker}{expr1}"
    probes.append({
        "type": "arith",
        "payload": payload1,
        "expr": expr1,
        "expected": expected1,
    })

    # Probe 2: string concatenation
    s1 = _rand_token(6)
    s2 = _rand_token(6)
    # Jinja2 uses ~ for string concat
    expr2 = f"{{{{'{s1}' ~ '{s2}'}}}}"
    expected2 = f"{s1}{s2}"
    payload2 = f"{marker}{expr2}"
    probes.append({
        "type": "concat",
        "payload": payload2,
        "expr": expr2,
        "expected": expected2,
    })

    # Probe 3: filter transform (upper)
    s3 = _rand_token(10)  # lowercase+digits; upper() changes letters
    expr3 = f"{{{{'{s3}'|upper}}}}"
    expected3 = s3.upper()
    payload3 = f"{marker}{expr3}"
    probes.append({
        "type": "filter_upper",
        "payload": payload3,
        "expr": expr3,
        "expected": expected3,
    })

    return probes


def jinja2_ssti_scan(client: HTTPClient, targets: List[Target]) -> List[Dict[str, Any]]:
    """
    For each (target, param):
      1) Baseline request
      2) Marker reflection check
      3) Run 3 unique SSTI probes (arith / concat / filter)
      4) For each probe, check:
         - marker_present (helps confidence)
         - eval_present (expected appears and was not in baseline)
      5) Verdict: vulnerable if ANY probe evaluates AND (reflected OR marker_present)
    """
    results: List[Dict[str, Any]] = []

    for t in targets:
        params = list(getattr(t, "params", []) or [])
        if not params:
            continue

        # baseline (no injected marker)
        try:
            b_status, b_body, _, b_url = _send_target(client, t, {})
        except Exception:
            continue

        for p in params:
            marker = _rand_marker()

            # Step 1: marker reflection check
            try:
                r_status, r_body, _, r_url = _send_target(client, t, {p: marker})
            except Exception:
                continue

            reflected = (marker in (r_body or "")) and (marker not in (b_body or ""))

            # Step 2: run 3 unique probes
            probes = _make_three_unique_probes(marker)
            probe_results: List[Dict[str, Any]] = []

            any_marker_present = False
            eval_count = 0

            for pr in probes:
                payload = pr["payload"]
                expected = pr["expected"]
                expr = pr["expr"]
                ptype = pr["type"]

                try:
                    e_status, e_body, _, e_url = _send_target(client, t, {p: payload})
                except Exception:
                    probe_results.append({
                        "type": ptype,
                        "payload": payload,
                        "expr": expr,
                        "expected": expected,
                        "marker_present": False,
                        "eval_present": False,
                        "status": 0,
                        "final_url": t.url,
                        "error": "probe_request_failed",
                    })
                    continue

                marker_present = (marker in (e_body or "")) and (marker not in (b_body or ""))
                eval_present = _detect_eval(e_body or "", expected) and (expected not in (b_body or ""))

                any_marker_present = any_marker_present or marker_present
                if eval_present:
                    eval_count += 1

                probe_results.append({
                    "type": ptype,
                    "payload": payload,
                    "expr": expr,
                    "expected": expected,
                    "marker_present": marker_present,
                    "eval_present": eval_present,
                    "status": e_status,
                    "final_url": e_url,
                })

            # Confidence scoring
            confidence = 0
            if reflected:
                confidence += 30
            if any_marker_present:
                confidence += 20
            if eval_count >= 1:
                confidence += 60
            if eval_count >= 2:
                confidence += 10
            if eval_count == 3:
                confidence += 10
            confidence = min(confidence, 100)

            vulnerable = (eval_count >= 1) and (reflected or any_marker_present)

            results.append({
                "target": t.to_dict(),
                "param": p,
                "baseline": {"status": b_status, "final_url": b_url, "len": len(b_body or "")},
                "reflection_check": {"marker": marker, "reflected": reflected, "status": r_status, "final_url": r_url},
                "ssti_probes": probe_results,  # list of 3 probes
                "verdict": {
                    "vulnerable": vulnerable,
                    "confidence": confidence,
                    "eval_count": eval_count,
                },
            })

    return results
