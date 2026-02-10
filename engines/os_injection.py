from __future__ import annotations

import os
import random
import string
from typing import Any, Dict, List, Tuple

from core.http import HTTPClient
from core.targets import Target


def _rand_token(n: int = 10) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _send_target(client: HTTPClient, t: Target, values: Dict[str, str]) -> Tuple[int, str, float, str]:
    """
    Target-aware sender:
      - GET/DELETE -> query params
      - POST/PUT/PATCH -> body (JSON if t.is_json else form)
      - Always includes hidden fields (CSRF, etc) when present.
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


def _make_osinj_probes(marker: str) -> List[Dict[str, str]]:
    """
    REAL (output-based) OS command injection probes (POSIX-style):

    We avoid the classic false-positive trap "echo TOKEN" where TOKEN is literally in the payload
    and can be reflected. Instead, we use arithmetic expansion so the *computed* result appears.

    Payload example:
      <marker>;echo TOASTI_OS_$((123*456))

    Expected output in response (only if a shell evaluated it):
      TOASTI_OS_56088

    Return exactly 3 probes (semicolon, pipe, &&) for neat reporting.
    """
    prefix = "TOASTI_OS_"

    a1, b1 = random.randint(101, 999), random.randint(101, 999)
    a2, b2 = random.randint(101, 999), random.randint(101, 999)
    a3, b3 = random.randint(2000, 9000), random.randint(10, 99)

    expr1 = f"$(({a1}*{b1}))"
    expr2 = f"$(({a2}+{b2}))"
    expr3 = f"$(({a3}-{b3}))"

    expected1 = f"{prefix}{a1*b1}"
    expected2 = f"{prefix}{a2+b2}"
    expected3 = f"{prefix}{a3-b3}"

    # Note: marker prefix helps see "reach", but expected output must not be in payload.
    return [
        {"name": "semicolon_arith", "payload": f"{marker};echo {prefix}{expr1}", "expected": expected1, "raw_expr": expr1},
        {"name": "pipe_arith",      "payload": f"{marker}|echo {prefix}{expr2}", "expected": expected2, "raw_expr": expr2},
        {"name": "andand_arith",    "payload": f"{marker}&&echo {prefix}{expr3}", "expected": expected3, "raw_expr": expr3},
    ]


def _pass_conditions(body: str, baseline_body: str, expected: str, raw_expr: str, payload: str) -> bool:
    """
    PASS only if:
      - expected computed output appears in response
      - expected was not in baseline
      - raw_expr is NOT present unchanged (helps reject pure reflection)
      - payload is NOT present verbatim (helps reject pure reflection)
    """
    body = body or ""
    baseline_body = baseline_body or ""

    if expected not in body:
        return False
    if expected in baseline_body:
        return False

    # If the expression shows up unchanged, it likely wasn't evaluated.
    if raw_expr in body:
        return False

    # If the whole payload comes back unchanged, it's likely reflection.
    if payload in body:
        return False

    return True


def os_injection_scan(client: HTTPClient, targets: List[Target]) -> List[Dict[str, Any]]:
    """
    OS command injection detection (output-based):

      For each (target, param):
        1) baseline request
        2) marker reflection check (helps confidence)
        3) 3 probes (semicolon / pipe / &&) using arithmetic expansion
        4) pass if computed output appears with anti-reflection guards
    """
    results: List[Dict[str, Any]] = []

    for t in targets:
        params = list(getattr(t, "params", []) or [])
        if not params:
            continue

        # baseline
        try:
            b_status, b_body, _, b_url = _send_target(client, t, {})
        except Exception:
            continue

        for p in params:
            marker = "toasti_osinj_" + _rand_token(10)

            # reflection/reach check
            try:
                r_status, r_body, _, r_url = _send_target(client, t, {p: marker})
            except Exception:
                continue

            reflected = (marker in (r_body or "")) and (marker not in (b_body or ""))

            probes = _make_osinj_probes(marker)
            probe_results: List[Dict[str, Any]] = []
            pass_count = 0
            any_marker_present = False

            for pr in probes:
                payload = pr["payload"]
                expected = pr["expected"]
                raw_expr = pr["raw_expr"]

                try:
                    s_status, s_body, _, s_url = _send_target(client, t, {p: payload})
                except Exception:
                    probe_results.append({
                        "name": pr["name"],
                        "payload": payload,
                        "expected": expected,
                        "pass": False,
                        "status": 0,
                        "final_url": t.url,
                        "error": "probe_request_failed",
                    })
                    continue

                marker_present = (marker in (s_body or "")) and (marker not in (b_body or ""))
                any_marker_present = any_marker_present or marker_present

                passed = _pass_conditions(
                    body=s_body or "",
                    baseline_body=b_body or "",
                    expected=expected,
                    raw_expr=raw_expr,
                    payload=payload,
                )

                if passed:
                    pass_count += 1

                probe_results.append({
                    "name": pr["name"],
                    "payload": payload,
                    "expected": expected,
                    "pass": passed,
                    "status": s_status,
                    "final_url": s_url,
                })

            # verdict (conservative): at least 1 probe passes AND some sign input reaches response
            vulnerable = (pass_count >= 1) and (reflected or any_marker_present)

            confidence = 0
            if reflected:
                confidence += 20
            if any_marker_present:
                confidence += 20
            if pass_count >= 1:
                confidence += 60
            if pass_count >= 2:
                confidence += 10
            if pass_count == 3:
                confidence += 10
            confidence = min(confidence, 100)

            results.append({
                "target": t.to_dict(),
                "param": p,
                "baseline": {"status": b_status, "final_url": b_url, "len": len(b_body or "")},
                "reflection_check": {"marker": marker, "reflected": reflected, "status": r_status, "final_url": r_url},
                "osinj_probes": probe_results,
                "verdict": {
                    "vulnerable": vulnerable,
                    "confidence": confidence,
                    "pass_count": pass_count,
                    "probe_count": len(probes),
                },
            })

    return results
