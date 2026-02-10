import random
import string
from typing import Dict, Any, List, Tuple

from core.http import HTTPClient
from core.targets import Target


def _rand_token(n: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _rand_marker() -> str:
    return "toasti_fm_" + _rand_token(10)


def _send_target(client: HTTPClient, t: Target, values: Dict[str, str]) -> Tuple[int, str, float, str]:
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
    FreeMarker probes:
      1) ${A*B} -> number
      2) ${"a" + "b"} -> ab
      3) ${"abc"?upper_case} -> ABC
    """
    probes: List[Dict[str, str]] = []

    a = random.randint(23, 97)
    b = random.randint(29, 89)
    expr1 = f"${{{a}*{b}}}"
    expected1 = str(a * b)
    probes.append({"type": "arith", "payload": f"{marker}{expr1}", "expr": expr1, "expected": expected1})

    s1 = _rand_token(6)
    s2 = _rand_token(6)
    expr2 = f'${{"{s1}" + "{s2}"}}'
    expected2 = f"{s1}{s2}"
    probes.append({"type": "concat", "payload": f"{marker}{expr2}", "expr": expr2, "expected": expected2})

    s3 = _rand_token(10)
    expr3 = f'${{"{s3}"?upper_case}}'
    expected3 = s3.upper()
    probes.append({"type": "upper_case", "payload": f"{marker}{expr3}", "expr": expr3, "expected": expected3})

    return probes


def freemarker_ssti_scan(client: HTTPClient, targets: List[Target]) -> List[Dict[str, Any]]:
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
            marker = _rand_marker()

            # reflection check
            try:
                r_status, r_body, _, r_url = _send_target(client, t, {p: marker})
            except Exception:
                continue

            reflected = (marker in (r_body or "")) and (marker not in (b_body or ""))

            probes = _make_three_unique_probes(marker)
            probe_results: List[Dict[str, Any]] = []

            pass_count = 0
            any_marker_present = False

            for pr in probes:
                payload = pr["payload"]
                expected = pr["expected"]
                expr = pr["expr"]
                ptype = pr["type"]

                try:
                    s_status, s_body, _, s_url = _send_target(client, t, {p: payload})
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

                marker_present = (marker in (s_body or "")) and (marker not in (b_body or ""))
                eval_present = _detect_eval(s_body or "", expected) and (expected not in (b_body or ""))

                any_marker_present = any_marker_present or marker_present
                if eval_present:
                    pass_count += 1

                probe_results.append({
                    "type": ptype,
                    "payload": payload,
                    "expr": expr,
                    "expected": expected,
                    "marker_present": marker_present,
                    "eval_present": eval_present,
                    "status": s_status,
                    "final_url": s_url,
                })

            confidence = 0
            if reflected:
                confidence += 30
            if any_marker_present:
                confidence += 20
            if pass_count >= 1:
                confidence += 60
            if pass_count >= 2:
                confidence += 10
            if pass_count == 3:
                confidence += 10
            confidence = min(confidence, 100)

            vulnerable = (pass_count >= 1) and (reflected or any_marker_present)

            results.append({
                "target": t.to_dict(),
                "param": p,
                "baseline": {"status": b_status, "final_url": b_url, "len": len(b_body or "")},
                "reflection_check": {"marker": marker, "reflected": reflected, "status": r_status, "final_url": r_url},
                "ssti_probes": probe_results,
                "verdict": {
                    "vulnerable": vulnerable,
                    "confidence": confidence,
                    "pass_count": pass_count,
                    "probe_count": len(probes),
                },
            })

    return results
