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

    method = (t.method or "GET").upper().strip()

    payload: Dict[str, Any] = {}
    payload.update(t.hidden or {})
    payload.update(values or {})

    if method in ("GET", "DELETE"):
        return client.request(method, t.url, params=payload)

    if getattr(t, "is_json", False):
        return client.request(method, t.url, json=payload)

    return client.request(method, t.url, data=payload)


# FIXED: better eval detection
def _detect_eval(body: str, expected: str, baseline: str) -> bool:

    if not body:
        return False

    # expected must appear in response
    if expected not in body:
        return False

    # but must not appear in baseline
    if baseline and expected in baseline:
        return False

    return True


def _make_three_unique_probes(marker: str) -> List[Dict[str, str]]:

    probes: List[Dict[str, str]] = []

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

    s1 = _rand_token(6)
    s2 = _rand_token(6)

    expr2 = f"{{{{'{s1}' ~ '{s2}'}}}}"
    expected2 = f"{s1}{s2}"
    payload2 = f"{marker}{expr2}"

    probes.append({
        "type": "concat",
        "payload": payload2,
        "expr": expr2,
        "expected": expected2,
    })

    s3 = _rand_token(10)

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

    results: List[Dict[str, Any]] = []

    for t in targets:

        params = list(getattr(t, "params", []) or [])

        if not params:
            continue

        try:
            b_status, b_body, _, b_url = _send_target(client, t, {})
        except Exception:
            continue

        for p in params:

            marker = _rand_marker()

            try:
                r_status, r_body, _, r_url = _send_target(client, t, {p: marker})
            except Exception:
                continue

            reflected = marker in (r_body or "")

            probes = _make_three_unique_probes(marker)

            probe_results = []

            eval_count = 0

            for pr in probes:

                payload = pr["payload"]
                expected = pr["expected"]

                try:

                    e_status, e_body, _, e_url = _send_target(client, t, {p: payload})

                except Exception:

                    continue

                eval_present = _detect_eval(

                    e_body,
                    expected,
                    b_body,

                )

                if eval_present:
                    eval_count += 1

                probe_results.append({

                    "payload": payload,
                    "expected": expected,
                    "eval_present": eval_present,
                    "status": e_status,
                    "final_url": e_url,

                })

            confidence = min(eval_count * 40, 100)

            # FIXED VULNERABILITY LOGIC
            vulnerable = eval_count >= 1

            results.append({

                "target": t.to_dict(),

                "param": p,

                "ssti_probes": probe_results,

                "verdict": {

                    "vulnerable": vulnerable,

                    "confidence": confidence,

                    "eval_count": eval_count,

                },

            })

    return results
