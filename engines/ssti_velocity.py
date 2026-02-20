import random
import string
from typing import Dict, Any, List, Tuple

from core.http import HTTPClient
from core.targets import Target


def _rand_token(n: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _rand_marker() -> str:
    return "toasti_vel_" + _rand_token(10)


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


def _detect_eval(body: str, expected: str, baseline: str) -> bool:
    """
    expected must appear in response, but NOT in baseline.
    """
    if not body:
        return False
    if expected not in body:
        return False
    if baseline and expected in baseline:
        return False
    return True


def _looks_like_login(final_url: str, body: str) -> bool:
    """
    If we got redirected to a login page mid-scan, SSTI checks will false-negative.
    """
    u = (final_url or "").lower()
    b = (body or "").lower()
    if "/login" in u:
        return True
    if "<form" in b and ("password" in b and ("login" in b or "sign in" in b or "signin" in b)):
        return True
    return False


def _make_three_unique_probes(marker: str) -> List[Dict[str, str]]:
    """
    Velocity probes (safe, non-RCE) designed to keep '#set' at the start of payload.
    Also prints the marker in output so marker_present works reliably.

      1) #set($x=A*B)<marker>$x -> <marker><number>
      2) #set($s="a" + "b")<marker>$s -> <marker>ab
      3) #set($t="abc")<marker>$t.toUpperCase() -> <marker>ABC
    """
    probes: List[Dict[str, str]] = []

    # Probe 1: arithmetic
    a = random.randint(23, 97)
    b = random.randint(29, 89)
    expected1 = str(a * b)
    expr1 = f"#set($x={a}*{b}){marker}$x"
    probes.append({
        "type": "arith_set",
        "payload": expr1,
        "expr": expr1,
        "expected": expected1,
    })

    # Probe 2: concat
    s1 = _rand_token(6)
    s2 = _rand_token(6)
    expected2 = f"{s1}{s2}"
    # Velocity usually supports + for concat on strings
    expr2 = f'#set($s="{s1}" + "{s2}"){marker}$s'
    probes.append({
        "type": "concat_set",
        "payload": expr2,
        "expr": expr2,
        "expected": expected2,
    })

    # Probe 3: upper
    s3 = _rand_token(10)
    expected3 = s3.upper()
    expr3 = f'#set($t="{s3}"){marker}$t.toUpperCase()'
    probes.append({
        "type": "upper_method",
        "payload": expr3,
        "expr": expr3,
        "expected": expected3,
    })

    return probes


def velocity_ssti_scan(client: HTTPClient, targets: List[Target]) -> List[Dict[str, Any]]:
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

            # reflection check (optional confidence signal)
            try:
                r_status, r_body, _, r_url = _send_target(client, t, {p: marker})
            except Exception:
                continue

            # if we got sent to login, stop false negatives
            if _looks_like_login(r_url, r_body):
                results.append({
                    "target": t.to_dict(),
                    "param": p,
                    "baseline": {"status": b_status, "final_url": b_url, "len": len(b_body or "")},
                    "reflection_check": {"marker": marker, "reflected": False, "status": r_status, "final_url": r_url},
                    "ssti_probes": [],
                    "verdict": {"vulnerable": False, "confidence": 0, "pass_count": 0, "probe_count": 0},
                    "error": "auth_redirect_during_reflection_check",
                })
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

                # Detect auth redirect mid-scan
                if _looks_like_login(s_url, s_body):
                    probe_results.append({
                        "type": ptype,
                        "payload": payload,
                        "expr": expr,
                        "expected": expected,
                        "marker_present": False,
                        "eval_present": False,
                        "status": s_status,
                        "final_url": s_url,
                        "error": "auth_redirect_during_probe",
                    })
                    continue

                marker_present = (marker in (s_body or "")) and (marker not in (b_body or ""))
                eval_present = _detect_eval(s_body or "", expected, b_body or "")

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

            # Confidence scoring
            confidence = 0
            if reflected:
                confidence += 20
            if any_marker_present:
                confidence += 30
            if pass_count >= 1:
                confidence += 60
            if pass_count >= 2:
                confidence += 10
            if pass_count == 3:
                confidence += 10
            confidence = min(confidence, 100)

            # IMPORTANT FIX:
            # Velocity pages often don't "reflect" raw input, but still evaluate.
            # If evaluation happened, it's vulnerable even if reflection/marker_present isn't strong.
            vulnerable = (pass_count >= 1)

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
