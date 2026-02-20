import random
import re
import string
from typing import Dict, Any, List, Tuple, Optional

from core.http import HTTPClient
from core.targets import Target


# ============================================================
# Helpers
# ============================================================

def _rand_token(n: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _rand_marker() -> str:
    return "toasti_os_" + _rand_token(10)


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


_PRE_RE = re.compile(r"<pre[^>]*>(.*?)</pre>", re.IGNORECASE | re.DOTALL)


def _extract_pre_text(html: str) -> Optional[str]:
    """
    If the page uses engine.html style output, command output is inside <pre>...</pre>.
    We ONLY trust this region to avoid reflection false positives elsewhere in the HTML.
    """
    if not html:
        return None
    m = _PRE_RE.search(html)
    if not m:
        return None
    # Keep it simple: return raw inner text (may include HTML entities, that's fine for marker matching)
    return m.group(1)


def _baseline_region(b_body: str) -> str:
    """
    Region used for baseline comparison. Prefer <pre> if present, else whole body.
    """
    pre = _extract_pre_text(b_body or "")
    return pre if pre is not None else (b_body or "")


def _response_region(s_body: str) -> str:
    """
    Region used for detection. Prefer <pre> if present, else whole body.
    """
    pre = _extract_pre_text(s_body or "")
    return pre if pre is not None else (s_body or "")


def _detect_exec(region: str, baseline_region: str, marker: str, payload: str) -> bool:
    """
    Robust execution detection to avoid reflection false positives.

    We require:
      - marker appears in the output region
      - marker did NOT appear in baseline region
      - the literal injection string ('echo <marker>') does NOT appear in output region
      - the full payload does NOT appear verbatim in output region

    Why:
      Reflection often prints the payload itself. Real command output prints only the marker.
    """
    if not region:
        return False

    if marker not in region:
        return False

    if baseline_region and marker in baseline_region:
        return False

    # If output region contains the literal injected command, it's likely just reflection / debug
    # (In real command output, you'll see the marker, not "echo toasti_os_xxx")
    if f"echo {marker}".lower() in region.lower():
        return False

    # If the output region contains the exact payload, also likely reflection
    if payload and payload in region:
        return False

    return True


# ============================================================
# Cross-platform probes (safe, marker-based)
# ============================================================

def _make_probes(marker: str) -> List[Dict[str, str]]:
    """
    We always include both Windows and Linux-style separators.
    If ANY works, we flag vulnerable and record which family succeeded.

    We use echo because it's common on Windows and Linux, and it produces deterministic output.
    """
    base = "127.0.0.1"

    probes: List[Dict[str, str]] = []

    # Windows-style chaining
    probes.append({
        "type": "win_amp",
        "platform": "windows",
        "payload": f"{base} & echo {marker}",
        "expected_marker": marker,
    })
    probes.append({
        "type": "win_and",
        "platform": "windows",
        "payload": f"{base} && echo {marker}",
        "expected_marker": marker,
    })
    probes.append({
        "type": "win_pipe",
        "platform": "windows",
        "payload": f"{base} | echo {marker}",
        "expected_marker": marker,
    })

    # Linux/macOS-style chaining
    probes.append({
        "type": "lin_semicolon",
        "platform": "linux",
        "payload": f"{base}; echo {marker}",
        "expected_marker": marker,
    })
    probes.append({
        "type": "lin_and",
        "platform": "linux",
        "payload": f"{base} && echo {marker}",
        "expected_marker": marker,
    })
    probes.append({
        "type": "lin_pipe",
        "platform": "linux",
        "payload": f"{base} | echo {marker}",
        "expected_marker": marker,
    })

    return probes


# ============================================================
# Main scan
# ============================================================

def os_injection_scan(client: HTTPClient, targets: List[Target]) -> List[Dict[str, Any]]:
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

        baseline_region = _baseline_region(b_body or "")

        for p in params:
            marker = _rand_marker()
            probes = _make_probes(marker)

            probe_results: List[Dict[str, Any]] = []
            pass_count = 0
            detected_platforms = set()

            for pr in probes:
                payload = pr["payload"]
                platform = pr["platform"]
                ptype = pr["type"]

                try:
                    s_status, s_body, _, s_url = _send_target(client, t, {p: payload})
                except Exception:
                    probe_results.append({
                        "type": ptype,
                        "platform": platform,
                        "payload": payload,
                        "marker_present": False,
                        "exec_present": False,
                        "status": 0,
                        "final_url": t.url,
                        "error": "probe_request_failed",
                    })
                    continue

                region = _response_region(s_body or "")

                exec_present = _detect_exec(
                    region=region,
                    baseline_region=baseline_region,
                    marker=marker,
                    payload=payload
                )

                if exec_present:
                    pass_count += 1
                    detected_platforms.add(platform)

                probe_results.append({
                    "type": ptype,
                    "platform": platform,
                    "payload": payload,
                    "marker_present": (marker in region),
                    "exec_present": exec_present,
                    "status": s_status,
                    "final_url": s_url,
                })

            # Confidence scoring (simple, stable)
            confidence = 0
            if pass_count >= 1:
                confidence = 80
            if pass_count >= 2:
                confidence = 90
            if pass_count >= 3:
                confidence = 100

            vulnerable = (pass_count >= 1)

            results.append({
                "target": t.to_dict(),
                "param": p,
                "baseline": {"status": b_status, "final_url": b_url, "len": len(b_body or "")},
                "os_probes": probe_results,
                "verdict": {
                    "vulnerable": vulnerable,
                    "confidence": confidence,
                    "pass_count": pass_count,
                    "probe_count": len(probes),
                    "detected_platforms": list(detected_platforms),
                },
            })

    return results
