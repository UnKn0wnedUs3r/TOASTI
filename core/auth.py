# core/auth.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from core.http import HTTPClient


@dataclass
class AuthResult:
    ok: bool
    reason: str
    login_url: str
    final_url: str
    status: int
    evidence: Dict[str, str]


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def _pick_login_form(html: str) -> Optional[Tuple[str, str, Dict[str, str]]]:
    """
    Pick the most likely login form:
    - contains an <input type="password">
    Returns: (method, action, hidden_fields) or None
    """
    soup = BeautifulSoup(html, "lxml")
    forms = soup.find_all("form")
    if not forms:
        return None

    best = None
    best_score = -1

    for f in forms:
        inputs = f.find_all("input")

        has_password = any((i.get("type") or "").lower() == "password" for i in inputs)
        if not has_password:
            continue

        # score: password + presence of text/email input + number of inputs
        score = 10
        score += sum(1 for i in inputs if (i.get("type") or "text").lower() in ("text", "email"))
        score += len(inputs)

        method = (f.get("method") or "POST").upper().strip()
        action = f.get("action") or ""
        hidden: Dict[str, str] = {}
        for i in inputs:
            if (i.get("type") or "").lower() == "hidden":
                name = i.get("name")
                if name:
                    hidden[name] = i.get("value") or ""

        if score > best_score:
            best_score = score
            best = (method, action, hidden)

    return best


def _guess_user_field(html: str) -> Optional[str]:
    soup = BeautifulSoup(html, "lxml")
    # common names
    common = ["username", "user", "email", "login", "userid"]
    for name in common:
        if soup.find("input", attrs={"name": name}):
            return name

    # fall back: first text/email input
    for inp in soup.find_all("input"):
        t = (inp.get("type") or "text").lower()
        if t in ("text", "email"):
            n = inp.get("name")
            if n:
                return n
    return None


def _guess_pass_field(html: str) -> Optional[str]:
    soup = BeautifulSoup(html, "lxml")
    for inp in soup.find_all("input"):
        if (inp.get("type") or "").lower() == "password":
            n = inp.get("name")
            if n:
                return n
    # common fallback
    if soup.find("input", attrs={"name": "password"}):
        return "password"
    return None


def authenticate_form(
    client: HTTPClient,
    login_url: str,
    username: str,
    password: str,
    user_field: Optional[str] = None,
    pass_field: Optional[str] = None,
    check_url: Optional[str] = None,
    require_same_origin: bool = True,
) -> AuthResult:
    """
    Logs in using a classic HTML form:
      1) GET login page
      2) choose form containing password input
      3) POST creds + hidden fields
      4) optionally verify by fetching check_url

    This reuses client's requests.Session, so cookies persist automatically.
    """

    # Step 1: fetch login page
    try:
        r1 = client.session.get(
            login_url,
            timeout=client.timeout,
            verify=client.verify_tls,
            allow_redirects=True,
        )
    except Exception as e:
        return AuthResult(
            ok=False,
            reason=f"Failed to GET login page: {e}",
            login_url=login_url,
            final_url=login_url,
            status=0,
            evidence={},
        )

    login_html = r1.text
    final_login_url = str(r1.url)

    # Step 2: parse login form
    picked = _pick_login_form(login_html)
    if not picked:
        return AuthResult(
            ok=False,
            reason="No suitable login form found (no <form> with a password input).",
            login_url=login_url,
            final_url=final_login_url,
            status=r1.status_code,
            evidence={},
        )

    method, action, hidden = picked
    action_abs = urljoin(final_login_url, action) if action else final_login_url

    if require_same_origin and not _same_origin(final_login_url, action_abs):
        return AuthResult(
            ok=False,
            reason="Login form action points to a different origin (possible SSO/OAuth flow).",
            login_url=final_login_url,
            final_url=action_abs,
            status=r1.status_code,
            evidence={"action": action_abs},
        )

    # Step 2b: decide field names
    u_field = user_field or _guess_user_field(login_html)
    p_field = pass_field or _guess_pass_field(login_html)

    if not u_field or not p_field:
        return AuthResult(
            ok=False,
            reason="Could not determine username/password field names (use --user-field/--pass-field).",
            login_url=final_login_url,
            final_url=final_login_url,
            status=r1.status_code,
            evidence={"guessed_user_field": str(u_field), "guessed_pass_field": str(p_field)},
        )

    # Step 3: submit credentials (+ hidden fields such as CSRF)
    data = dict(hidden)
    data[u_field] = username
    data[p_field] = password

    try:
        if method == "GET":
            r2 = client.session.get(
                action_abs,
                params=data,
                timeout=client.timeout,
                verify=client.verify_tls,
                allow_redirects=True,
            )
        else:
            r2 = client.session.post(
                action_abs,
                data=data,
                timeout=client.timeout,
                verify=client.verify_tls,
                allow_redirects=True,
            )
    except Exception as e:
        return AuthResult(
            ok=False,
            reason=f"Failed to submit login form: {e}",
            login_url=final_login_url,
            final_url=action_abs,
            status=0,
            evidence={"action": action_abs},
        )

    final_after_login = str(r2.url)

    # Step 4: verify
    evidence = {
        "action": action_abs,
        "method": method,
        "user_field": u_field,
        "pass_field": p_field,
        "post_final_url": final_after_login,
        "post_status": str(r2.status_code),
        "redirected": "yes" if len(r2.history) > 0 else "no",
    }

    # Strong check: user-provided check_url
    if check_url:
        try:
            r3 = client.session.get(
                check_url,
                timeout=client.timeout,
                verify=client.verify_tls,
                allow_redirects=True,
            )
            evidence["check_url"] = str(r3.url)
            evidence["check_status"] = str(r3.status_code)

            if r3.status_code in (401, 403):
                return AuthResult(
                    ok=False,
                    reason="Login check URL still unauthorized (401/403).",
                    login_url=final_login_url,
                    final_url=str(r3.url),
                    status=r3.status_code,
                    evidence=evidence,
                )

            # If check page ends up back at login, treat as failure
            if urlparse(str(r3.url)).path == urlparse(final_login_url).path:
                return AuthResult(
                    ok=False,
                    reason="Login check URL redirected back to login page.",
                    login_url=final_login_url,
                    final_url=str(r3.url),
                    status=r3.status_code,
                    evidence=evidence,
                )

            return AuthResult(
                ok=True,
                reason="Login succeeded (verified by check URL).",
                login_url=final_login_url,
                final_url=str(r3.url),
                status=r3.status_code,
                evidence=evidence,
            )
        except Exception as e:
            return AuthResult(
                ok=False,
                reason=f"Login check failed: {e}",
                login_url=final_login_url,
                final_url=final_after_login,
                status=r2.status_code,
                evidence=evidence,
            )

    # Heuristic fallback (no check_url):
    # - If redirected away from login OR final URL differs from login page path
    login_path = urlparse(final_login_url).path
    after_path = urlparse(final_after_login).path

    # Many apps stay on /login with an error message when failing.
    likely_failed = (after_path == login_path) and ("invalid" in r2.text.lower() or "error" in r2.text.lower())
    if likely_failed:
        return AuthResult(
            ok=False,
            reason="Login likely failed (still on login page with error-like text).",
            login_url=final_login_url,
            final_url=final_after_login,
            status=r2.status_code,
            evidence=evidence,
        )

    # If we got redirected away, treat as success
    if len(r2.history) > 0 and after_path != login_path:
        return AuthResult(
            ok=True,
            reason="Login likely succeeded (redirected away from login page).",
            login_url=final_login_url,
            final_url=final_after_login,
            status=r2.status_code,
            evidence=evidence,
        )

    # Otherwise ambiguous: return ok but low confidence? We'll treat as failure to be safe.
    return AuthResult(
        ok=False,
        reason="Login result ambiguous (provide --login-check-url for reliable verification).",
        login_url=final_login_url,
        final_url=final_after_login,
        status=r2.status_code,
        evidence=evidence,
    )
