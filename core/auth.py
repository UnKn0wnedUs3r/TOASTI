from __future__ import annotations

import json
from typing import Optional, Dict, Any, Tuple, List
from urllib.parse import urljoin

from core.http import HTTPClient
from core.crawl import extract_forms


# Common username/email field names
USERNAME_CANDIDATES = [
    "username",
    "user",
    "login",
    "email",
    "mail",
    "account",
    "id",
    "name",
]


# Common password field names
PASSWORD_CANDIDATES = [
    "password",
    "pass",
    "pwd",
    "secret",
    "key",
]


# Common token names in JSON login
TOKEN_KEYS = [
    "token",
    "access_token",
    "jwt",
    "auth",
    "session",
]


# ============================================================
# Detect username field
# ============================================================

def _detect_user_field(form):

    for inp in form.get("inputs", []):

        name = inp.get("name", "").lower()

        for candidate in USERNAME_CANDIDATES:

            if candidate in name:

                return inp.get("name")

    return "username"


# ============================================================
# Detect password field
# ============================================================

def _detect_pass_field(form):

    for inp in form.get("inputs", []):

        name = inp.get("name", "").lower()

        for candidate in PASSWORD_CANDIDATES:

            if candidate in name:

                return inp.get("name")

    return "password"


# ============================================================
# JSON login attempt
# ============================================================

def _attempt_json_login(

    client: HTTPClient,
    login_url: str,
    username: str,
    password: str,

) -> Tuple[bool, Optional[str]]:


    print("[+] Trying JSON login...")

    payload = {

        "username": username,
        "email": username,
        "user": username,
        "password": password,

    }


    try:

        status, body, _, final_url = client.request(

            "POST",
            login_url,
            json=payload,

        )


        if not body:

            return False, None


        try:

            data = json.loads(body)

        except:

            return False, None


        for key in TOKEN_KEYS:

            if key in data:

                token = data[key]

                print(f"[+] Token detected: {key}")

                client.session.headers.update({

                    "Authorization": f"Bearer {token}"

                })

                return True, final_url


    except:

        pass


    return False, None


# ============================================================
# HTML login attempt (FIXED VERSION)
# ============================================================

def _attempt_html_login(

    client: HTTPClient,
    login_url: str,
    username: str,
    password: str,
    user_field: Optional[str],
    pass_field: Optional[str],

) -> Tuple[bool, Optional[str]]:


    print("[+] Trying HTML login...")


    status, body, _, final_url = client.request(

        "GET",
        login_url,

    )


    forms = extract_forms(final_url, body)


    if not forms:

        print("[!] No forms found")

        return False, None


    form = forms[0]


    action = form.get("action") or login_url

    action_url = urljoin(final_url, action)

    method = (form.get("method") or "POST").upper()


    hidden: Dict[str, Any] = {}

    for inp in form.get("inputs", []):

        if inp.get("type") == "hidden":

            hidden[inp.get("name")] = inp.get("value", "")


    if not user_field:

        user_field = _detect_user_field(form)

    if not pass_field:

        pass_field = _detect_pass_field(form)


    payload = {}

    payload.update(hidden)

    payload[user_field] = username

    payload[pass_field] = password


    print(f"[+] Using fields: {user_field} / {pass_field}")


    status, body, _, final_url = client.request(

        method,
        action_url,
        data=payload,

    )


    # ============================================================
    # CRITICAL FIX: VERIFY LOGIN SUCCESS
    # ============================================================


    status, verify_body, _, verify_url = client.request(

        "GET",
        final_url,

    )


    login_indicators = [

        "logout",
        "dashboard",
        "welcome",

    ]


    for word in login_indicators:

        if word in verify_body.lower():

            print("[+] Login verified")

            return True, verify_url


    print("[!] Login verification failed")

    return False, None


# ============================================================
# MAIN LOGIN FUNCTION
# ============================================================

def perform_login(

    client: HTTPClient,
    login_url: str,
    username: str,
    password: str,
    user_field: Optional[str] = None,
    pass_field: Optional[str] = None,
    **kwargs,

) -> Tuple[bool, List[str]]:


    print("[+] Attempting login...")


    success, landing = _attempt_json_login(

        client,
        login_url,
        username,
        password,

    )


    if success:

        print("[+] Logged in via JSON")

        return True, [landing]


    success, landing = _attempt_html_login(

        client,
        login_url,
        username,
        password,
        user_field,
        pass_field,

    )


    if success:

        print("[+] Logged in via HTML")

        return True, [landing]


    print("[!] Login failed")

    return False, []
