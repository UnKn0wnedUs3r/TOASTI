from bs4 import BeautifulSoup
from urllib.parse import urljoin
from typing import List, Dict, Any


def extract_forms(page_url: str, html: str) -> List[Dict[str, Any]]:
    """
    Extract <form> elements with:
      - method
      - action (absolute)
      - fields (non-hidden input names + textarea/select names)
      - hidden (hidden input name->value)
    """
    soup = BeautifulSoup(html, "lxml")
    results: List[Dict[str, Any]] = []

    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        method = (form.get("method") or "GET").upper().strip()
        action_abs = urljoin(page_url, action)

        fields: List[str] = []
        hidden: Dict[str, str] = {}

        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name:
                continue

            itype = (inp.get("type") or "text").lower()
            value = inp.get("value") or ""

            if itype in {"submit", "button", "image"}:
                continue

            if itype == "hidden":
                hidden[name] = value
                continue

            fields.append(name)

        for ta in form.find_all("textarea"):
            name = ta.get("name")
            if name:
                fields.append(name)

        for sel in form.find_all("select"):
            name = sel.get("name")
            if name:
                fields.append(name)

        results.append({
            "method": method,
            "action": action_abs,
            "fields": sorted(set(fields)),
            "hidden": hidden,
        })

    return results
