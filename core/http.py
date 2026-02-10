import time
import warnings
import requests
from typing import Dict, Optional, Tuple, Any

try:
    from urllib3.exceptions import InsecureRequestWarning
except Exception:
    InsecureRequestWarning = None  # type: ignore


class HTTPClient:
    """
    HTTP client with:
      - requests.Session cookie persistence
      - supports GET/POST/PUT/PATCH/DELETE/etc
      - supports params, data, json
      - optional TLS verify
      - optional suppression of InsecureRequestWarning when verify=False
    """

    def __init__(
        self,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: int = 15,
        verify_tls: bool = True,
        suppress_insecure_warnings: bool = True,
    ):
        self.session = requests.Session()
        self.timeout = timeout
        self.verify_tls = verify_tls

        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)

        # Hide the noisy warning when user intentionally disables TLS verification
        if suppress_insecure_warnings and (not verify_tls) and InsecureRequestWarning is not None:
            warnings.simplefilter("ignore", InsecureRequestWarning)

    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str, float, str]:
        method = method.upper().strip()
        start = time.perf_counter()

        r = self.session.request(
            method=method,
            url=url,
            params=params,
            data=data,
            json=json,
            headers=headers,
            timeout=self.timeout,
            verify=self.verify_tls,
            allow_redirects=True,
        )

        elapsed = time.perf_counter() - start
        return r.status_code, r.text, elapsed, str(r.url)
