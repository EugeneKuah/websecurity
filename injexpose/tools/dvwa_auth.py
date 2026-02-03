import re
import requests


class DvwaAuthError(Exception):
    pass


def _extract_user_token(html: str) -> str | None:
    if not html:
        return None

    patterns = [
        r'name=["\']user_token["\']\s+value=["\']([^"\']+)["\']',
        r'value=["\']([^"\']+)["\']\s+name=["\']user_token["\']',
        r'name=["\']user_token["\'][^>]*value=["\']([^"\']+)["\']',
    ]
    for pat in patterns:
        m = re.search(pat, html, flags=re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def dvwa_login_and_get_cookie(
    login_url: str,
    username: str,
    password: str,
    security_level: str = "low",
) -> str:
    """
    Jordan-style DVWA login:
      - GET login_url
      - extract user_token if present
      - POST login_url with username/password (+ optional user_token) + Login=Login
      - return cookie string: "PHPSESSID=...; security=low"
    """
    if not login_url.startswith(("http://", "https://")):
        raise DvwaAuthError("Login URL must start with http:// or https://")

    s = requests.Session()

    try:
        r1 = s.get(login_url, timeout=8, allow_redirects=True)
        r1.raise_for_status()
    except Exception as e:
        raise DvwaAuthError(f"Failed to load DVWA login page: {e}")

    token = _extract_user_token(r1.text)

    data = {"username": username, "password": password, "Login": "Login"}
    if token:
        data["user_token"] = token

    try:
        r2 = s.post(login_url, data=data, timeout=8, allow_redirects=True)
        r2.raise_for_status()
    except Exception as e:
        raise DvwaAuthError(f"Login POST failed: {e}")

    low = (r2.text or "").lower()
    if "login" in (r2.url or "").lower() and ("username" in low and "password" in low):
        raise DvwaAuthError("Login failed (still on login page). Check username/password or DVWA config.")

    jar = s.cookies.get_dict()
    if "PHPSESSID" not in jar:
        raise DvwaAuthError("Login did not yield PHPSESSID. DVWA session cookie missing.")

    jar["security"] = security_level
    return f"PHPSESSID={jar['PHPSESSID']}; security={jar['security']}"
