import os
import re
import subprocess
import requests


def get_csrf_token(session: requests.Session, login_url: str) -> str:
    """
    Get CSRF token from DVWA login page.
    Works without BeautifulSoup using regex.
    """
    r = session.get(login_url, timeout=15)

    # Flexible regex to match token in HTML
    match = re.search(r'name=["\']user_token["\']\s+value=["\']([^"\']+)["\']', r.text)

    if not match:
        # Fallback: sometimes token appears in JS
        match = re.search(r'user_token=([a-zA-Z0-9]+)', r.text)

    return match.group(1) if match else ""


def login_and_get_cookies(login_url: str, username: str, password: str) -> str:
    """
    Login to DVWA and return cookie string.
    """
    session = requests.Session()

    token = get_csrf_token(session, login_url)

    if not token:
        print("[!] Could not find CSRF token (attempts failed).")
        return ""

    payload = {
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": token,
    }

    response = session.post(login_url, data=payload, timeout=15)

    if "Login" in response.text and "user_token" in response.text:
        print("[!] Login failed. Check username/password.")
        return ""

    cookies = session.cookies.get_dict()
    return "; ".join([f"{k}={v}" for k, v in cookies.items()])


def run_sqlmap(target: str, cookies: str | None = None) -> str:
    """
    Run sqlmap against a target URL and return stdout+stderr text.
    """
    command = [
        "sqlmap",
        "-u", target,
        "--batch",
        "--level", "5",
        "--risk", "3",
        "--random-agent",
    ]

    if cookies:
        command.extend(["--cookie", cookies])

    print("[*] Running SQLmap...")
    print(f"[*] Command: {' '.join(command)}")

    result = subprocess.run(command, capture_output=True, text=True)

    output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
    return output


def main():
    target = input("Enter target URL:\n> ").strip()

    if not target:
        print("[!] No URL provided. Exiting.")
        return

    login_required = input("Does this target require login? (y/N): ").strip().lower() == "y"

    cookies = ""
    if login_required:
        login_url = input("Login URL:\n> ").strip()
        username = input("Username:\n> ").strip()
        password = input("Password:\n> ").strip()

        print("[*] Attempting login to retrieve session cookies...")
        cookies = login_and_get_cookies(login_url, username, password)

        if not cookies:
            print("[!] Failed to login. Exiting.")
            return

        print(f"[*] Using cookies: {cookies}")

    output = run_sqlmap(target, cookies if cookies else None)

    os.makedirs("reports", exist_ok=True)
    out_path = os.path.join("reports", "sqlmap_output.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(output)

    print(f"[+] Scan complete. Output saved to {out_path}")


if __name__ == "__main__":
    main()

