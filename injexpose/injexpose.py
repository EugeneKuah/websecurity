import getpass
import os
from urllib.parse import urlparse

from tools.sqlmap_scan import run_sqlmap
from tools.zap_scan import run_zap_scan
from tools.virustotal_scan import run_virustotal_url_scan
from tools.nikto_scan import run_nikto_scan
from tools.ollama_report import generate_llm_report


def derive_tool_targets(universal_url: str) -> dict:
    """
    User enters ONE universal URL. We derive tool-specific targets automatically.

    Example input:
      http://localhost:8081/vulnerabilities/sqli/

    Derived:
      - zap_target: page URL for crawling
      - zap_seed: parameterized URL to seed baseline for DVWA forms
      - sqlmap: parameterized URL (sqlmap needs a parameter)
      - nikto: site root (nikto scans the server)
      - virustotal: universal URL (VT uses the URL reputation)
    """
    u = (universal_url or "").strip()
    p = urlparse(u)
    base_site = f"{p.scheme}://{p.netloc}/" if p.scheme and p.netloc else u

    zap_target = u
    zap_seed = u
    sqlmap_url = u

    if "/vulnerabilities/sqli" in u:
        base_page = u.split("?")[0]
        if not base_page.endswith("/"):
            base_page += "/"
        zap_target = base_page
        zap_seed = base_page + "?id=1&Submit=Submit"
        sqlmap_url = zap_seed

    return {
        "zap_target": zap_target,
        "zap_seed": zap_seed,
        "sqlmap": sqlmap_url,
        "nikto": base_site,
        "virustotal": u,
    }


def _choose_level_preset() -> int:
    print("\nSQLMap Level Presets:")
    print("1) Level 1 (fast)")
    print("2) Level 2 (balanced)")
    print("3) Level 3 (deeper, slower)")
    pick = input("Choose 1/2/3: ").strip()
    if pick not in ("1", "2", "3"):
        print("Invalid. Defaulting to Level 1.")
        pick = "1"
    return int(pick)


def _cookie_flow_once() -> str | None:
    """
    Ask for login and return cookie string.
    - If login required: auto-login DVWA and return cookies.
    - Else: optional manual cookie paste.
    """
    need_login = input("Login required? (y/N): ").strip().lower() == "y"

    if not need_login:
        manual = input("Cookies (press Enter to skip): ").strip()
        return manual or None

    login_url = input("Login URL:\n> ").strip()
    username = input("Username:\n> ").strip()
    password = getpass.getpass("Password (hidden): ")

    try:
        from tools.dvwa_auth import dvwa_login_and_get_cookie
        cookie = dvwa_login_and_get_cookie(login_url, username, password, security_level="low")
        print("[Auth] Auto-login success ✅")
        print(f"[Auth] Cookie: {cookie}")
        return cookie
    except Exception as e:
        print("[Auth] Auto-login failed ❌")
        print(e)
        manual = input("Paste cookies manually (or press Enter to skip): ").strip()
        return manual or None


def _press_enter_to_continue() -> None:
    input("\nPress Enter to go back to the main menu...")


def _resolve_default_report_paths(base_dir: str) -> dict:
    """
    Fallback paths if user runs 'LLM Report' without doing scans in this session.
    """
    def _latest_file(folder: str, exts: tuple[str, ...]) -> str | None:
        """Return most recently modified file in folder matching extensions."""
        try:
            if not os.path.isdir(folder):
                return None
            candidates: list[str] = []
            for name in os.listdir(folder):
                p = os.path.join(folder, name)
                if os.path.isfile(p) and name.lower().endswith(exts):
                    candidates.append(p)
            if not candidates:
                return None
            candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            return candidates[0]
        except Exception:
            return None

    reports_dir = os.path.join(base_dir, "reports")

    # These tools overwrite stable filenames each run.
    sqlmap_out = os.path.join(reports_dir, "sqlmap", "sqlmap_output.txt")
    nikto_out = os.path.join(reports_dir, "nikto", "nikto_report.txt")
    vt_json = os.path.join(reports_dir, "virustotal", "virustotal_report.json")
    vt_summary = os.path.join(reports_dir, "virustotal", "virustotal_summary.txt")

    # ZAP uses timestamped files; pick the latest JSON.
    zap_json = _latest_file(os.path.join(reports_dir, "zap"), exts=(".json",))

    return {
        "sqlmap_out": sqlmap_out,
        "nikto_out": nikto_out,
        "vt_json": vt_json,
        "vt_summary": vt_summary,
        "zap_json": zap_json,
    }


def main():
    print("=== InjeXpose ===")

    # Base dir for relative report paths (so running from anywhere still works)
    base_dir = os.path.abspath(os.path.dirname(__file__))

    # Session state (persists until you exit)
    target = None
    derived = None
    cookies = None

    # Track outputs so LLM can use them (no auto-LLM after scans)
    sqlmap_out = None
    zap_html = None
    zap_json = None
    vt_json = None
    vt_summary = None
    nikto_out = None

    while True:
        # Ask target once (or when user changes it)
        if not target:
            target = input("Target URL (enter ONE URL; InjeXpose will adapt it for each tool):\n> ").strip()
            derived = derive_tool_targets(target)

        print("\n==============================")
        print(f"Target: {target}")
        print(f"Cookies: {'SET' if cookies else 'NOT SET'}")
        print("==============================\n")

        print("Main Menu:")
        print("1) SQLMap (SQL Injection)")
        print("2) OWASP ZAP (Spider + Active Scan)")
        print("3) Run BOTH (SQLMap + ZAP)")
        print("4) VirusTotal (URL Reputation Scan)")
        print("5) Nikto (Web Server Scanner)")
        print("6) Run ALL (SQLMap + ZAP + VirusTotal + Nikto)")
        print("7) Generate LLM Report (Ollama) from latest outputs")
        print("8) Login / Set Cookies")
        print("9) Change Target URL")
        print("0) Exit")

        choice = input("Enter choice: ").strip()

        if choice == "0":
            print("Bye!")
            break

        if choice == "9":
            target = None
            derived = None
            # Keep cookies by default (useful), but you can reset via option 8
            continue

        if choice == "8":
            cookies = _cookie_flow_once()
            _press_enter_to_continue()
            continue

        # Cookie prompt only if the scan likely needs it AND cookies not set
        if choice in ("1", "2", "3", "5", "6") and not cookies:
            print("\n[INFO] This scan usually works better when logged in (DVWA).")
            cookies = _cookie_flow_once()

        if choice == "1":
            preset = _choose_level_preset()
            sqlmap_out = run_sqlmap(derived["sqlmap"], cookies=cookies, level_preset=preset)
            print(f"[+] SQLMap done. Output saved to: {sqlmap_out}")
            _press_enter_to_continue()

        elif choice == "2":
            zap_html, zap_json = run_zap_scan(
                derived["zap_target"],
                cookies=cookies,
                seed_url=derived["zap_seed"]
            )
            print(f"[+] ZAP done. Reports saved to: {zap_html} and {zap_json}")
            _press_enter_to_continue()

        elif choice == "3":
            preset = _choose_level_preset()
            sqlmap_out = run_sqlmap(derived["sqlmap"], cookies=cookies, level_preset=preset)
            print(f"[+] SQLMap done. Output saved to: {sqlmap_out}")

            zap_html, zap_json = run_zap_scan(
                derived["zap_target"],
                cookies=cookies,
                seed_url=derived["zap_seed"]
            )
            print(f"[+] ZAP done. Reports saved to: {zap_html} and {zap_json}")
            _press_enter_to_continue()

        elif choice == "4":
            vt_json, vt_summary = run_virustotal_url_scan(derived["virustotal"])
            print(f"[+] VirusTotal done. Outputs saved to: {vt_json} and {vt_summary}")
            _press_enter_to_continue()

        elif choice == "5":
            nikto_out = run_nikto_scan(derived["nikto"], cookies=cookies)
            print(f"[+] Nikto done. Output saved to: {nikto_out}")
            _press_enter_to_continue()

        elif choice == "6":
            preset = _choose_level_preset()
            sqlmap_out = run_sqlmap(derived["sqlmap"], cookies=cookies, level_preset=preset)
            print(f"[+] SQLMap done. Output saved to: {sqlmap_out}")

            zap_html, zap_json = run_zap_scan(
                derived["zap_target"],
                cookies=cookies,
                seed_url=derived["zap_seed"]
            )
            print(f"[+] ZAP done. Reports saved to: {zap_html} and {zap_json}")

            vt_json, vt_summary = run_virustotal_url_scan(derived["virustotal"])
            print(f"[+] VirusTotal done. Outputs saved to: {vt_json} and {vt_summary}")

            nikto_out = run_nikto_scan(derived["nikto"], cookies=cookies)
            print(f"[+] Nikto done. Output saved to: {nikto_out}")
            _press_enter_to_continue()

        elif choice == "7":
            # Prefer latest outputs from this session. If missing, fallback to default paths.
            defaults = _resolve_default_report_paths(base_dir)

            use_sqlmap = sqlmap_out or defaults["sqlmap_out"]
            use_zap_json = zap_json or defaults["zap_json"]
            use_nikto = nikto_out or defaults["nikto_out"]
            use_vt_json = vt_json or defaults["vt_json"]
            use_vt_summary = vt_summary or defaults["vt_summary"]

            try:
                paths = generate_llm_report(
                    target=target,
                    cookies_used=bool(cookies),
                    sqlmap_out=use_sqlmap,
                    zap_json=use_zap_json,
                    nikto_out=use_nikto,
                    vt_json=use_vt_json,
                    vt_summary=use_vt_summary,
                )
                print(f"[LLM] Report saved: {paths['json']}")
                print(f"[LLM] Report saved: {paths['md']}")
            except Exception as e:
                print("[LLM] Failed to generate report ⚠️")
                print(e)

            _press_enter_to_continue()

        else:
            print("Invalid choice.")
            _press_enter_to_continue()


if __name__ == "__main__":
    main()
