import getpass

from tools.sqlmap_scan import run_sqlmap
from tools.zap_scan import run_zap_scan
from tools.virustotal_scan import run_virustotal_url_scan
from tools.nikto_scan import run_nikto_scan
from tools.ollama_report import generate_llm_report


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


def _choose_scan_type() -> str:
    print("\nSQLMap Scan Type:")
    print("1) URL only (scan the URL directly)")
    print("2) Forms (crawl and scan forms)")
    pick = input("Choose 1/2: ").strip()
    if pick == "1":
        return "url"
    elif pick == "2":
        return "forms"
    else:
        print("Invalid. Defaulting to Forms.")
        return "forms"


def _cookie_flow_once() -> str | None:
    """
    Jordan-style:
      - Ask login required? y/n
      - If yes: ask login URL + username + password, auto-login DVWA and return cookie string
      - If no: optional manual cookie paste
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


def _maybe_run_llm_report(
    *,
    target: str,
    cookies: str | None,
    sqlmap_out: str | None,
    zap_json: str | None,
    nikto_out: str | None,
    vt_json: str | None,
    vt_summary: str | None
) -> None:
    """
    Runs LLM report if OPENAI_API_KEY exists.
    This does NOT affect your scans; it's just analysis/reporting.
    """
    import os
    try:
        paths = generate_llm_report(
            target=target,
            cookies_used=bool(cookies),
            sqlmap_out=sqlmap_out,
            zap_json=zap_json,
            nikto_out=nikto_out,
            vt_json=vt_json,
            vt_summary=vt_summary,
        )
        print(f"[LLM] Report saved: {paths['json']}")
        print(f"[LLM] Report saved: {paths['md']}")
    except Exception as e:
        print("[LLM] Failed to generate report ⚠️")
        print(e)


def main():
    print("=== InjeXpose ===")
    target = input("Target URL:\n> ").strip()

    print("\nChoose tool:")
    print("1) SQLMap (SQL Injection)")
    print("2) OWASP ZAP (Spider + Active Scan)")
    print("3) Run BOTH")
    print("4) VirusTotal (URL Reputation Scan)")
    print("5) Nikto (Web Server Scanner)")
    print("6) Run ALL (SQLMap + ZAP + VirusTotal + Nikto)")
    print("7) LLM Report (analyze existing outputs)")
    choice = input("Enter 1/2/3/4/5/6/7: ").strip()

    cookies = None
    preset = 1
    scan_type = "forms"

    # Track outputs so we can feed them into the LLM report
    sqlmap_out = None
    zap_html = None
    zap_json = None
    vt_json = None
    vt_summary = None
    nikto_out = None

    # If any tool that benefits from cookies is selected, do auth once
    if choice in ("1", "2", "3", "5", "6"):
        cookies = _cookie_flow_once()

    if choice in ("1", "3", "6"):
        preset = _choose_level_preset()
        scan_type = _choose_scan_type()

    if choice == "1":
        sqlmap_out = run_sqlmap(target, cookies=cookies, level_preset=preset, scan_type=scan_type)
        print(f"[+] SQLMap done. Output saved to: {sqlmap_out}")
        _maybe_run_llm_report(
            target=target, cookies=cookies,
            sqlmap_out=sqlmap_out, zap_json=zap_json,
            nikto_out=nikto_out, vt_json=vt_json, vt_summary=vt_summary
        )

    elif choice == "2":
        zap_html, zap_json = run_zap_scan(target, cookies=cookies)
        print(f"[+] ZAP done. Reports saved to: {zap_html} and {zap_json}")
        _maybe_run_llm_report(
            target=target, cookies=cookies,
            sqlmap_out=sqlmap_out, zap_json=zap_json,
            nikto_out=nikto_out, vt_json=vt_json, vt_summary=vt_summary
        )

    elif choice == "3":
        sqlmap_out = run_sqlmap(target, cookies=cookies, level_preset=preset, scan_type=scan_type)
        print(f"[+] SQLMap done. Output saved to: {sqlmap_out}")

        zap_html, zap_json = run_zap_scan(target, cookies=cookies)
        print(f"[+] ZAP done. Reports saved to: {zap_html} and {zap_json}")

        _maybe_run_llm_report(
            target=target, cookies=cookies,
            sqlmap_out=sqlmap_out, zap_json=zap_json,
            nikto_out=nikto_out, vt_json=vt_json, vt_summary=vt_summary
        )

    elif choice == "4":
        vt_json, vt_summary = run_virustotal_url_scan(target)
        print(f"[+] VirusTotal done. Outputs saved to: {vt_json} and {vt_summary}")
        _maybe_run_llm_report(
            target=target, cookies=cookies,
            sqlmap_out=sqlmap_out, zap_json=zap_json,
            nikto_out=nikto_out, vt_json=vt_json, vt_summary=vt_summary
        )

    elif choice == "5":
        nikto_out = run_nikto_scan(target, cookies=cookies)
        print(f"[+] Nikto done. Output saved to: {nikto_out}")
        _maybe_run_llm_report(
            target=target, cookies=cookies,
            sqlmap_out=sqlmap_out, zap_json=zap_json,
            nikto_out=nikto_out, vt_json=vt_json, vt_summary=vt_summary
        )

    elif choice == "6":
        sqlmap_out = run_sqlmap(target, cookies=cookies, level_preset=preset, scan_type=scan_type)
        print(f"[+] SQLMap done. Output saved to: {sqlmap_out}")

        zap_html, zap_json = run_zap_scan(target, cookies=cookies)
        print(f"[+] ZAP done. Reports saved to: {zap_html} and {zap_json}")

        vt_json, vt_summary = run_virustotal_url_scan(target)
        print(f"[+] VirusTotal done. Outputs saved to: {vt_json} and {vt_summary}")

        nikto_out = run_nikto_scan(target, cookies=cookies)
        print(f"[+] Nikto done. Output saved to: {nikto_out}")

        _maybe_run_llm_report(
            target=target, cookies=cookies,
            sqlmap_out=sqlmap_out, zap_json=zap_json,
            nikto_out=nikto_out, vt_json=vt_json, vt_summary=vt_summary
        )

    elif choice == "7":
        # Just try to generate a report from whatever outputs exist.
        # (You can point it at specific files later if you want.)
        _maybe_run_llm_report(
            target=target, cookies=cookies,
            sqlmap_out="reports/sqlmap/sqlmap_output.txt",
            zap_json=None,
            nikto_out="reports/nikto/nikto_report.txt",
            vt_json="reports/virustotal/virustotal_report.json",
            vt_summary="reports/virustotal/virustotal_summary.txt"
        )

    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
