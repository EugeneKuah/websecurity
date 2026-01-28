from tools.sqlmap_scan import run_sqlmap
from tools.zap_scan import run_zap_scan

def main():
    print("=== InjeXpose ===")
    target = input("Target URL: ").strip()

    print("\nChoose tool:")
    print("1) SQLMap (SQL Injection)")
    print("2) OWASP ZAP (Spider + Active Scan)")
    print("3) Run BOTH")
    choice = input("Enter 1/2/3: ").strip()

    cookies = None
    if choice in ("1", "3"):
        cookies = input("Cookies for SQLMap (press Enter to skip): ").strip() or None

    if choice == "1":
        out = run_sqlmap(target, cookies=cookies)
        print(f"[+] SQLMap done. Output saved to: {out}")

    elif choice == "2":
        html_path, json_path = run_zap_scan(target)
        print(f"[+] ZAP done. Reports saved to: {html_path} and {json_path}")

    elif choice == "3":
        out = run_sqlmap(target, cookies=cookies)
        print(f"[+] SQLMap done. Output saved to: {out}")

        html_path, json_path = run_zap_scan(target)
        print(f"[+] ZAP done. Reports saved to: {html_path} and {json_path}")

    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()

