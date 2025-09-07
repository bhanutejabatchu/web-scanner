import requests
from bs4 import BeautifulSoup
import os

# Create reports folder if not exists
if not os.path.exists("reports"):
    os.makedirs("reports")

def check_security_headers(url):
    print("\n[*] Checking Security Headers...")
    try:
        response = requests.get(url)
        headers = response.headers
        important_headers = [
            "X-Frame-Options",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options"
        ]
        findings = []
        for h in important_headers:
            if h in headers:
                findings.append(f"[+] {h}: {headers[h]}")
            else:
                findings.append(f"[-] {h}: Missing")
        return findings
    except Exception as e:
        return [f"[!] Error: {e}"]

def test_sql_injection(url):
    print("\n[*] Testing SQL Injection...")
    payload = "' OR '1'='1"
    try:
        response = requests.get(url + payload)
        if "sql" in response.text.lower() or "error" in response.text.lower():
            return ["[!] Possible SQL Injection vulnerability detected!"]
        else:
            return ["[+] No SQL Injection vulnerability found."]
    except Exception as e:
        return [f"[!] Error: {e}"]

def test_xss(url):
    print("\n[*] Testing XSS...")
    payload = "<script>alert('XSS')</script>"
    try:
        response = requests.get(url + payload)
        if payload in response.text:
            return ["[!] Possible XSS vulnerability detected!"]
        else:
            return ["[+] No XSS vulnerability found."]
    except Exception as e:
        return [f"[!] Error: {e}"]

def main():
    # Hardcoded target (no input)
    target = "http://testphp.vulnweb.com/"
    print(f">>> Using hardcoded target: {target}")

    print(f"\n[*] Scanning {target} ...")

    results = []
    results.extend(check_security_headers(target))
    results.extend(test_sql_injection(target))
    results.extend(test_xss(target))

    # Save report
    report_path = "reports/scan_report.txt"
    with open(report_path, "w") as f:
        for line in results:
            f.write(line + "\n")

    print("\n[*] Scan completed. Report saved to", report_path)

if __name__ == "__main__":
    main()


