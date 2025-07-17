#!/usr/bin/env python3
import os
import json
import requests
import re
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# === CORE MODULES IMPLEMENTATION ===

def find_subdomains(domain):
    domain_clean = domain.replace("https://", "").replace("http://", "")
    url = f"https://crt.sh/?q=%25.{domain_clean}&output=json"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            subdomains = set()
            for entry in data:
                name = entry.get('name_value')
                if name:
                    for sub in name.split('\n'):
                        sub = sub.strip()
                        if sub.endswith(domain_clean):
                            subdomains.add("https://" + sub)
            return list(subdomains)
    except Exception as e:
        print(f"[!] Error find_subdomains: {e}")
    return [domain]

def get_archive_urls(subdomains):
    urls = []
    for domain in subdomains:
        domain_clean = domain.replace("https://", "").replace("http://", "")
        url = f"https://web.archive.org/cdx/search/cdx?url={domain_clean}/*&output=json&fl=original&collapse=urlkey"
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                urls.extend(item[0] for item in data[1:])
        except Exception as e:
            print(f"[!] Error get_archive_urls: {e}")
    return urls

def extract_parameters(urls):
    params = set()
    for url in urls:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for param in qs.keys():
            params.add(param)
    return list(params)

def analyze_vulnerabilities_by_severity(params):
    results = {"HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
    for p in params:
        if "id" in p or "user" in p:
            results["HIGH"].append(f"Parameter '{p}' mungkin rentan SQL Injection")
        else:
            results["INFO"].append(f"Parameter '{p}' ditemukan")
    return results

def detect_backdoor(domain):
    test_url = domain.rstrip('/') + "/backdoor.php"
    try:
        resp = requests.get(test_url, timeout=5)
        if resp.status_code == 200 and "backdoor" in resp.text.lower():
            return "Backdoor ditemukan di backdoor.php"
    except Exception:
        pass
    return "Tidak ditemukan backdoor"

def analyze_js_sinks(domain):
    sinks = []
    try:
        resp = requests.get(domain, timeout=5)
        if resp.status_code == 200:
            body = resp.text.lower()
            if "eval(" in body:
                sinks.append("eval()")
            if "document.write(" in body:
                sinks.append("document.write()")
    except Exception:
        pass
    return sinks if sinks else ["Tidak ditemukan sink JS"]

def extract_api_endpoints(domain):
    # Contoh sederhana (dummy)
    return [domain.rstrip("/") + "/api/v1/users", domain.rstrip("/") + "/api/v1/admin"]

def detect_cms(domain):
    try:
        resp = requests.get(domain, timeout=5)
        server = resp.headers.get("Server", "").lower()
        x_powered = resp.headers.get("X-Powered-By", "").lower()
        body = resp.text.lower()
        if "wordpress" in body:
            return "WordPress"
        if "joomla" in body:
            return "Joomla"
        if "drupal" in body:
            return "Drupal"
        if "nginx" in server:
            return "Nginx Server"
        if "php" in x_powered:
            return "PHP"
    except Exception:
        pass
    return "Unknown CMS"

# === UTILS ===

def sanitize_filename(domain):
    return domain.replace("https://", "").replace("http://", "").replace("/", "").replace(":", "_")

def save_report(report, domain, format="json"):
    os.makedirs("output/reports", exist_ok=True)
    path = f"output/reports/{sanitize_filename(domain)}.{format}"
    with open(path, "w") as f:
        if format == "json":
            json.dump(report, f, indent=2)
        elif format == "markdown":
            f.write(f"# CivetSpider Report for {domain}\n")
            f.write(f"Generated at: {datetime.now()}\n\n")
            for severity in ["HIGH", "MEDIUM", "LOW", "INFO"]:
                f.write(f"## {severity} Severity\n\n")
                for item in report.get("vulnerabilities", {}).get(severity, []):
                    f.write(f"- {item}\n")
            f.write("\n## CMS Detection\n")
            f.write(f"- CMS Detected: **{report.get('cms', 'Unknown')}**\n")
            f.write("\n## Backdoor Analysis\n")
            f.write(f"- {report.get('backdoor_status', 'Unknown')}\n")
            f.write("\n## JavaScript Sink Analysis\n")
            for js in report.get("js_sinks", []):
                f.write(f"- {js}\n")
            f.write("\n## API Endpoint Analysis\n")
            for api in report.get("api_endpoints", []):
                f.write(f"- {api}\n")
        elif format == "html":
            f.write(f"<html><head><title>CivetSpider Report</title></head><body>")
            f.write(f"<h1>CivetSpider Report for {domain}</h1>")
            f.write(f"<p>Generated at: {datetime.now()}</p>")
            for severity in ["HIGH", "MEDIUM", "LOW", "INFO"]:
                f.write(f"<h2>{severity} Severity</h2><ul>")
                for item in report.get("vulnerabilities", {}).get(severity, []):
                    f.write(f"<li>{item}</li>")
                f.write("</ul>")
            f.write(f"<h2>CMS Detection</h2><p>CMS Detected: <b>{report.get('cms', 'Unknown')}</b></p>")
            f.write(f"<h2>Backdoor Analysis</h2><p>{report.get('backdoor_status', 'Unknown')}</p>")
            f.write(f"<h2>JavaScript Sink Analysis</h2><ul>")
            for js in report.get("js_sinks", []):
                f.write(f"<li>{js}</li>")
            f.write("</ul>")
            f.write(f"<h2>API Endpoint Analysis</h2><ul>")
            for api in report.get("api_endpoints", []):
                f.write(f"<li>{api}</li>")
            f.write("</ul></body></html>")
    print(f"[✓] Laporan disimpan di: {path}")

# === MAIN ===

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="🕷️ CivetSpider - Advanced Web Parameter & Vulnerability Analyzer",
        epilog="Example: python3 civetspider.py -d https://example.com --scan-vuln --deep --report json"
    )
    parser.add_argument("--domain", "-d", required=False, default="https://example.com", help="Target domain (default: https://example.com)")
    parser.add_argument("--deep", action="store_true", help="Deep scan dengan JS parser dan heuristic")
    parser.add_argument("--scan-vuln", action="store_true", help="Scan untuk vulnerability pada parameter")
    parser.add_argument("--report", choices=["markdown", "json", "html"], default="json", help="Format report")
    args = parser.parse_args()

    domain = args.domain

    print(f"[+] Mulai scan pada: {domain}")

    subdomains = find_subdomains(domain)
    print(f"[+] Ditemukan subdomain: {len(subdomains)}")

    urls = get_archive_urls(subdomains)
    print(f"[+] Mengambil URL arsip: {len(urls)}")

    extracted_params = extract_parameters(urls)
    print(f"[+] Parameter ditemukan: {len(extracted_params)}")

    if args.scan_vuln:
        results = analyze_vulnerabilities_by_severity(extracted_params)
    else:
        results = {"INFO": extracted_params}

    backdoor_status = detect_backdoor(domain)
    js_findings = analyze_js_sinks(domain)
    api_endpoints = extract_api_endpoints(domain)
    cms = detect_cms(domain)

    report = {
        "domain": domain,
        "scan_time": str(datetime.now()),
        "vulnerabilities": results,
        "backdoor_status": backdoor_status,
        "js_sinks": js_findings,
        "api_endpoints": api_endpoints,
        "cms": cms
    }

    save_report(report, domain, args.report)

if __name__ == "__main__":
    main()
