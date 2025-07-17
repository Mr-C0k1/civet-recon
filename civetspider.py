#!/usr/bin/env python3
import argparse
import os
import json
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import requests

# ----------- Real function: find_subdomains menggunakan crt.sh -----------
def find_subdomains(domain):
    domain_clean = domain.replace("https://", "").replace("http://", "").strip("/")
    print(f"[+] Mencari subdomain untuk {domain_clean} via crt.sh...")
    url = f"https://crt.sh/?q=%25.{domain_clean}&output=json"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value")
            if name:
                # name_value bisa multiline, pisahkan dan simpan unique
                for n in name.split("\n"):
                    if n.endswith(domain_clean):
                        subdomains.add(f"https://{n.strip()}")
        print(f"[+] Ditemukan {len(subdomains)} subdomain dari crt.sh")
        return list(subdomains)
    except Exception as e:
        print(f"[!] Gagal mendapatkan subdomain: {e}")
        # fallback domain utama saja supaya lanjut scanning
        return [f"https://{domain_clean}"]

# ----------- Real function: get_archive_urls menggunakan web.archive.org -----------
def get_archive_urls(subdomains):
    print(f"[+] Mengambil arsip URL dari {len(subdomains)} subdomain via Wayback Machine...")
    urls = set()
    for sub in subdomains:
        domain_clean = sub.replace("https://", "").replace("http://", "").strip("/")
        api = f"https://web.archive.org/cdx/search/cdx?url={domain_clean}/*&output=json&fl=original&collapse=urlkey"
        try:
            resp = requests.get(api, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            # data[0] biasanya header, data[1:] adalah URL arsip
            for item in data[1:]:
                if isinstance(item, list) and len(item) > 0:
                    urls.add(item[0])
            print(f"[+] {len(data)-1} URL arsip ditemukan untuk {domain_clean}")
        except Exception as e:
            print(f"[!] Gagal ambil arsip untuk {domain_clean}: {e}")
    return list(urls)

# ----------- Fungsi lainnya -----------

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
    # Dummy backdoor check, bisa kamu ganti dengan logic real
    return "Tidak ditemukan backdoor (dummy)"

def analyze_js_sinks(domain):
    # Dummy JS sink check
    return ["Tidak ditemukan sink JS (dummy)"]

def extract_api_endpoints(domain):
    # Dummy API endpoint list
    domain_clean = domain.rstrip("/")
    return [f"{domain_clean}/api/v1/users", f"{domain_clean}/api/v1/admin"]

def detect_cms(domain):
    # Dummy CMS detection
    return "Unknown CMS (dummy)"

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
    print(f"[✓] Report saved at: {path}")

def main():
    parser = argparse.ArgumentParser(
        description="🕷️ CivetSpider - Advanced Web Parameter & Vulnerability Analyzer",
        epilog="Example: python3 civetspider.py -d https://example.com --scan-vuln --deep --report html"
    )
    parser.add_argument("--domain", "-d", required=True, help="Target domain (e.g., https://example.com)")
    parser.add_argument("--deep", action="store_true", help="Deep scan with JS parser and heuristic analysis")
    parser.add_argument("--scan-vuln", action="store_true", help="Scan for vulnerabilities in parameters")
    parser.add_argument("--report", choices=["markdown", "json", "html"], default="markdown", help="Report format")
    args = parser.parse_args()

    print(f"[+] Starting CivetSpider scan on: {args.domain}")

    subdomains = find_subdomains(args.domain)
    urls = get_archive_urls(subdomains)
    extracted_params = extract_parameters(urls)

    if args.scan_vuln:
        print("[+] Analyzing parameters for vulnerabilities by severity...")
        results = analyze_vulnerabilities_by_severity(extracted_params)
    else:
        results = {"INFO": extracted_params}

    print("[+] Checking for potential backdoors...")
    backdoor_status = detect_backdoor(args.domain)
    print(f"[✓] Backdoor Status: {backdoor_status}")

    print("[+] Analyzing JavaScript for sink functions...")
    js_findings = analyze_js_sinks(args.domain)
    for finding in js_findings:
        print(f"[✓] JS Sink: {finding}")

    print("[+] Scanning for sensitive API endpoints...")
    api_endpoints = extract_api_endpoints(args.domain)
    for api in api_endpoints:
        print(f"[✓] API Found: {api}")

    print("[+] Fingerprinting CMS...")
    cms = detect_cms(args.domain)
    print(f"[✓] CMS Detected: {cms}")

    report = {
        "domain": args.domain,
        "scan_time": str(datetime.now()),
        "vulnerabilities": results,
        "backdoor_status": backdoor_status,
        "js_sinks": js_findings,
        "api_endpoints": api_endpoints,
        "cms": cms
    }

    save_report(report, args.domain, args.report)

if __name__ == "__main__":
    main()
