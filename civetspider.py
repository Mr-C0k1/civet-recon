#!/usr/bin/env python3
# civetspider.py - v0.6 Stable

import argparse
import os
import json
from datetime import datetime
from core.subdomain import find_subdomains
from core.archive import get_archive_urls
from core.extractor import extract_parameters
from core.analyzer import analyze_vulnerabilities_by_severity
from core.backdoor import detect_backdoor
from core.js_analyzer import analyze_js_sinks
from core.api_endpoint_scanner import extract_api_endpoints
from core.cms_fingerprint import detect_cms

def sanitize_filename(domain):
    return domain.replace("https://", "").replace("http://", "").replace("/", "").replace(":", "_")

def save_report(results, domain, format):
    output_dir = f"output/reports"
    os.makedirs(output_dir, exist_ok=True)

    safe_domain = sanitize_filename(domain)
    path = f"{output_dir}/{safe_domain}.{format}"

    if format == "markdown":
        with open(path, "w") as f:
            f.write(f"# CivetSpider Report for {domain}\n")
            f.write(f"Generated at: {datetime.now()}\n\n")
            for severity in ["HIGH", "MEDIUM", "LOW", "INFO"]:
                f.write(f"## {severity} Severity\n\n")
                for item in results.get(severity, []):
                    f.write(f"- `{item}`\n")

    elif format == "json":
        with open(path, "w") as f:
            json.dump({"domain": domain, "results": results, "generated": str(datetime.now())}, f, indent=2)

    elif format == "html":
        with open(path, "w") as f:
            f.write(f"<html><head><title>CivetSpider Report</title></head><body>")
            f.write(f"<h1>CivetSpider Report for {domain}</h1>")
            f.write(f"<p>Generated at: {datetime.now()}</p>")
            for severity in ["HIGH", "MEDIUM", "LOW", "INFO"]:
                f.write(f"<h2>{severity} Severity</h2><ul>")
                for item in results.get(severity, []):
                    f.write(f"<li>{item}</li>")
                f.write("</ul>")
            f.write("</body></html>")

def append_to_report(domain, format, backdoor_status, js_findings, api_endpoints, cms):
    safe_domain = sanitize_filename(domain)
    path = f"output/reports/{safe_domain}.{format}"

    if format == "markdown":
        with open(path, "a") as f:
            f.write("\n\n## CMS Detection\n")
            f.write(f"- CMS Detected: **{cms}**\n")
            f.write("\n## Backdoor Analysis\n")
            f.write(f"- {backdoor_status}\n")
            f.write("\n## JavaScript Sink Analysis\n")
            for js in js_findings:
                f.write(f"- {js}\n")
            f.write("\n## API Endpoint Analysis\n")
            for api in api_endpoints:
                f.write(f"- {api}\n")

    elif format == "json":
        with open(path, "r+") as f:
            data = json.load(f)
            data["cms"] = cms
            data["backdoor_analysis"] = backdoor_status
            data["js_sink_analysis"] = js_findings
            data["api_endpoints"] = api_endpoints
            f.seek(0)
            json.dump(data, f, indent=2)
            f.truncate()

    elif format == "html":
        with open(path, "r+") as f:
            content = f.read()
            insert = f"<h2>CMS Detection</h2><p>CMS Detected: <b>{cms}</b></p>"
            insert += f"<h2>Backdoor Analysis</h2><p>{backdoor_status}</p>"
            insert += f"<h2>JavaScript Sink Analysis</h2><ul>"
            for js in js_findings:
                insert += f"<li>{js}</li>"
            insert += "</ul>"
            insert += f"<h2>API Endpoint Analysis</h2><ul>"
            for api in api_endpoints:
                insert += f"<li>{api}</li>"
            insert += "</ul></body>"
            content = content.replace("</body>", insert)
            f.seek(0)
            f.write(content)
            f.truncate()

def main():
    parser = argparse.ArgumentParser(
        description="🕷️ CivetSpider - Advanced Web Parameter & Vulnerability Analyzer",
        epilog="Example: python3 civetspider.py -d https://example.com --scan-vuln --deep --report html"
    )
    parser.add_argument("--domain", "-d", required=True, help="Target domain (e.g., https://example.com)")
    parser.add_argument("--deep", action="store_true", help="Deep scan with JS parser and heuristic analysis")
    parser.add_argument("--scan-vuln", action="store_true", help="Scan for vulnerabilities in parameters")
    parser.add_argument("--report", choices=["markdown", "json", "html"], default="markdown", help="Report format")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads")
    args = parser.parse_args()

    domain = args.domain
    print(f"[+] Starting CivetSpider scan on: {domain}")

    print("[+] Finding subdomains...")
    subdomains = find_subdomains(domain)

    print(f"[✓] {len(subdomains)} subdomains found.")

    print("[+] Getting archive URLs...")
    urls = []
    for sub in subdomains:
        urls.extend(get_archive_urls(sub))

    print(f"[✓] Total {len(urls)} URLs collected.")

    print("[+] Extracting parameters...")
    extracted_params = extract_parameters(urls)

    if args.scan_vuln:
        print("[+] Analyzing parameters for vulnerabilities by severity...")
        results = analyze_vulnerabilities_by_severity(extracted_params)
    else:
        results = {"INFO": extracted_params}

    print("[+] Checking for potential backdoors...")
    backdoor_status = detect_backdoor(domain)
    print(f"[✓] Backdoor Status: {backdoor_status}")

    print("[+] Analyzing JavaScript for sink functions...")
    js_findings = analyze_js_sinks(domain)
    for finding in js_findings:
        print(f"[✓] JS Sink: {finding}")

    print("[+] Scanning for sensitive API endpoints...")
    api_endpoints = extract_api_endpoints(domain)
    for api in api_endpoints:
        print(f"[✓] API Found: {api}")

    print("[+] Fingerprinting CMS...")
    cms = detect_cms(domain)
    print(f"[✓] CMS Detected: {cms}")

    save_report(results, domain, args.report)
    append_to_report(domain, args.report, backdoor_status, js_findings, api_endpoints, cms)

    safe_domain = sanitize_filename(domain)
    print(f"[✓] Report saved in output/reports/{safe_domain}.{args.report}")

if __name__ == "__main__":
    main()
