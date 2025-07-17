#!/usr/bin/env python3

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
    # Interaktif prompt jika tidak pakai argumen
    domain = input("🕷️ Masukkan domain target (cth: https://example.com): ").strip()

    # Set default mode
    deep_scan = True
    scan_vuln = True
    report_format = "html"

    print(f"[+] Memulai scan pada: {domain}")

    print("[+] Mencari subdomain...")
    subdomains = find_subdomains(domain)
    print(f"[✓] {len(subdomains)} subdomain ditemukan.")

    print("[+] Mengambil arsip URL...")
    urls = []
    for sub in subdomains:
        urls.extend(get_archive_urls(sub))
    print(f"[✓] Total {len(urls)} URL berhasil dikumpulkan.")

    print("[+] Mengekstrak parameter dari URL...")
    extracted_params = extract_parameters(urls)

    if scan_vuln:
        print("[+] Menganalisis parameter untuk potensi kerentanan...")
        results = analyze_vulnerabilities_by_severity(extracted_params)
    else:
        results = {"INFO": extracted_params}

    print("[+] Memeriksa backdoor...")
    backdoor_status = detect_backdoor(domain)
    print(f"[✓] Status Backdoor: {backdoor_status}")

    print("[+] Menganalisis JavaScript untuk sink berbahaya...")
    js_findings = analyze_js_sinks(domain)

    print("[+] Menemukan endpoint API sensitif...")
    api_endpoints = extract_api_endpoints(domain)

    print("[+] Mendeteksi CMS target...")
    cms = detect_cms(domain)
    print(f"[✓] CMS Dikenali: {cms}")

    save_report(results, domain, report_format)
    append_to_report(domain, report_format, backdoor_status, js_findings, api_endpoints, cms)

    safe_domain = sanitize_filename(domain)
    print(f"[✓] Laporan disimpan: output/reports/{safe_domain}.{report_format}")

if __name__ == "__main__":
    main()
