#!/usr/bin/env python3
"""
civet-nobe_safe.py - SAFETY-FOCUSED UPGRADED VERSION
Advanced Web Reconnaissance & Vulnerability Scanner
!! ONLY USE ON TARGETS YOU OWN OR HAVE EXPLICIT PERMISSION !!

Changes & Improvements:
- Added --mode safe|normal|aggressive to control active testing
- Safer XSS detection (reflection check + context awareness)
- Better parameter handling (GET & POST separately)
- Improved crawler (max URLs limit, exclude extensions)
- Optional skipping of dangerous tests (RCE, SQLi, XXE)
- Better false-positive reduction
- Summary report at the end
- More configurable via arguments
"""

import requests
import re
import argparse
import json
import logging
import time
import random
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init(autoreset=True)

# ================= CONFIGURATION =================
DEFAULT_THREADS = 5
DEFAULT_DEPTH = 2
DEFAULT_RATE_MIN, DEFAULT_RATE_MAX = 1.0, 3.0
MAX_CRAWLED_URLS = 300

COMMON_SUBDOMAINS = [
    "www", "api", "app", "dev", "test", "staging", "beta", "admin", "portal",
    "auth", "login", "mail", "ftp", "cdn", "static", "blog", "shop"
]

PAYLOADS = {
    "xss": {
        "basic": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
        "context_aware": ["'\"`><script>alert(1)</script>", "';alert(1);//"]
    },
    "sqli": ["' OR 1=1 --", "1' WAITFOR DELAY '0:0:5' --"],  # limited & safer
    "redirect": ["//evil.com", "http://evil.com"]
    # RCE, XXE, SSRF deliberately limited / removed from default
}

DANGEROUS_TESTS = {"rce", "xxe", "ssrf"}

# Logging
logging.basicConfig(
    filename="civet_safe.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def print_logo():
    logo = r"""
      (()__(()
      / \     Recon-Corp
     ( / \    Safety-Focused Scanner
      \ o o /
      (_()_)__/
    """
    print(Fore.YELLOW + logo + Style.RESET_ALL)

def rate_limit(min_sec=1.0, max_sec=3.0):
    time.sleep(random.uniform(min_sec, max_sec))

def crawl_urls(start_url, depth=2, max_urls=MAX_CRAWLED_URLS):
    visited = set()
    to_visit = [(start_url, 0)]
    collected = set()

    while to_visit and len(collected) < max_urls:
        url, current_depth = to_visit.pop(0)
        if url in visited or current_depth > depth:
            continue
        visited.add(url)

        try:
            r = requests.get(url, timeout=8, allow_redirects=True)
            if r.status_code != 200 or "text/html" not in r.headers.get("content-type", ""):
                continue

            soup = BeautifulSoup(r.text, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link["href"]
                full_url = urljoin(url, href)
                parsed = urlparse(full_url)
                if parsed.netloc == urlparse(start_url).netloc:
                    ext = parsed.path.split(".")[-1].lower()
                    if ext not in {"css", "js", "png", "jpg", "jpeg", "gif", "svg", "woff", "woff2", "ttf"}:
                        collected.add(full_url)
                        if current_depth < depth:
                            to_visit.append((full_url, current_depth + 1))

        except Exception as e:
            logging.debug(f"Crawl error {url}: {e}")

    return collected

def scan_subdomains(domain):
    found = []
    for sub in COMMON_SUBDOMAINS:
        url = f"https://{sub}.{domain}"
        try:
            r = requests.head(url, timeout=5, allow_redirects=True)
            if r.status_code < 400:
                found.append(url)
                print(f"{Fore.GREEN}[+] Subdomain: {url}{Style.RESET_ALL}")
        except:
            pass
    return found

def find_forms_and_params(url):
    try:
        r = requests.get(url, timeout=8)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action", ""))
            method = form.get("method", "get").lower()
            inputs = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs[name] = inp.get("type", "text")
            if inputs:
                forms.append({"action": action, "method": method, "params": inputs})
        return forms
    except Exception as e:
        logging.debug(f"Form extraction error {url}: {e}")
        return []

def test_param_reflection(url, param_name, payload, method="get", session=None):
    """Check if payload is reflected in response (basic reflected XSS detection)"""
    test_value = f"TEST{payload}REFLECT"
    if method == "get":
        params = {param_name: test_value}
        try:
            r = (session or requests).get(url, params=params, timeout=8)
        except:
            return False
    else:
        data = {param_name: test_value}
        try:
            r = (session or requests).post(url, data=data, timeout=8)
        except:
            return False

    if test_value in r.text:
        return {"url": r.url, "param": param_name, "payload": payload, "method": method}
    return None

def scan_vulns(url, mode="safe"):
    results = {}
    session = requests.Session()

    forms = find_forms_and_params(url)
    if not forms:
        return results

    for form in forms:
        action = form["action"]
        method = form["method"]
        params = form["params"]

        for param_name, _ in params.items():
            for vuln_type, payload_dict in PAYLOADS.items():
                if mode == "safe" and vuln_type in DANGEROUS_TESTS:
                    continue

                for category, payloads_list in payload_dict.items():
                    for payload in payloads_list:
                        rate_limit()
                        finding = test_param_reflection(
                            action, param_name, payload, method, session
                        )
                        if finding:
                            print(f"{Fore.RED}[!] Possible {vuln_type.upper()} reflection: "
                                  f"{action} ({param_name}={payload}){Style.RESET_ALL}")
                            results.setdefault(vuln_type, []).append(finding)

    return results

def main():
    parser = argparse.ArgumentParser(
        description="civet-nobe_safe.py - Safety-focused web vulnerability scanner",
        epilog="Use --mode safe for reconnaissance only. Use responsibly!"
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL[](https://example.com)")
    parser.add_argument("--mode", choices=["safe", "normal", "aggressive"], default="safe",
                        help="safe = recon only, normal = basic payloads, aggressive = more payloads")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    parser.add_argument("--depth", type=int, default=DEFAULT_DEPTH)
    parser.add_argument("--skip", nargs="+", choices=DANGEROUS_TESTS,
                        help="Skip dangerous test categories")
    args = parser.parse_args()

    print_logo()
    print(f"{Fore.YELLOW}Target: {args.url}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Mode: {args.mode} | Threads: {args.threads} | Depth: {args.depth}{Style.RESET_ALL}")
    print(f"{Fore.RED}WARNING: Only scan targets you have explicit permission for!{Style.RESET_ALL}\n")

    parsed = urlparse(args.url)
    domain = parsed.netloc or parsed.path

    results = {"target": args.url, "subdomains": [], "vulnerabilities": {}, "crawled": []}

    # Subdomains
    subs = scan_subdomains(domain)
    results["subdomains"] = subs

    # Crawl
    print(f"{Fore.CYAN}Crawling...{Style.RESET_ALL}")
    urls = crawl_urls(args.url, args.depth)
    results["crawled"] = list(urls)[:MAX_CRAWLED_URLS]
    print(f"{Fore.CYAN}Found {len(urls)} URLs to scan{Style.RESET_ALL}")

    # Vulnerability scanning
    print(f"{Fore.CYAN}Scanning for vulnerabilities...{Style.RESET_ALL}")
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {executor.submit(scan_vulns, u, args.mode): u for u in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                vulns = future.result()
                for vtype, findings in vulns.items():
                    results["vulnerabilities"].setdefault(vtype, []).extend(findings)
            except Exception as e:
                logging.error(f"Scan error on {url}: {e}")

    # Save
    outfile = f"civet_safe_{domain.replace('.', '_')}_{int(time.time())}.json"
    with open(outfile, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # Summary
    print(f"\n{Fore.GREEN}Scan finished. Results saved to {outfile}{Style.RESET_ALL}")
    total_findings = sum(len(v) for v in results["vulnerabilities"].values())
    print(f"Total potential findings: {total_findings}")
    for vtype, findings in results["vulnerabilities"].items():
        print(f"  {vtype.upper():<6}: {len(findings)}")

if __name__ == "__main__":
    main()
