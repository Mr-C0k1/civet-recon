#!/usr/bin/env python3
# Civet_Upgraded: Reconnaissance & Vulnerability Scanner (Upgraded Version)
# Features: Nuclei/Dalfox Integration, Sensitive Files, API Scan, Built-in Payloads, Multithreading, Logging, Export

import argparse
import requests
import os
import re
import subprocess
import time
import random
import json
import logging
import shutil
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

# === CONFIGURATION ===
RATE_LIMIT = (1, 3)  # Random delay in seconds
THREAD_COUNT_DEFAULT = 5
CRAWL_DEPTH = 2
OUTPUT_DIR_DEFAULT = 'output'
PROXIES = {}  # Add proxy if needed
SUBDOMAIN_WORDLIST = ["www", "api", "dev", "test", "admin", "staging", "beta"]  # Expandable
SENSITIVE_FILES = [
    ".env", ".git/config", ".htaccess", "config.json", "config.yml",
    "db.sql", "backup.zip", "credentials.txt", "secret.key",
    "error.log", "debug.log"
]
API_ENDPOINTS = [
    "/api/login", "/api/auth", "/api/register", "/api/admin", "/api/config",
    "/api/debug", "/api/token", "/api/upload", "/api/user/delete", "/api/settings"
]
PAYLOADS_XSS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]  # Basic for fallback

# Setup logging
logging.basicConfig(filename='civet_results.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

logo = r'''
   ／＞　 フ
  | 　_　_| 
／` ミ＿xノ 
/　　　　 |
/　 ヽ　　 ﾉ
│　　|　|　|
／￣|　　 |　|　|
(￣ヽ＿_ヽ_)__)
＼二)

CIVET Recon Engine (Upgraded)
'''

def is_root_domain(url):
    parsed = urlparse(url)
    return parsed.path in ('', '/')

def banner():
    print(Fore.CYAN + logo + Style.RESET_ALL)

def check_dependencies():
    """Check if external tools are available."""
    tools = ['nuclei', 'dalfox']
    available = {}
    for tool in tools:
        if shutil.which(tool):
            available[tool] = True
            print(Fore.GREEN + f"[+] {tool} tersedia." + Style.RESET_ALL)
        else:
            available[tool] = False
            print(Fore.YELLOW + f"[-] {tool} tidak tersedia. Menggunakan built-in scanning." + Style.RESET_ALL)
    return available

def run_nuclei(url, output_dir, deps):
    if not deps.get('nuclei', False):
        print(Fore.RED + "[-] Nuclei tidak tersedia, skipping." + Style.RESET_ALL)
        return []
    print(Fore.YELLOW + "[+] Menjalankan Nuclei..." + Style.RESET_ALL)
    try:
        result = subprocess.run(['nuclei', '-u', url, '-o', f"{output_dir}/nuclei_result.txt", '-json'], capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            with open(f"{output_dir}/nuclei_result.txt", 'r') as f:
                return f.readlines()
        else:
            logging.warning(f"Nuclei error: {result.stderr}")
            return []
    except Exception as e:
        logging.warning(f"Error running Nuclei: {e}")
        return []

def run_dalfox(url, output_dir, deps):
    if not deps.get('dalfox', False):
        print(Fore.RED + "[-] Dalfox tidak tersedia, skipping." + Style.RESET_ALL)
        return []
    print(Fore.YELLOW + "[+] Menjalankan Dalfox..." + Style.RESET_ALL)
    try:
        result = subprocess.run(['dalfox', 'url', url, '--output', f"{output_dir}/dalfox_result.txt"], capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            with open(f"{output_dir}/dalfox_result.txt", 'r') as f:
                return f.readlines()
        else:
            logging.warning(f"Dalfox error: {result.stderr}")
            return []
    except Exception as e:
        logging.warning(f"Error running Dalfox: {e}")
        return []

def scan_sensitive_files(url, output_dir, results):
    print(Fore.YELLOW + "[+] Mendeteksi file sensitif..." + Style.RESET_ALL)
    found = []
    for file in SENSITIVE_FILES:
        full_url = f"{url.rstrip('/')}/{file}"
        time.sleep(random.uniform(*RATE_LIMIT))
        try:
            r = requests.get(full_url, timeout=10, proxies=PROXIES, verify=False)
            if r.status_code == 200 and 'html' not in r.headers.get('Content-Type', ''):
                found.append(full_url)
                results['sensitive_files'].append(full_url)
                logging.info(f"Sensitive file found: {full_url}")
        except Exception as e:
            logging.warning(f"Error scanning {full_url}: {e}")
    if found:
        print(Fore.GREEN + f"[+] Ditemukan file sensitif: {len(found)}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "[-] Tidak ditemukan file sensitif." + Style.RESET_ALL)

def scan_vulnerable_api(url, output_dir, results):
    print(Fore.YELLOW + "[+] Mendeteksi endpoint API rentan..." + Style.RESET_ALL)
    found = []
    for endpoint in API_ENDPOINTS:
        full_url = f"{url.rstrip('/')}{endpoint}"
        time.sleep(random.uniform(*RATE_LIMIT))
        try:
            r = requests.get(full_url, timeout=10, proxies=PROXIES, verify=False)
            if r.status_code in [200, 403] and 'html' not in r.headers.get('Content-Type', ''):
                found.append(full_url)
                results['vulnerable_api'].append(full_url)
                logging.info(f"Vulnerable API found: {full_url}")
        except Exception as e:
            logging.warning(f"Error scanning {full_url}: {e}")
    if found:
        print(Fore.GREEN + f"[+] Ditemukan endpoint API rentan: {len(found)}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "[-] Tidak ditemukan endpoint API rentan." + Style.RESET_ALL)

def crawl_and_inject(url, results, depth=0, visited=set()):
    """Basic crawling and payload injection for fallback."""
    if depth > CRAWL_DEPTH or url in visited:
        return
    visited.add(url)
    try:
        r = requests.get(url, timeout=10, proxies=PROXIES, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a"):
            href = a.get("href")
            if href:
                full = urljoin(url, href)
                if url in full and full not in visited:
                    crawl_and_inject(full, results, depth + 1, visited)
        # Basic XSS injection on forms
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            form_url = urljoin(url, action)
            for payload in PAYLOADS_XSS:
                time.sleep(random.uniform(*RATE_LIMIT))
                try:
                    if method == "post":
                        res = requests.post(form_url, data={"test": payload}, proxies=PROXIES, verify=False)
                    else:
                        res = requests.get(form_url, params={"test": payload}, proxies=PROXIES, verify=False)
                    if payload in res.text:
                        results['xss'].append({"url": form_url, "payload": payload})
                        print(Fore.RED + f"[!] XSS Detected at {form_url}" + Style.RESET_ALL)
                        logging.info(f"XSS Detected: {form_url}")
                except Exception as e:
                    logging.warning(f"Error injecting {form_url}: {e}")
    except Exception as e:
        logging.warning(f"Error crawling {url}: {e}")

def scan_subdomains(domain, results):
    print(Fore.YELLOW + "[+] Scanning subdomains..." + Style.RESET_ALL)
    found = []
    for sub in SUBDOMAIN_WORDLIST:
        url = f"https://{sub}.{domain}"
        time.sleep(random.uniform(*RATE_LIMIT))
        try:
            r = requests.get(url, timeout=5, proxies=PROXIES, verify=False)
            if r.status_code < 400:
                found.append(url)
                results['subdomains'].append(url)
                print(Fore.GREEN + f"[+] Subdomain Found: {url}" + Style.RESET_ALL)
                logging.info(f"Subdomain Found: {url}")
        except Exception as e:
            logging.warning(f"Error scanning subdomain {url}: {e}")
    return found

def check_cors(url, results):
    """Check for CORS misconfiguration."""
    try:
        headers = {"Origin": "https://evil.com"}
        r = requests.get(url, headers=headers, proxies=PROXIES, verify=False)
        cors_header = r.headers.get("Access-Control-Allow-Origin")
        if cors_header and cors_header != "*":
            results['cors'].append({"url": url, "header": cors_header})
            print(Fore.RED + f"[!] CORS Misconfig at {url}: {cors_header}" + Style.RESET_ALL)
            logging.info(f"CORS Misconfig: {url}")
    except Exception as e:
        logging.warning(f"Error checking CORS {url}: {e}")

def save_results(results, output_dir):
    with open(f"{output_dir}/results.json", 'w') as f:
        json.dump(results, f, indent=4)
    print(Fore.GREEN + f"[+] Results saved to {output_dir}/results.json" + Style.RESET_ALL)

def main():
    parser = argparse.ArgumentParser(description='CIVET - Recon Engine (Upgraded)')
    parser.add_argument('-u', '--url', required=True, help='Target URL (root domain only)')
    parser.add_argument('--stealth', action='store_true', help='Mode stealth (random delay)')
    parser.add_argument('-o', '--output', default=OUTPUT_DIR_DEFAULT, help='Direktori output')
    parser.add_argument('--threads', type=int, default=THREAD_COUNT_DEFAULT, help='Number of threads')
    parser.add_argument('--proxy', help='Proxy URL (e.g. http://proxy:port)')
    args = parser.parse_args()

    url = args.url
    stealth = args.stealth
    output_dir = args.output
    threads = args.threads
    if args.proxy:
        global PROXIES
        PROXIES = {"http": args.proxy, "https": args.proxy}

    # Auto-scheme detection
    if not url.startswith("http"):
        url = f"https://{url}"

    if not is_root_domain(url):
        print(Fore.RED + "[!] Hanya root domain yang diperbolehkan. Contoh: https://example.com" + Style.RESET_ALL)
        exit()

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    banner()
    print(Fore.RED + "[WARNING] Use only on authorized targets (e.g., bug bounty programs). Unauthorized scanning is illegal!" + Style.RESET_ALL)

    deps = check_dependencies()
    results = {'sensitive_files': [], 'vulnerable_api': [], 'subdomains': [], 'xss': [], 'cors': [], 'nuclei': [], 'dalfox': []}

    parsed = urlparse(url)
    domain = parsed.netloc

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        futures.append(executor.submit(scan_sensitive_files, url, output_dir, results))
        futures.append(executor.submit(scan_vulnerable_api, url, output_dir, results))
        futures.append(executor.submit(scan_subdomains, domain, results))
        futures.append(executor.submit(check_cors, url, results))
        futures.append(executor.submit(crawl_and_inject, url, results))

        # Run external tools
        nuclei_results = run_nuclei(url, output_dir, deps)
        dalfox_results = run_dalfox(url, output_dir, deps)
        results['nuclei'] = nuclei_results
        results['dalfox'] = dalfox_results

        for future in as_completed(futures):
            future.result()

    save_results(results, output_dir)
    print(Fore.CYAN + f"[✓] Hasil disimpan di direktori {output_dir}. Check civet_results.log" + Style.RESET_ALL)

if __name__ == "__main__":
    main()
