#!/usr/bin/env python3
# Civet: Reconnaissance & Vulnerability Scanner

import argparse
import requests
import os
import re
import subprocess
import time
from urllib.parse import urlparse
from colorama import Fore, Style

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

CIVET Recon Engine
'''

def is_root_domain(url):
    parsed = urlparse(url)
    return parsed.path in ('', '/')

def banner():
    print(Fore.CYAN + logo + Style.RESET_ALL)

def run_nuclei(url, output_dir):
    print(Fore.YELLOW + "[+] Menjalankan Nuclei..." + Style.RESET_ALL)
    os.system(f"nuclei -u {url} -o {output_dir}/nuclei_result.txt")

def run_dalfox(url, output_dir):
    print(Fore.YELLOW + "[+] Menjalankan Dalfox..." + Style.RESET_ALL)
    os.system(f"dalfox url {url} --output {output_dir}/dalfox_result.txt")

def scan_sensitive_files(url, output_dir):
    print(Fore.YELLOW + "[+] Mendeteksi file sensitif..." + Style.RESET_ALL)
    sensitive_files = [
        ".env", ".git/config", ".htaccess", "config.json", "config.yml",
        "db.sql", "backup.zip", "credentials.txt", "secret.key",
        "error.log", "debug.log"
    ]
    found = []
    for file in sensitive_files:
        full_url = f"{url.rstrip('/')}/{file}"
        try:
            r = requests.get(full_url, timeout=10)
            if r.status_code == 200 and 'html' not in r.headers.get('Content-Type', ''):
                found.append(full_url)
        except:
            continue
    with open(f"{output_dir}/sensitive_files.txt", 'w') as f:
        for item in found:
            f.write(f"{item}\n")
    if found:
        print(Fore.GREEN + f"[+] Ditemukan file sensitif: {len(found)}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "[-] Tidak ditemukan file sensitif." + Style.RESET_ALL)

def scan_vulnerable_api(url, output_dir):
    print(Fore.YELLOW + "[+] Mendeteksi endpoint API rentan..." + Style.RESET_ALL)
    endpoints = [
        "/api/login", "/api/auth", "/api/register", "/api/admin", "/api/config",
        "/api/debug", "/api/token", "/api/upload", "/api/user/delete", "/api/settings"
    ]
    found = []
    for endpoint in endpoints:
        full_url = f"{url.rstrip('/')}{endpoint}"
        try:
            r = requests.get(full_url, timeout=10)
            if r.status_code in [200, 403] and 'html' not in r.headers.get('Content-Type', ''):
                found.append(full_url)
        except:
            continue
    with open(f"{output_dir}/vulnerable_api.txt", 'w') as f:
        for item in found:
            f.write(f"{item}\n")
    if found:
        print(Fore.GREEN + f"[+] Ditemukan endpoint API rentan: {len(found)}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "[-] Tidak ditemukan endpoint API rentan." + Style.RESET_ALL)

def main():
    parser = argparse.ArgumentParser(description='CIVET - Recon Engine')
    parser.add_argument('-u', '--url', required=True, help='Target URL (root domain only)')
    parser.add_argument('--stealth', action='store_true', help='Mode stealth (delay setiap permintaan)')
    parser.add_argument('-o', '--output', default='output', help='Direktori output')
    args = parser.parse_args()

    url = args.url
    stealth = args.stealth
    output_dir = args.output

    if not is_root_domain(url):
        print(Fore.RED + "[!] Hanya root domain yang diperbolehkan. Contoh: https://example.com" + Style.RESET_ALL)
        exit()

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    banner()

    if stealth:
        print(Fore.CYAN + "[i] Mode stealth aktif: delay ditambahkan." + Style.RESET_ALL)
        time.sleep(2)

    scan_sensitive_files(url, output_dir)
    scan_vulnerable_api(url, output_dir)
    run_nuclei(url, output_dir)
    run_dalfox(url, output_dir)

    print(Fore.CYAN + f"[✓] Hasil disimpan di direktori {output_dir}" + Style.RESET_ALL)

if __name__ == "__main__":
    main()
