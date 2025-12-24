#!/usr/bin/env python3
"""
Civet Pro - Advanced Web Reconnaissance Engine (2025 Edition)
Integrasi modern: httpx + nuclei + dalfox + gowitness (opsional)
Fitur: Live endpoint discovery, tech detect, screenshot, vuln scan, safe mode
"""

import argparse
import json
import logging
import os
import random
import shutil
import subprocess
import time
from datetime import datetime
from urllib.parse import urlparse

import requests
from colorama import Fore, Style, init

init(autoreset=True)

# ===================== CONFIG =====================
RATE_MIN, RATE_MAX = 0.5, 2.0
DEFAULT_THREADS = 10
MAX_URLS = 500
COMMON_SUBDOMAINS = ["www", "api", "dev", "test", "staging", "admin", "app", "beta", "mail", "cdn"]

# External tools
REQUIRED_TOOLS = ["httpx"]
RECOMMENDED_TOOLS = ["nuclei", "dalfox", "gowitness"]

logo = r"""
   ／＞　 フ
  | 　_　 _ l
／` ミ＿xノ      CIVET PRO
/　　　　 |
/　 ヽ　　 ﾉ      Advanced Recon Engine
│　　|　|　|
／￣|　　 |　|　|
(￣ヽ＿_ヽ_)__)
＼二)
"""

# ===================== UTILITIES =====================
def banner():
    print(Fore.CYAN + logo + Style.RESET_ALL)
    print(Fore.YELLOW + "          Advanced Web Reconnaissance Engine - 2025" + Style.RESET_ALL)

def check_tools():
    available = {}
    missing = []
    for tool in REQUIRED_TOOLS + RECOMMENDED_TOOLS:
        available[tool] = shutil.which(tool) is not None
        if not available[tool] and tool in REQUIRED_TOOLS:
            missing.append(tool)
    
    if missing:
        print(Fore.RED + f"[!] Required tool tidak ditemukan: {', '.join(missing)}" + Style.RESET_ALL)
        print(Fore.YELLOW + "    Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest" + Style.RESET_ALL)
        exit(1)
    
    for tool, found in available.items():
        status = Fore.GREEN + "[+]" if found else Fore.YELLOW + "[-]"
        print(f"{status} {tool} {'tersedia' if found else 'tidak tersedia (opsional)'}" + Style.RESET_ALL)
    
    return available

def rate_limit():
    time.sleep(random.uniform(RATE_MIN, RATE_MAX))

def run_command(cmd, timeout=600):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Timeout", 1
    except Exception as e:
        return "", str(e), 1

# ===================== CORE FUNCTIONS =====================
def discover_live_targets(target, wordlist=None, tools_available=None):
    print(Fore.CYAN + "[+] Discovering live targets..." + Style.RESET_ALL)
    urls = [target.rstrip("/")]
    
    # Subdomain brute jika ada wordlist
    if wordlist and os.path.isfile(wordlist):
        print(Fore.YELLOW + "    → Brute-force subdomain dengan wordlist..." + Style.RESET_ALL)
        cmd = f"cat '{wordlist}' | sed 's/^/{target.split('://')[-1].lstrip('www.')}/' | httpx -silent -json"
        out, _, _ = run_command(cmd)
        for line in out.splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    urls.append(data["url"])
                except:
                    continue
    else:
        # Common subdomains
        common_urls = [f"https://{sub}.{urlparse(target).netloc}" for sub in COMMON_SUBDOMAINS]
        input_file = f"/tmp/civet_common_{os.getpid()}.txt"
        with open(input_file, "w") as f:
            f.write("\n".join(common_urls))
        cmd = f"httpx -list {input_file} -silent -json -title -tech-detect -status-code"
        out, _, _ = run_command(cmd)
        os.remove(input_file)
        for line in out.splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    urls.append(data["url"])
                except:
                    continue

    # Probe main target + common paths
    print(Fore.YELLOW + "    → Probing main target + common paths..." + Style.RESET_ALL)
    common_paths = ["/admin", "/api", "/login", "/graphql", "/.git", "/backup", "/config"]
    path_urls = [target.rstrip("/") + p for p in common_paths]
    input_file = f"/tmp/civet_paths_{os.getpid()}.txt"
    with open(input_file, "w") as f:
        f.write("\n".join(set(path_urls + urls)))
    cmd = f"httpx -list {input_file} -silent -json -title -tech-detect -status-code -follow-redirects"
    out, _, _ = run_command(cmd)
    os.remove(input_file)

    live_targets = []
    for line in out.splitlines():
        if line.strip():
            try:
                data = json.loads(line)
                live_targets.append({
                    "url": data["url"],
                    "status": data.get("status_code", 0),
                    "title": data.get("title", "No title"),
                    "tech": data.get("technologies", [])
                })
                print(f"     {Fore.GREEN}[LIVE]{Style.RESET_ALL} {data['url']} [{data.get('status_code')}] {data.get('title', '')}")
            except:
                continue

    return live_targets[:MAX_URLS]

def run_nuclei_scan(targets, output_dir, tools):
    if not tools.get("nuclei"):
        print(Fore.YELLOW + "[-] Nuclei tidak tersedia → skip" + Style.RESET_ALL)
        return []
    
    print(Fore.CYAN + "[+] Running Nuclei scan..." + Style.RESET_ALL)
    input_file = f"{output_dir}/nuclei_targets.txt"
    with open(input_file, "w") as f:
        f.write("\n".join([t["url"] for t in targets]))
    
    cmd = f"nuclei -list {input_file} -severity low,medium,high,critical -o {output_dir}/nuclei_results.json -jsonl"
    out, err, rc = run_command(cmd)
    
    if rc == 0 and os.path.exists(f"{output_dir}/nuclei_results.json"):
        with open(f"{output_dir}/nuclei_results.json") as f:
            return [json.loads(line) for line in f if line.strip()]
    return []

def run_dalfox_scan(targets, output_dir, tools):
    if not tools.get("dalfox"):
        print(Fore.YELLOW + "[-] Dalfox tidak tersedia → skip" + Style.RESET_ALL)
        return []
    
    print(Fore.CYAN + "[+] Running Dalfox XSS scan..." + Style.RESET_ALL)
    urls = [t["url"] for t in targets if "html" in requests.head(t["url"], timeout=5).headers.get("content-type", "")]
    if not urls:
        return []
    
    input_file = f"{output_dir}/dalfox_targets.txt"
    with open(input_file, "w") as f:
        f.write("\n".join(urls[:50]))  # Limit untuk menghindari overload
    
    cmd = f"dalfox file {input_file} --output {output_dir}/dalfox_results.txt"
    run_command(cmd)
    return []

def take_screenshots(targets, output_dir, tools):
    if not tools.get("gowitness"):
        print(Fore.YELLOW + "[-] Gowitness tidak tersedia → skip screenshot" + Style.RESET_ALL)
        return
    
    print(Fore.CYAN + "[+] Taking screenshots..." + Style.RESET_ALL)
    screenshot_dir = f"{output_dir}/screenshots"
    os.makedirs(screenshot_dir, exist_ok=True)
    
    input_file = f"{output_dir}/screenshot_targets.txt"
    with open(input_file, "w") as f:
        f.write("\n".join([t["url"] for t in targets]))
    
    cmd = f"gowitness file {input_file} -s {screenshot_dir} --threads 10"
    run_command(cmd, timeout=600)

# ===================== MAIN =====================
def main():
    parser = argparse.ArgumentParser(description="Civet Pro - Advanced Recon Engine")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("--wordlist", help="Wordlist untuk subdomain brute-force")
    parser.add_argument("-o", "--output", default="civet_output", help="Output directory")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    parser.add_argument("--proxy", help="Proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--mode", choices=["safe", "normal", "aggressive"], default="normal",
                        help="safe = no active vuln scan, normal = recommended, aggressive = full power")
    args = parser.parse_args()

    target = args.url.rstrip("/")
    if not target.startswith("http"):
        target = "https://" + target

    output_dir = f"{args.output}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(output_dir, exist_ok=True)

    logging.basicConfig(
        filename=f"{output_dir}/civet.log",
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    banner()
    print(Fore.RED + "\n[!] HANYA GUNAKAN PADA TARGET YANG ANDA MILIKI ATAU IZINKAN SECARA RESMI!" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[+] Target: {target}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[+] Mode: {args.mode.upper()}" + Style.RESET_ALL)

    tools = check_tools()

    # Discovery
    live_targets = discover_live_targets(target, args.wordlist, tools)
    if not live_targets:
        print(Fore.RED + "[!] Tidak ada target live ditemukan." + Style.RESET_ALL)
        return

    results = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "live_targets": live_targets,
        "nuclei_findings": [],
        "dalfox_findings": [],
        "screenshots": False
    }

    # Active scanning
    if args.mode in ["normal", "aggressive"]:
        results["nuclei_findings"] = run_nuclei_scan(live_targets, output_dir, tools)
        results["dalfox_findings"] = run_dalfox_scan(live_targets, output_dir, tools)
    
    if args.mode == "aggressive":
        take_screenshots(live_targets, output_dir, tools)
        results["screenshots"] = True

    # Save results
    with open(f"{output_dir}/summary.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # Summary
    print(Fore.CYAN + "\n" + "="*60)
    print(Fore.GREEN + "SCAN SELESAI - RINGKASAN")
    print(Fore.CYAN + "="*60)
    print(f"Live targets ditemukan : {len(live_targets)}")
    print(f"Nuclei findings        : {len(results['nuclei_findings'])}")
    print(f"Dalfox findings        : {len(results['dalfox_findings'])}")
    print(f"Screenshots            : {'Ya' if results['screenshots'] else 'Tidak'}")
    print(f"Output directory       : {output_dir}")
    print(Fore.CYAN + "="*60 + Style.RESET_ALL)

if __name__ == "__main__":
    main()
