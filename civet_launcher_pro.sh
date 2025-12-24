#!/bin/bash
# civet_launcher_pro.sh - Advanced Multi-Tool Recon Launcher (2025 Edition)
# Mendukung: Civet Pro, IMDS Scanner, Domain Scanner, dan Bash Quick Scan

set -euo pipefail

# ===================== CONFIG =====================
TARGETS_FILE="targets.txt"          # File berisi list target (satu per baris)
WORDLIST="wordlists/subdomains-top1000.txt"  # Opsional, ganti jika ada
OUTPUT_BASE="civet_campaigns"
DATE=$(date +%Y-%m-%d_%H-%M-%S)
CAMPAIGN_DIR="$OUTPUT_BASE/campaign_$DATE"
THREADS=10
MODE="normal"  # safe | normal | aggressive

# Tools yang tersedia
TOOLS=(
    "civet_pro:Civet Pro (httpx + nuclei + dalfox + screenshot)"
    "imds_scanner:IMDSv1/v2 SSRF Vulnerability Checker"
    "domain_scanner:Upgraded Domain Scanner (bash + nmap + openssl)"
    "all:Run Semua Tools Secara Berurutan"
)

# ===================== BANNER =====================
banner() {
    echo -e "\033[36m"
    cat << "EOF"
   _____ _ _     __      __  ___ 
  / ____(_) |    \ \    / / / _ \
 | |     _| |_    \ \  / /_| | | |
 | |    | | __|    \ \/ / _| | | |
 | |____| | |_      \  / | | |_| |
  \_____|_|\__|      \/  |_|\___/ 
                                  
         Multi-Tool Recon Launcher Pro
                  Edisi 2025
EOF
    echo -e "\033[0m"
    echo -e "\033[33m[!] HANYA GUNAKAN PADA TARGET YANG ANDA MILIKI ATAU MEMILIKI IZIN RESMI!\033[0m"
    echo
}

# ===================== UTILITIES =====================
log() {
    echo -e "\033[32m[+] $1\033[0m" | tee -a "$CAMPAIGN_DIR/launcher.log"
}

warn() {
    echo -e "\033[33m[!] $1\033[0m" | tee -a "$CAMPAIGN_DIR/launcher.log"
}

error() {
    echo -e "\033[31m[-] $1\033[0m" | tee -a "$CAMPAIGN_DIR/launcher.log"
}

check_file() {
    if [[ ! -f "$1" ]]; then
        error "File tidak ditemukan: $1"
        exit 1
    fi
}

# ===================== TOOL RUNNERS =====================
run_civet_pro() {
    log "Menjalankan Civet Pro (Recon Modern)..."
    local mode_flag=""
    [[ "$MODE" == "safe" ]] && mode_flag="--mode safe"
    [[ "$MODE" == "aggressive" ]] && mode_flag="--mode aggressive"

    python3 civet_pro.py \
        -f "$TARGETS_FILE" \
        $mode_flag \
        --wordlist "$WORDLIST" \
        -o "$CAMPAIGN_DIR/civet_pro" \
        --threads "$THREADS" || warn "Civet Pro selesai dengan error"
}

run_imds_scanner() {
    log "Menjalankan IMDSv1/v2 Vulnerability Scanner..."
    local agg_flag=""
    [[ "$MODE" == "aggressive" ]] && agg_flag="--aggressive"

    python3 imds_scanner.py \
        -f "$TARGETS_FILE" \
        $agg_flag \
        -o "$CAMPAIGN_DIR/imds_results.json" || warn "IMDS Scanner error"
}

run_domain_scanner() {
    log "Menjalankan Quick Domain Scanner (per target)..."
    while IFS= read -r target || [[ -n "$target" ]]; do
        [[ -z "$target" || "$target" =~ ^# ]] && continue
        target=$(echo "$target" | xargs)
        out_dir="$CAMPAIGN_DIR/domain_scan/$(echo "$target" | tr '/' '_')"
        mkdir -p "$out_dir"
        
        ./upgraded-domain-scanner.sh "$target" | tee "$out_dir/report.txt" || true
    done < "$TARGETS_FILE"
}

update_nuclei() {
    if command -v nuclei &> /dev/null; then
        log "Update Nuclei templates..."
        nuclei -update-templates || warn "Gagal update templates"
    fi
}

# ===================== MAIN =====================
main() {
    banner

    # Validasi input
    check_file "$TARGETS_FILE"
    if [[ -n "$WORDLIST" ]]; then
        check_file "$WORDLIST" || warn "Wordlist tidak ditemukan, subdomain brute akan skip"
    fi

    # Buat direktori campaign
    mkdir -p "$CAMPAIGN_DIR"
    echo "Campaign ID: $DATE" > "$CAMPAIGN_DIR/CAMPAIGN_INFO.txt"
    echo "Targets: $TARGETS_FILE" >> "$CAMPAIGN_DIR/CAMPAIGN_INFO.txt"
    echo "Mode: $MODE" >> "$CAMPAIGN_DIR/CAMPAIGN_INFO.txt"
    echo "Threads: $THREADS" >> "$CAMPAIGN_DIR/CAMPAIGN_INFO.txt"

    log "Memulai campaign baru: $DATE"
    log "Total target: $(grep -v '^#' "$TARGETS_FILE" | wc -l)"
    log "Mode operasi: $MODE"

    # Pilih tool
    echo -e "\n\033[36mPilih tool yang akan dijalankan:\033[0m"
    for i in "${!TOOLS[@]}"; do
        echo "  $((i+1))) ${TOOLS[i]#*:}"
    done
    echo
    read -p "Masukkan nomor (1-${#TOOLS[@]}) atau 'all': " choice

    case $choice in
        1) TOOL="civet_pro" ;;
        2) TOOL="imds_scanner" ;;
        3) TOOL="domain_scanner" ;;
        all|*) TOOL="all" ;;
        *) error "Pilihan tidak valid"; exit 1 ;;
    esac

    # Update nuclei dulu
    update_nuclei

    # Jalankan tool
    if [[ "$TOOL" == "all" || "$TOOL" == "civet_pro" ]]; then
        run_civet_pro
    fi

    if [[ "$TOOL" == "all" || "$TOOL" == "imds_scanner" ]]; then
        run_imds_scanner
    fi

    if [[ "$TOOL" == "all" || "$TOOL" == "domain_scanner" ]]; then
        run_domain_scanner
    fi

    # Final summary
    echo
    echo -e "\033[36m"=================================================="\033[0m"
    echo -e "\033[32m               CAMPAIGN SELESAI\033[0m"
    echo -e "\033[36m"=================================================="\033[0m"
    echo -e "Campaign Directory : \033[33m$CAMPAIGN_DIR\033[0m"
    echo -e "Log Launcher       : \033[33m$CAMPAIGN_DIR/launcher.log\033[0m"
    echo -e "Total Direktori    : \033[33m$(find "$CAMPAIGN_DIR" -type f | wc -l) files\033[0m"
    echo -e "\033[36m"=================================================="\033[0m"
    echo -e "\033[33mJangan lupa review hasil secara manual!\033[0m"
}

# ===================== ARGUMENTS =====================
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--targets) TARGETS_FILE="$2"; shift 2 ;;
        -w|--wordlist) WORDLIST="$2"; shift 2 ;;
        -m|--mode) MODE="$2"; shift 2 ;;
        -j|--threads) THREADS="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [-t targets.txt] [-w wordlist.txt] [-m safe|normal|aggressive] [-j threads]"
            exit 0
            ;;
        *) warn "Opsi tidak dikenal: $1"; shift ;;
    esac
done

main
