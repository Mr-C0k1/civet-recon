#!/bin/bash

TARGETS="targets.txt"
OUTPUT_DIR="scan-results"
DATE=$(date +%Y-%m-%d_%H-%M-%S)

mkdir -p $OUTPUT_DIR/$DATE

echo "[+] Menjalankan pemindaian Civet Nobe..."
python3 civet-nobe.py -l $TARGETS \
--stealth --deep-api --auto-exploit \
--xss --sqli --lfi --rce --csrf --ssrf --xxe --redirect \
--subdomain --crawl --js-sink --input-trace \
--payloads all --bypass-waf \
-o $OUTPUT_DIR/$DATE/scan.txt \
--report-pdf --save-api --save-js --save-all

echo "[+] Selesai. Hasil disimpan di: $OUTPUT_DIR/$DATE"
