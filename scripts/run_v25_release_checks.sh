#!/usr/bin/env bash
set -euo pipefail

BIN="./fecchunter"
OUT="AUDITTEST_V25"
mkdir -p "$OUT/reports" "$OUT/evidence" "$OUT/logs"

"$BIN" --version | tee "$OUT/logs/version.txt"
"$BIN" --list-curves | tee "$OUT/logs/list-curves.txt"

"$BIN" --all samples/related_nonce_delta1.json --report-json "$OUT/reports/related.json" --report-txt "$OUT/reports/related.txt" > "$OUT/logs/related.stdout.txt" 2> "$OUT/logs/related.stderr.txt"
"$BIN" --all samples/v22_spki_backend_suite.json --report-json "$OUT/reports/spki.json" --report-txt "$OUT/reports/spki.txt" > "$OUT/logs/spki.stdout.txt" 2> "$OUT/logs/spki.stderr.txt"
"$BIN" --all-dir samples --report-dir "$OUT/reports/batch" --evidence-pack "$OUT/evidence/batch" > "$OUT/logs/all-dir.stdout.txt" 2> "$OUT/logs/all-dir.stderr.txt"
