#!/usr/bin/env bash
set -euo pipefail
BIN="./fecchunter"
[ -x "$BIN" ] || { echo "fatal: fecchunter not found or not executable"; exit 2; }
$BIN --version
$BIN --self-test AUDITTEST_V28
$BIN --explain-check tiny_public_key_multiple_scan >/dev/null
$BIN --all samples/backend_differential_findings.json --strict >/dev/null
$BIN --all samples/valid_pubkey_secp256k1_clean.json --strict >/dev/null
$BIN --all samples/valid_pubkey_secp256k1_1337.json --strict >/dev/null
echo "v30 release checks: PASS"
