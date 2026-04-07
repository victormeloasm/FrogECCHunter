#!/usr/bin/env bash
set -euo pipefail

BIN="./fecchunter"
[ -x "$BIN" ] || { echo "fatal: fecchunter not found or not executable"; exit 2; }

$BIN --version
$BIN --self-test
$BIN --explain-check tiny_public_key_multiple_scan >/dev/null
$BIN --all samples/backend_differential_findings.json --strict >/dev/null
$BIN --all samples/tiny_public_key_16bit.json --strict >/dev/null

echo "v26 release checks: PASS"
