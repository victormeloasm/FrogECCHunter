# FrogECCHunter

## v30 final hardening release

- `--all` and `--all-dir` remain the stable primary audit commands
- package reports **348 total checks** in the current full sweep
- stronger **hardening and compatibility** around generated JSON templates, passive-analysis flows, batch summaries, and evidence packs
- generated JSON from `--make-json-from-pubkey` is now **neutral by default**, without opinionated RNG or oracle placeholders that could mislead auditors
- malformed public keys scaffolded with `--allow-invalid-pubkey` continue cleanly into passive parser/oracle/provenance analysis
- raw-family templates such as `Ed25519` and `X25519` now stay consistent with `raw_hex` and passive-analysis expectations
- `--list-curves` prints named curves with OIDs and `--version` reports the active capability profile
- optional runtime context labels: `--backend` and `--diff-backends`
- `--self-test` now validates pubkey-to-JSON conversion internally for compressed SEC1, uncompressed SEC1, PEM/SPKI, raw-family, and invalid-preserved inputs
- bundled playground samples now include clean public-key cases, tiny-range keygen cases, invalid-preserved parser cases, and passive raw-family cases

FrogECCHunter is an offline ECC weakness lab for owned material, challenge files, defensive implementation reviews, and internal red-team rehearsal on synthetic data.

This build stays intentionally offline. It does not probe remote services. It consumes JSON challenge descriptions, runs a broad `--all` sweep, emits machine-readable JSON, scans a whole directory of cases, generates challenge JSON from a supplied public key, and emits reproducible evidence packs for serious review workflows.

## What changed in this build

- the suite keeps the 300+ structural milestone and reports **348 total checks** in the default full sweep
- `--make-json-from-pubkey` now emits **neutral templates** by default for valid keys, which is safer for client-facing workflows and GitHub examples
- invalid public-key scaffolds stay analysis-ready for parser, oracle, and provenance paths without crashing the main sweep
- batch summaries now include **overlap group counts** for repeated pubkeys, `r` values, hashes, and recovered keys
- `--version` makes it explicit that active algebra is currently short-Weierstrass and raw families use passive-analysis paths
- `--evidence-pack` metadata now identifies this release as **v30**
- single-case and batch runs emit Markdown and SARIF alongside TXT and JSON reports

## Build requirements

- g++ or clang++
- GMP and GMP C++ bindings
- Boost headers for `property_tree`

## Build

Fast portable build:

```bash
g++ -std=c++23 -O2 src/*.cpp -o fecchunter -lgmpxx -lgmp
```

Ubuntu dependencies:

```bash
sudo apt update
sudo apt install -y g++ make libgmp-dev libboost-all-dev
```

If you want to try the package Makefile instead:

```bash
make ultra
```

## Usage

Run the full sweep on one case:

```bash
./fecchunter --all samples/related_nonce_delta1.json
./fecchunter --all samples/backend_differential_findings.json
./fecchunter --all samples/valid_pubkey_secp256k1_clean.json
./fecchunter --all samples/valid_pubkey_secp256k1_1337.json
```

Show every PASS, MISS, SKIP, and INFO line:

```bash
./fecchunter --all samples/backend_differential_findings.json --verbose
```

Focus on backend findings only:

```bash
./fecchunter --all samples/backend_differential_findings.json --family backend --severity-min medium --verbose
```

Generate a reproducible evidence bundle:

```bash
./fecchunter --all samples/backend_differential_findings.json \
  --report-json build/backend.json \
  --evidence-pack build/evidence_backend
```

Sweep a whole directory:

```bash
./fecchunter --all-dir samples --report-dir build/reports
```

Playground samples added in this build:

```text
samples/valid_pubkey_secp256k1_clean.json
samples/valid_pubkey_secp256k1_1337.json
samples/valid_pubkey_secp256r1_clean.json
samples/invalid_pubkey_template_playground.json
samples/raw_family_ed25519_playground.json
samples/raw_family_x448_playground.json
```

Sweep a directory but keep only parser and backend findings at medium+ severity:

```bash
./fecchunter --all-dir samples \
  --report-dir build/reports \
  --family parser,backend \
  --severity-min medium \
  --evidence-pack build/evidence_batch
```

Generate a starter challenge JSON from a named curve public key:

```bash
./fecchunter --make-json-from-pubkey secp256k1 \
  0272588CF4BC7FB52A68D5C81B83643A96A881ACFD9359D268BF675C0173B46920 \
  build/from_pubkey.json --mode ecdsa --backend openssl --diff-backends openssl,libsecp256k1
```

Generate a parser/oracle scaffold from malformed SEC1 or SPKI bytes without forcing point validation:

```bash
./fecchunter --make-json-from-pubkey secp256k1 @bad_pubkey.pem build/bad_pubkey.json \
  --mode parser --allow-invalid-pubkey
```

Generate a starter challenge JSON for a custom short-Weierstrass curve:

```bash
./fecchunter --make-json-from-pubkey custom \
  0272588CF4BC7FB52A68D5C81B83643A96A881ACFD9359D268BF675C0173B46920 \
  build/custom.json --mode parser \
  --p FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F \
  --a 0 \
  --b 7 \
  --gx 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 \
  --gy 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8 \
  --n FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 \
  --h 1
```

Accepted public-key formats for `--make-json-from-pubkey`:

- compressed SEC1 hex starting with `02` or `03`
- uncompressed SEC1 hex starting with `04`
- `x:y` as two hexadecimal coordinates
- `@file` to read the pubkey text from a file
- malformed SEC1/SPKI blobs together with `--allow-invalid-pubkey` to preserve bytes for parser/oracle templates

## JSON format

The loader expects JSON like this:

```json
{
  "title": "Small nonce over secp256k1",
  "mode": "ecdsa",
  "curve": { "name": "secp256k1" },
  "public_key": { "compressed": "02..." },
  "constraints": {
    "nonce_max_bits": 30,
    "privkey_max_bits": 0,
    "related_delta_max": 8,
    "related_a_abs_max": 0,
    "related_b_abs_max": 0,
    "unix_time_min": 0,
    "unix_time_max": 0
  },
  "facts": {
    "rng.source": "counter",
    "nonce.rfc6979": "false",
    "validation.subgroup_check": "false",
    "backend.diff.pubkey_validation": "true"
  },
  "signatures": [
    {
      "message": "optional text",
      "hash_hex": "SHA-256 digest as hex",
      "r": "hex",
      "s": "hex"
    }
  ]
}
```

Facts are flattened key-value hints that allow the suite to name risk classes even when a full algebraic exploit is not possible from the JSON alone.

For raw-family scaffolds such as Ed25519 and X25519, generated templates use `public_key.raw_hex`. Active algebra remains short-Weierstrass in this build, so raw-family templates are primarily for parser, oracle, provenance, and evidence workflows.

## Included sample additions

- `samples/backend_differential_findings.json`

## Design note

This build is honest about what it can do.

- active algebra in this package still targets the short-Weierstrass path for active algebra; raw families now have cleaner JSON scaffolding and clearer compatibility notes
- backend-differential findings are driven by supplied audit evidence, not by dynamic loading of multiple crypto libraries inside the tool
- Ed25519, Ed448, X25519, and X448 remain scaffold/template families here

## License

MIT


List supported curves and OIDs:

```bash
./fecchunter --list-curves
```

Generate a template directly from a PEM public key and let the tool resolve the curve from SPKI:

```bash
./fecchunter --make-json-from-pubkey auto @pubkey.pem build/from_pem.json --mode parser
```

Generate Markdown and SARIF alongside the normal reports:

```bash
./fecchunter --all samples/v22_spki_backend_suite.json \
  --report-json build/v22.json \
  --report-md build/v22.md \
  --report-sarif build/v22.sarif
```


## v30 hardening notes

- `--all` now continues in a passive analysis path for malformed public keys scaffolded with `--allow-invalid-pubkey`.
- Raw families such as `X25519` and `Ed25519` can now be loaded into `--all` for parser/oracle/provenance workflows without crashing the run.
- Reports explicitly say when active algebra was unavailable and passive analysis was used instead.


## Version

```bash
./fecchunter --version
```
