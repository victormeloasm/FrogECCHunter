# FrogECCHunter Report

- **Title:** Valid secp256k1 tiny-range keygen playground (d=1337)
- **Mode:** `parser`
- **Curve:** `secp256k1`
- **Checks:** `348`
- **Findings:** `1`
- **Recovered keys:** `1`

## Severity summary

- `critical`: 1
- `high`: 0
- `medium`: 0
- `low`: 0

## Category summary

- `keygen`: 1

## Primary findings

### `tiny\_public\_key\_multiple\_scan`

- Fault: **Public key falls in a tiny scalar range**
- Category: `keygen`
- Severity: `critical`
- Recoverability: `R5\_trivial\_or\_lab\_proven`
- Recovered key: `FLAG{1337}`

Evidence

- scan\_bound\_bits = 16
- recovered\_private\_key\_decimal = 1337
- flag = FLAG{1337}
- impact = the audited public key sits inside a tiny bounded range and is recoverable offline

Remediation

- regenerate the long-term key from a full-entropy source and invalidate the weak key immediately
- add key-generation self-tests that reject undersized or patterned private scalars

