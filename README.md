# Airgap Guardian

Airgap Guardian is an offline-first security tool for air-gapped environments. It runs as a single CLI executable with no network access required.

It scans directories for X.509 certificates, reports their expiration status, and analyzes each certificate for common security issues (weak keys, weak signature algorithms, self-signed certificates, and more). Every certificate receives a risk score from 0 to 100. Results are available as a terminal table, JSON, or a standalone HTML report. The architecture is prepared for additional offline security scanners in the future.

## Installation

Requires a stable Rust toolchain (https://rustup.rs).

```
cargo install --path .
```

## Build

```
cargo build --release
```

The binary is produced at `target/release/airgap-guardian`.

## Usage

```
airgap-guardian scan <directory>                # scan and print a table
airgap-guardian scan <directory> --json         # scan and print JSON
airgap-guardian scan <directory> --html <file>  # also write an HTML report
airgap-guardian version                         # print version
airgap-guardian --help                          # show help
```

Examples:

```
airgap-guardian scan ./certs
airgap-guardian scan /etc/ssl
airgap-guardian scan ./certs --json
airgap-guardian scan ./certs --html report.html
airgap-guardian scan ./certs --json --html report.html
```

`--html` can be combined with either output mode; the confirmation message is printed to stderr so JSON on stdout stays clean.

## Example Output

```
┌──────────────────┬──────────┬──────┬───────────┬────────────┐
│ File             ┆ Status   ┆ Risk ┆ Remaining ┆ Expires    │
╞══════════════════╪══════════╪══════╪═══════════╪════════════╡
│ certs/api.crt    ┆ OK       ┆ 0    ┆ 182 days  ┆ 2027-01-10 │
│ certs/ldap.crt   ┆ Warning  ┆ 30   ┆ 14 days   ┆ 2026-07-18 │
│ certs/vpn.crt    ┆ Critical ┆ 85   ┆ 2 days    ┆ 2026-07-06 │
│ certs/old.crt    ┆ Expired  ┆ 50   ┆ -5 days   ┆ 2026-06-27 │
└──────────────────┴──────────┴──────┴───────────┴────────────┘

certs/vpn.crt
  Status: Critical
  Risk: 85
  Findings:
    - [Critical] RSA key is only 1024 bits.
    - [Warning] Weak signature algorithm (sha1WithRSAEncryption).
    - Expires in 2 days

Certificates scanned: 4
OK: 1
Warning: 1
Critical: 1
Expired: 1
Parse errors: 0
```

After the table, a details section is printed for each certificate that has findings or a non-OK expiration status. Statuses are colored in the terminal: green (OK), yellow (Warning), red (Critical), bright red (Expired).

With `--json`:

```json
{
  "summary": {
    "total": 1,
    "ok": 0,
    "warning": 1,
    "critical": 0,
    "expired": 0,
    "parse_errors": 0
  },
  "certificates": [
    {
      "path": "certs/ldap.crt",
      "subject": "CN=ldap.example.test",
      "issuer": "CN=Example Internal CA",
      "serial_number": "1f:91:cc:50:...",
      "not_before": "2026-07-02T20:06:19Z",
      "not_after": "2026-07-16T20:06:19Z",
      "days_remaining": 14,
      "status": "Warning",
      "signature_algorithm": "sha256WithRSAEncryption",
      "public_key_algorithm": "rsaEncryption",
      "key_size": 2048,
      "is_ca": false,
      "has_san": false,
      "risk_score": 30,
      "findings": [
        {
          "severity": "Warning",
          "rule": "missing_san",
          "message": "Certificate has no Subject Alternative Name."
        }
      ]
    }
  ],
  "errors": []
}
```

## Supported Certificate Formats

Files with the following extensions are scanned (case-insensitive):

| Extension | Encoding |
|-----------|----------|
| `.pem`    | PEM (multiple certificates per file supported) |
| `.crt`    | PEM or DER (detected automatically) |
| `.cer`    | PEM or DER (detected automatically) |
| `.der`    | DER |

All other files are ignored. Files that cannot be parsed are reported as parse errors without aborting the scan.

## Expiration Status

| Status   | Rule |
|----------|------|
| Expired  | `not_after` is in the past |
| Critical | expires within 7 days |
| Warning  | expires within 30 days |
| OK       | more than 30 days remaining |

## Security Checks

Each certificate is analyzed for common security issues. Findings are reported separately from the expiration status.

| Rule | Condition | Severity |
|------|-----------|----------|
| `weak_signature` | signed with MD5 or SHA-1 | Warning |
| `weak_rsa` | RSA key smaller than 2048 bits | Critical |
| `self_signed` | subject equals issuer | Warning (Info if the certificate is a CA) |
| `invalid_validity` | `not_before` is after `not_after` | Critical |
| `long_validity` | valid for more than 398 days | Warning |
| `missing_san` | no Subject Alternative Name extension | Warning |

## Risk Score

Every certificate receives a risk score from 0 to 100, computed from its expiration status and findings:

| Factor | Points |
|--------|--------|
| Expired | +50 |
| Critical expiration | +40 |
| Warning expiration | +20 |
| Invalid validity period | +50 |
| Weak RSA key | +25 |
| Weak signature algorithm | +20 |
| Self-signed | +10 |
| Missing SAN | +10 |
| Long validity | +5 |

The total is capped at 100. The score appears in the terminal table, the JSON output (`risk_score`), and the HTML report.

## HTML Report

`--html <file>` writes a standalone, fully offline HTML report: a single file with embedded CSS, no JavaScript, and no external assets. It contains the scan summary, statistics cards, a color-coded certificate table with risk scores, a findings section for flagged certificates, parse errors, and the generation timestamp.

## Exit Codes

The highest severity encountered is returned.

| Code | Meaning |
|------|---------|
| 0 | No warnings or errors |
| 1 | Warnings present (including parse errors) |
| 2 | Critical certificates found |
| 3 | Expired certificates found |
| 4 | Invalid CLI usage |
| 5 | Directory not found |
| 6 | Unexpected runtime error |

## Development

```
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

Sample certificates for tests live under `testdata/`.
