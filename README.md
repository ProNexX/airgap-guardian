# Airgap Guardian

Airgap Guardian is an offline-first security tool for air-gapped environments. It runs as a single CLI executable with no network access required.

The current MVP scans directories for X.509 certificates and reports their expiration status. The architecture is prepared for additional offline security scanners in the future.

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
airgap-guardian scan <directory>          # scan and print a table
airgap-guardian scan <directory> --json   # scan and print JSON
airgap-guardian version                   # print version
airgap-guardian --help                    # show help
```

Examples:

```
airgap-guardian scan ./certs
airgap-guardian scan /etc/ssl
airgap-guardian scan ./certs --json
```

## Example Output

```
┌──────────────────┬──────────┬───────────┬────────────┐
│ File             ┆ Status   ┆ Remaining ┆ Expires    │
╞══════════════════╪══════════╪═══════════╪════════════╡
│ certs/api.crt    ┆ OK       ┆ 182 days  ┆ 2027-01-10 │
│ certs/ldap.crt   ┆ Warning  ┆ 14 days   ┆ 2026-07-18 │
│ certs/vpn.crt    ┆ Critical ┆ 2 days    ┆ 2026-07-06 │
│ certs/old.crt    ┆ Expired  ┆ -5 days   ┆ 2026-06-27 │
└──────────────────┴──────────┴───────────┴────────────┘

Certificates scanned: 4
OK: 1
Warning: 1
Critical: 1
Expired: 1
Parse errors: 0
```

Statuses are colored in the terminal: green (OK), yellow (Warning), red (Critical), bright red (Expired).

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
      "issuer": "CN=ldap.example.test",
      "serial_number": "1f:91:cc:50:...",
      "not_before": "2026-07-02T20:06:19Z",
      "not_after": "2026-07-16T20:06:19Z",
      "days_remaining": 14,
      "status": "Warning",
      "signature_algorithm": "sha256WithRSAEncryption",
      "public_key_algorithm": "rsaEncryption",
      "key_size": 2048
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
