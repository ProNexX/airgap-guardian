# Airgap Guardian

Airgap Guardian is an offline-first security tool for air-gapped environments. It runs as a single CLI executable with no network access required.

It scans directories with four scanners:

* **cert** — X.509 certificates: expiration status and common security issues (weak keys, disallowed signature algorithms, self-signed certificates, and more)
* **ssh** — SSH private keys (`id_rsa`, `id_ecdsa`, `id_ed25519`), `authorized_keys`, and `known_hosts`: weak RSA keys, unencrypted private keys, weak public key algorithms, duplicate keys
* **secrets** — file contents matched against conservative regex rules: AWS access keys, GitHub tokens, PEM private key material, generic API keys, JWT strings
* **jwt** — JWT tokens: structure and claims analysis (`alg`, `exp`, `iss`, `aud`) without signature verification, flagging `alg=none`, expired, and long-lived tokens

Every certificate and asset receives a risk score from 0 to 100. All security thresholds are driven by a configurable policy engine: pass a TOML policy file with `--policy`, or rely on built-in defaults. Results are available as a terminal table, JSON, or a standalone HTML report.

Beyond `scan`, the `discover` command quickly locates likely asset locations and writes a reusable `inventory.toml`, and the `inventory` command catalogs every discovered asset in full detail.

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
airgap-guardian scan <directory>                    # scan and print a table
airgap-guardian scan <directory> --json             # scan and print JSON
airgap-guardian scan <directory> --html <file>      # also write an HTML report
airgap-guardian scan <directory> --policy <file>    # scan with a custom policy
airgap-guardian scan <directory> --scanners <list>  # run only selected scanners
airgap-guardian discover <directory>                # locate scan targets, write inventory.toml
airgap-guardian inventory <directory>               # catalog every security asset
airgap-guardian version                             # print version
airgap-guardian --help                              # show help
```

Examples:

```
airgap-guardian scan ./certs
airgap-guardian scan /etc/ssl
airgap-guardian scan ./certs --json
airgap-guardian scan ./certs --html report.html
airgap-guardian scan ./certs --policy policy.toml
airgap-guardian scan ./certs --policy policy.toml --json --html report.html
airgap-guardian scan /etc --scanners cert,ssh
```

`--html` can be combined with either output mode; the confirmation message is printed to stderr so JSON on stdout stays clean. `--scanners` accepts a comma-separated subset of `cert`, `ssh`, `secrets`, `jwt`; all scanners run by default.

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
    - [Critical] RSA key is only 1024 bits (policy requires at least 2048).
    - [Warning] Signature algorithm sha1WithRSAEncryption is not allowed by policy.
    - Expires in 2 days

┌────────────────┬────────┬──────────────────────────────────────────┬──────┬──────────┐
│ File           ┆ Type   ┆ Asset                                    ┆ Risk ┆ Findings │
╞════════════════╪════════╪══════════════════════════════════════════╪══════╪══════════╡
│ home/.ssh/id_rsa ┆ ssh  ┆ RSA private key (1024 bits), unencrypted ┆ 55   ┆ 2        │
│ app/config.env ┆ secret ┆ AWS access key                           ┆ 40   ┆ 1        │
└────────────────┴────────┴──────────────────────────────────────────┴──────┴──────────┘

home/.ssh/id_rsa (ssh)
  Asset: RSA private key (1024 bits), unencrypted
  Risk: 55
  Findings:
    - [Critical] RSA key is only 1024 bits (policy requires at least 2048).
    - [Warning] Private key is not protected by a passphrase.

Certificates scanned: 4
OK: 1
Warning: 1
Critical: 1
Expired: 1
Assets discovered: 2
Asset warnings: 1
Asset critical: 1
Parse errors: 0
```

After the certificate table, a details section is printed for each certificate that has findings or a non-OK expiration status. SSH keys, secrets, and JWT tokens follow in an asset table with their own findings sections. Statuses are colored in the terminal: green (OK), yellow (Warning), red (Critical), bright red (Expired). Secret matches are never printed in full; previews are redacted.

With `--json`:

```json
{
  "summary": {
    "total": 1,
    "ok": 0,
    "warning": 1,
    "critical": 0,
    "expired": 0,
    "parse_errors": 0,
    "assets": 1,
    "asset_warning": 0,
    "asset_critical": 1
  },
  "certificates": [
    {
      "asset_type": "cert",
      "path": "certs/ldap.crt",
      "subject": "CN=ldap.example.test",
      "issuer": "CN=Example Internal CA",
      "serial_number": "1f:91:cc:50:...",
      "fingerprint_sha256": "a25f648f5f5a624defba9027523e87b55da9b99fbeaffc08ff9cc041ee456916",
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
  "assets": [
    {
      "asset_type": "secret",
      "path": "app/config.env",
      "description": "AWS access key",
      "details": {
        "kind": "secret",
        "rule": "aws_access_key",
        "line": 2,
        "preview": "AKIA****MPLE"
      },
      "risk_score": 40,
      "findings": [
        {
          "severity": "Critical",
          "rule": "aws_access_key",
          "message": "AWS access key detected on line 2."
        }
      ]
    }
  ],
  "errors": [],
  "policy": {
    "warning_days": 30,
    "critical_days": 7,
    "min_rsa_key_size": 2048,
    "max_certificate_lifetime_days": 398,
    "allow_self_signed": false,
    "required_subject_alternative_name": true,
    "allowed_signature_algorithms": [
      "sha256WithRSAEncryption",
      "sha384WithRSAEncryption",
      "sha512WithRSAEncryption",
      "ecdsa-with-SHA256",
      "ecdsa-with-SHA384",
      "ecdsa-with-SHA512"
    ]
  }
}
```

The `policy` object always contains the effective values used for the scan, whether they came from a policy file or from the built-in defaults. Every entry carries an `asset_type` (`cert`, `ssh`, `secret`, or `jwt`); non-certificate assets appear in the `assets` array with type-specific `details`. Certificates carry a `fingerprint_sha256` (hex SHA-256 of the DER encoding); OpenSSH-format private keys carry an OpenSSH-style `fingerprint` (`SHA256:` + base64 of the public key hash).

## Discovering Scan Targets

`discover` searches a directory tree for locations that likely contain security assets and writes a reusable inventory configuration file. It does not fully analyze files — classification is metadata-first (file names, extensions, directory names); only small text files are probed for JWT structures.

```
airgap-guardian discover /
airgap-guardian discover /etc
airgap-guardian discover / --output inventory.toml
airgap-guardian discover / --json
airgap-guardian discover / --follow-symlinks --max-depth 4
```

| Option | Meaning |
|--------|---------|
| `--output <file>` | Inventory file to write (default: `inventory.toml`) |
| `--json` | Print discovered targets as JSON instead of the terminal listing |
| `--follow-symlinks` | Follow symbolic links while searching (off by default) |
| `--max-depth <n>` | Maximum directory depth to descend into |

Locations are detected per asset type:

* **Certificates** — files with extensions `.pem`, `.crt`, `.cer`, `.der`, `.p7b`, `.p7c`, `.p12`, `.pfx`
* **SSH** — `.ssh` directories and files named `id_rsa`, `id_ed25519`, `id_ecdsa`, `authorized_keys`, `known_hosts`
* **Secrets** — directories named `config`, `configs`, `conf`, `etc`, `secrets`; files named `.env`, `*.env`, `config.json`, `config.yaml`, `config.yml`, `settings.json`, `settings.toml`, `docker-compose.yml`, `kubeconfig`
* **JWT** — text files smaller than 1 MiB containing a JWT structure

Terminal output lists the discovered locations per asset type followed by a summary. The generated inventory file contains one `[[scan]]` entry per directory, with duplicate paths merged, scanner lists combined, paths normalized to absolute form, and entries sorted alphabetically:

```toml
version = 1

[[scan]]
path = "/etc/ssl"
scanners = ["cert"]

[[scan]]
path = "/opt/app"
scanners = ["cert", "secret", "jwt"]

[[scan]]
path = "/root/.ssh"
scanners = ["ssh"]
```

With `--json` the same targets are printed as `{"version": 1, "targets": [{"path": ..., "scanners": [...]}]}`; the inventory file is written either way, and the confirmation message goes to stderr so stdout stays clean.

## Asset Inventory

`inventory` performs a full scan that catalogs every discovered security asset. Unlike `scan`, which reports findings, `inventory` records every asset with its complete details. It reuses the same scanners and single-pass directory walk.

```
airgap-guardian inventory /
airgap-guardian inventory /etc
airgap-guardian inventory /opt --json
airgap-guardian inventory /opt --html report.html
```

Each record includes:

* **Certificates** — path, subject, issuer, serial, SHA-256 fingerprint, algorithm, key size, validity, expiration, CA flag, self-signed flag, risk score
* **SSH keys** — path, type, key bits, encryption status, fingerprint (OpenSSH format keys), `authorized_keys` entries, `known_hosts` entry count
* **Secrets** — path, matched rule, line number, redacted preview
* **JWT** — path, algorithm, issuer, audience, expiration, risk score

```
Asset Inventory

Certificates

/etc/ssl/server.crt
  Subject      CN=server.example
  Issuer       CN=Internal CA
  Serial       6d:2a:7b:...
  Fingerprint  SHA256:925332b0...
  Algorithm    sha256WithRSAEncryption
  Key size     2048 bits
  Valid from   2026-07-02
  Expires      2027-05-12 (OK)
  CA           No
  Self-signed  No
  Risk         10

SSH Keys

/root/.ssh/id_rsa
  Type         RSA
  Bits         4096
  Encrypted    Yes
  Fingerprint  SHA256:qSLgv1Y2...

...

Summary

Certificates      82
SSH Keys          14
Secrets           8
JWT Tokens        5
Parse errors      0
```

With `--json`, the inventory is emitted as `{"summary": {"certificates": ..., "ssh_keys": ..., "secrets": ..., "jwt": ...}, "certificates": [...], "ssh": [...], "secrets": [...], "jwt": [...], "errors": [...]}`, reusing the same per-asset JSON structures as `scan`. `--html` writes the standard HTML report. Risk scores are computed with the built-in default policy. `inventory` exits with 0 on success regardless of findings; failure exit codes (4–6) match `scan`.

## Supported Certificate Formats

Files with the following extensions are scanned (case-insensitive):

| Extension | Encoding |
|-----------|----------|
| `.pem`    | PEM (multiple certificates per file supported) |
| `.crt`    | PEM or DER (detected automatically) |
| `.cer`    | PEM or DER (detected automatically) |
| `.der`    | DER |

All other files are ignored by the certificate scanner. Files that cannot be parsed are reported as parse errors without aborting the scan.

## Scanners

All scanners share one directory walk; each file is read at most once and offered to every scanner that can process it. A failure in one file or scanner never aborts the scan.

### SSH Scanner

Processes files named `id_rsa`, `id_ecdsa`, `id_ed25519`, `authorized_keys`, and `known_hosts`.

* Private keys: key type identification (OpenSSH and legacy PEM formats), RSA key size, and passphrase protection (format heuristics: OpenSSH cipher name, PEM `Proc-Type: 4,ENCRYPTED` headers)
* `authorized_keys`: per-entry algorithm and key size, weak algorithms (`ssh-rsa`, `ssh-dss`), duplicate keys
* `known_hosts`: basic parsing (entry count) only

### Secrets Scanner

Matches file contents against conservative regex rules: `aws_access_key`, `github_token`, `private_key`, `generic_api_key`, and `jwt_token`. Binary files (NUL-byte heuristic) and files larger than 1 MiB are skipped, as are SSH key files (owned by the SSH scanner). Matches are deduplicated per file and previews are redacted.

### JWT Scanner

Detects `header.payload.signature` structures, decodes header and payload (base64url), and extracts `alg`, `exp`, `iss`, and `aud`. Signatures are **not** verified. Strings that do not decode to valid JSON are silently ignored.

## Policy Engine

All security thresholds are resolved from a policy before scanning begins. The policy is loaded once, validated, and passed to the analyzer, so a report can always be interpreted from its embedded policy alone.

Load a custom policy with `--policy`:

```
airgap-guardian scan ./certs --policy policy.toml
```

If no policy file is supplied, the built-in default policy is used, which reproduces the behavior documented below.

### Configuration Format

Policies are TOML files. All fields are optional; omitted fields fall back to their defaults. Unknown fields are rejected to catch typos.

Example `policy.toml`:

```toml
warning_days = 30
critical_days = 7

min_rsa_key_size = 2048

max_certificate_lifetime_days = 398

allow_self_signed = false

required_subject_alternative_name = true

allowed_signature_algorithms = [
    "sha256WithRSAEncryption",
    "sha384WithRSAEncryption",
    "sha512WithRSAEncryption",
    "ecdsa-with-SHA256",
    "ecdsa-with-SHA384",
    "ecdsa-with-SHA512"
]
```

### Default Policy

| Field | Default | Meaning |
|-------|---------|---------|
| `warning_days` | 30 | Warning status when expiring within this many days |
| `critical_days` | 7 | Critical status when expiring within this many days |
| `min_rsa_key_size` | 2048 | Minimum accepted RSA key size in bits |
| `max_certificate_lifetime_days` | 398 | Maximum accepted certificate lifetime |
| `allow_self_signed` | false | Whether self-signed certificates are accepted without a finding |
| `required_subject_alternative_name` | true | Whether a missing SAN produces a finding |
| `allowed_signature_algorithms` | SHA-256/384/512 with RSA or ECDSA | Signature algorithms accepted without a finding (case-insensitive) |

### Validation

Policies are validated before the scan starts. A policy is rejected when:

* `critical_days` is negative
* `warning_days` is smaller than `critical_days`
* `min_rsa_key_size` is smaller than 1024
* `max_certificate_lifetime_days` is not positive
* `allowed_signature_algorithms` is empty

Invalid, unreadable, or malformed policy files fail fast with a clear error message and exit code 7; the scan is not performed. All validation violations are reported in a single message.

### Example: Scanning with a Stricter Policy

```toml
# strict.toml
warning_days = 90
critical_days = 30
min_rsa_key_size = 4096
```

```
$ airgap-guardian scan ./certs --policy strict.toml

certs/api.crt
  Status: Warning
  Risk: 45
  Findings:
    - [Critical] RSA key is only 2048 bits (policy requires at least 4096).
    - Expires in 60 days
```

A certificate that is fine under the default policy (2048-bit RSA, 60 days remaining) is now flagged: the RSA key is below the stricter minimum and the expiration falls inside the widened warning window. JSON and HTML reports produced with this policy embed these effective values.

## Expiration Status

Thresholds come from the policy (`warning_days`, `critical_days`); the table shows the defaults.

| Status   | Rule |
|----------|------|
| Expired  | `not_after` is in the past |
| Critical | expires within 7 days |
| Warning  | expires within 30 days |
| OK       | more than 30 days remaining |

## Security Checks

Each certificate is analyzed for common security issues. Findings are reported separately from the expiration status. Conditions are driven by the active policy; the table shows the defaults.

| Rule | Condition | Severity |
|------|-----------|----------|
| `weak_signature` | signature algorithm not in `allowed_signature_algorithms` | Warning |
| `weak_rsa` | RSA key smaller than `min_rsa_key_size` (2048 bits) | Critical |
| `self_signed` | subject equals issuer, unless `allow_self_signed = true` | Warning (Info if the certificate is a CA) |
| `invalid_validity` | `not_before` is after `not_after` | Critical |
| `long_validity` | valid for more than `max_certificate_lifetime_days` (398 days) | Warning |
| `missing_san` | no Subject Alternative Name extension, if `required_subject_alternative_name = true` | Warning |

Asset checks reuse the same policy thresholds:

| Rule | Condition | Severity |
|------|-----------|----------|
| `ssh_weak_rsa` | SSH RSA key smaller than `min_rsa_key_size` | Critical |
| `ssh_unencrypted_key` | SSH private key without passphrase protection | Warning |
| `ssh_weak_algorithm` | `authorized_keys` entry uses `ssh-rsa` or `ssh-dss` | Warning |
| `ssh_duplicate_key` | identical key appears more than once in `authorized_keys` | Warning |
| `aws_access_key` | AWS access key ID detected | Critical |
| `github_token` | GitHub token detected | Critical |
| `private_key` | PEM private key material detected | Critical |
| `generic_api_key` | generic API key assignment detected | Warning |
| `jwt_token` | JWT string detected (cross-reference with the jwt scanner) | Warning |
| `jwt_alg_none` | token uses `alg: none` | Critical |
| `jwt_expired` | `exp` is in the past | Warning |
| `jwt_long_lived` | `exp` is more than `max_certificate_lifetime_days` away | Warning |

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

Assets are scored from their findings alone:

| Factor | Points |
|--------|--------|
| JWT `alg: none` | +60 |
| Private key material found | +50 |
| AWS access key / generic API key found | +40 |
| GitHub token / JWT string found | +30 |
| Unencrypted SSH private key | +30 |
| Expired JWT | +30 |
| Weak SSH RSA key | +25 |
| Weak `authorized_keys` algorithm | +15 |
| Long-lived JWT | +15 |
| Duplicate `authorized_keys` entry | +10 |

The total is capped at 100. The score appears in the terminal tables, the JSON output (`risk_score`), and the HTML report.

## HTML Report

`--html <file>` writes a standalone, fully offline HTML report: a single file with embedded CSS, no JavaScript, and no external assets. It contains the scan summary, statistics cards, a "Scan Policy" section with the effective configuration, a color-coded certificate table with risk scores, a findings section for flagged certificates, asset and asset-findings sections for the other scanners, parse errors, and the generation timestamp. Because the active policy is embedded, reports remain interpretable later without the original policy file.

## Exit Codes

For `scan`, the highest severity encountered is returned. `discover` and `inventory` return 0 on success and share the failure codes (4–6).

| Code | Meaning |
|------|---------|
| 0 | No warnings or errors |
| 1 | Warnings present (including parse errors and Warning-level asset findings) |
| 2 | Critical certificates or Critical-level asset findings found |
| 3 | Expired certificates found |
| 4 | Invalid CLI usage |
| 5 | Directory not found |
| 6 | Unexpected runtime error |
| 7 | Invalid or unreadable policy file |

## Development

```
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

Sample certificates, SSH keys, and secret fixtures for tests live under `testdata/`.
