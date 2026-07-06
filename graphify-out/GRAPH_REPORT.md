# Graph Report - .  (2026-07-06)

## Corpus Check
- Corpus is ~18,021 words - fits in a single context window. You may not need a graph.

## Summary
- 508 nodes · 1272 edges · 16 communities
- Extraction: 97% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 31 edges (avg confidence: 0.83)
- Token cost: 60,163 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Risk Analysis Engine|Risk Analysis Engine]]
- [[_COMMUNITY_HTML Report Rendering|HTML Report Rendering]]
- [[_COMMUNITY_SSH Key Scanner|SSH Key Scanner]]
- [[_COMMUNITY_Core Data Models|Core Data Models]]
- [[_COMMUNITY_Inventory File Handling|Inventory File Handling]]
- [[_COMMUNITY_Target Discovery|Target Discovery]]
- [[_COMMUNITY_Certificate Scanner|Certificate Scanner]]
- [[_COMMUNITY_Errors and Policy Config|Errors and Policy Config]]
- [[_COMMUNITY_Scanner Registry and Encoding|Scanner Registry and Encoding]]
- [[_COMMUNITY_CLI Entry Point|CLI Entry Point]]
- [[_COMMUNITY_Docs and Sample Reports|Docs and Sample Reports]]
- [[_COMMUNITY_JWT Scanner|JWT Scanner]]
- [[_COMMUNITY_Secrets Scanner|Secrets Scanner]]
- [[_COMMUNITY_Inventory Report|Inventory Report]]
- [[_COMMUNITY_JSON Report|JSON Report]]

## God Nodes (most connected - your core abstractions)
1. `ScanResult` - 36 edges
2. `CertificateInfo` - 33 edges
3. `Policy` - 33 edges
4. `AssetInfo` - 27 edges
5. `render()` - 25 edges
6. `evaluate()` - 23 edges
7. `Finding` - 21 edges
8. `default_policy()` - 19 edges
9. `Inventory` - 19 edges
10. `Discovery` - 18 edges

## Surprising Connections (you probably didn't know these)
- `Graphify Knowledge Graph Workflow` --conceptually_related_to--> `Airgap Guardian`  [AMBIGUOUS]
  CLAUDE.md → README.md
- `Test Fixture Note (notes.txt)` --conceptually_related_to--> `Airgap Guardian`  [INFERRED]
  testdata/notes.txt → README.md
- `Scan Report with Policy Section (report2.html)` --implements--> `HTML Report`  [INFERRED]
  assets/report2.html → README.md
- `Scan Report with allow_self_signed Policy (report3.html)` --implements--> `HTML Report`  [INFERRED]
  assets/report3.html → README.md
- `Scan Report (report4.html)` --implements--> `HTML Report`  [INFERRED]
  assets/report4.html → README.md

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Four-Scanner Suite over a Shared Directory Walk** — readme_cert_scanner, readme_ssh_scanner, readme_secrets_scanner, readme_jwt_scanner, readme_single_directory_walk [EXTRACTED 1.00]
- **Inventory-Driven Scan Workflow** — readme_discover_command, readme_inventory_file, readme_scan_command [EXTRACTED 1.00]
- **Generated HTML Report Instances** — assets_report_scan_report, assets_report2_scan_report, assets_report3_scan_report, assets_report4_scan_report, assets_test_scan_report [INFERRED 0.85]

## Communities (16 total, 0 thin omitted)

### Community 0 - "Risk Analysis Engine"
Cohesion: 0.10
Nodes (56): Into, accepts_rsa_2048_and_ignores_non_rsa_keys(), analyze(), analyze_applies_custom_expiration_thresholds(), analyze_populates_asset_findings_and_summary(), analyze_populates_findings_and_risk_score(), asset(), asset_risk_score() (+48 more)

### Community 1 - "HTML Report Rendering"
Cohesion: 0.11
Nodes (43): ScanResult, escape(), escapes_html_in_untrusted_fields(), policy(), push_asset_findings(), push_asset_table(), push_certificate_row(), push_certificate_table() (+35 more)

### Community 2 - "SSH Key Scanner"
Cohesion: 0.11
Nodes (35): AssetInfo, ScanItem, asset(), der_element(), detects_ed25519_private_key(), detects_weak_unencrypted_rsa_private_key(), display_algorithm(), encrypted_pem_key_is_detected_via_headers() (+27 more)

### Community 3 - "Core Data Models"
Cohesion: 0.09
Nodes (30): Cell, Formatter, secret_severity(), AssetDetails, CertificateStatus, days_remaining(), days_remaining_in_future(), days_remaining_in_past_is_negative() (+22 more)

### Community 4 - "Inventory File Handling"
Cohesion: 0.10
Nodes (34): scanners_for(), entry(), Inventory, InventoryFile, loads_inventory_from_file(), merges_duplicate_paths_into_one_walk(), merges_entries_with_same_path(), missing_file_is_a_read_error() (+26 more)

### Community 5 - "Target Discovery"
Cohesion: 0.12
Nodes (31): DirEntry, classifies_ssh_and_secret_directories_by_name(), classify_directory(), classify_file(), discover(), discover_testdata(), discovers_targets_by_asset_type(), Discovery (+23 more)

### Community 6 - "Certificate Scanner"
Cohesion: 0.14
Nodes (29): ASN1Time, Oid, CertificateScanner, discovers_certificates_recursively(), extract_info(), extracts_certificate_fields(), follows_symlinked_certificates(), has_subject_alternative_name() (+21 more)

### Community 7 - "Errors and Policy Config"
Cohesion: 0.09
Nodes (23): InventoryError, PolicyError, Error, PathBuf, String, ScanError, default_policy_matches_builtin_thresholds(), load_reports_missing_file() (+15 more)

### Community 8 - "Scanner Registry and Encoding"
Cohesion: 0.13
Nodes (24): IntoIterator, build_scanners(), decode_base64(), decode_base64url(), decode_sextets(), encode_base64_nopad(), hex_lower(), missing_directory_is_an_error() (+16 more)

### Community 9 - "CLI Entry Point"
Cohesion: 0.17
Nodes (22): ExitCode, Cli, Command, Option, PathBuf, Vec, ScannerKind, build_scanners() (+14 more)

### Community 10 - "Docs and Sample Reports"
Cohesion: 0.13
Nodes (24): Scan Report with Policy Section (report2.html), Scan Report with allow_self_signed Policy (report3.html), Scan Report (report4.html), Scan Report (report.html), Inventory-Based Scan Report (test.html), Graphify Knowledge Graph Workflow, Airgap Guardian, Certificate Scanner (cert) (+16 more)

### Community 11 - "JWT Scanner"
Cohesion: 0.17
Nodes (18): decode_json(), detects_alg_none_with_empty_signature(), encode_token(), handles_binary_and_dedupes(), JwtClaims, JwtScanner, parse_token(), parses_valid_jwt_claims() (+10 more)

### Community 12 - "Secrets Scanner"
Cohesion: 0.15
Nodes (16): detects_aws_access_key(), detects_generic_api_key_and_jwt(), detects_github_token(), detects_pem_private_key_block(), is_binary(), line_number(), redact(), reports_line_numbers_and_dedupes_repeats() (+8 more)

### Community 13 - "Inventory Report"
Cohesion: 0.17
Nodes (19): ParseFailure, asset(), entry_header(), field(), InventoryReport, InventoryReport<'a>, InventorySummary, json_report_has_expected_shape() (+11 more)

### Community 14 - "JSON Report"
Cohesion: 0.24
Nodes (10): InventoryInfo, json_assets_carry_asset_type_tag(), json_report_embeds_inventory_info_with_policy(), json_report_includes_policy_and_scan_fields(), JsonReport, print(), Option, Result (+2 more)

## Ambiguous Edges - Review These
- `Airgap Guardian` → `Graphify Knowledge Graph Workflow`  [AMBIGUOUS]
  CLAUDE.md · relation: conceptually_related_to

## Knowledge Gaps
- **8 isolated node(s):** `InventoryReport<'a>`, `SecretRule`, `PemBlock<'a>`, `WireReader`, `Certificate Scanner (cert)` (+3 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `Airgap Guardian` and `Graphify Knowledge Graph Workflow`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **Why does `ScanResult` connect `HTML Report Rendering` to `Risk Analysis Engine`, `SSH Key Scanner`, `Core Data Models`, `Inventory File Handling`, `Certificate Scanner`, `Scanner Registry and Encoding`, `CLI Entry Point`, `Inventory Report`, `JSON Report`?**
  _High betweenness centrality (0.123) - this node is a cross-community bridge._
- **Why does `Policy` connect `Risk Analysis Engine` to `CLI Entry Point`, `JSON Report`, `HTML Report Rendering`, `Errors and Policy Config`?**
  _High betweenness centrality (0.107) - this node is a cross-community bridge._
- **Why does `AssetType` connect `Inventory File Handling` to `Risk Analysis Engine`, `SSH Key Scanner`, `Core Data Models`, `Target Discovery`, `Scanner Registry and Encoding`, `CLI Entry Point`, `Inventory Report`?**
  _High betweenness centrality (0.083) - this node is a cross-community bridge._
- **What connects `InventoryReport<'a>`, `SecretRule`, `PemBlock<'a>` to the rest of the system?**
  _8 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Risk Analysis Engine` be split into smaller, more focused modules?**
  _Cohesion score 0.10047593865679534 - nodes in this community are weakly interconnected._
- **Should `HTML Report Rendering` be split into smaller, more focused modules?**
  _Cohesion score 0.1091581868640148 - nodes in this community are weakly interconnected._