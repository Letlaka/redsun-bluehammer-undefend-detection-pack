# Changelog

## 2026-05-05

### Added

- `CrossFamily` detection package with shared hunting for observed tooling execution, BeigeBurrow follow-on tunnel activity, and recon commands near suspicious tooling.
- `Exposure/01_bluehammer_defender_platform_exposure.kql` and `Exposure/README.md` as tenant-verified platform exposure reporting templates.
- `ExternalTelemetry/README.md` for documentation-only VPN and SIEM correlation indicators.
- `SOURCES.md` for source traceability across CVE facts, IOC additions, and mitigation references.
- `IOCS.md` for observed indicator confidence and usage guidance.
- `MITIGATIONS.md`, `ATTACK_MAPPING.md`, and `DEPLOYMENT_GUIDE.md` for source-backed mitigation, ATT&CK, and rollout guidance.
- `UnDefend/09_undefend_defender_health_and_signature_staleness.kql` for correlated Defender health and staleness hunting after suspicious access.
- Conservative production query variants under `BlueHammer/production/`, `RedSun/production/`, `UnDefend/production/`, and `CrossFamily/production/`.

### Changed

- Corrected the documented BlueHammer fixed Defender Antimalware Platform baseline from `4.18.26050.3011` to `4.18.26030.3011`.
- Updated root and package documentation to reflect the 2026-05-05 source review and the behavior-focused status of RedSun and UnDefend.
- Expanded BlueHammer Stage 7 detection-name matching to include `Exploit:Win32/DfndrPEBluHmr.BZ`.
- Extended CrossFamily hunting to preserve nearby BlueHammer `.BZ`, EICAR, and observed aggressive `undef.exe` command-line context.
- Added `// DetectionMetadata:` blocks across the KQL inventory and expanded repository validation to enforce metadata, production placement, and IOC source mapping.
- Extended repository validation and contribution metadata to include `CrossFamily`, `Exposure`, and the production query split.

### Validation

- Static repository validation now covers metadata blocks, support-document presence, production placement, IOC source mapping, `Exposure/`, and `CrossFamily` with the same numbering, stage-alignment, and README-coverage rules as the existing packages.
- Confirmed `4.18.26050.3011` no longer appears as the active BlueHammer fixed baseline in repository guidance; remaining references are historical or explicitly marked non-authoritative.

## 2026-04-20

### Added

- RedSun standalone stages for Cloud Files sync-root registration, Storage Tiers COM activation markers, and Microsoft Defender RedSun detection-name telemetry.
- BlueHammer standalone stage for Microsoft Defender BlueHammer detection-name telemetry.
- Repository validation checks for standalone-to-full-chain stage alignment and package README KQL coverage.
- Repository-level README covering project purpose, layout, Defender XDR table dependencies, validation workflow, production deployment guidance, performance notes, and maintenance expectations.
- Folder-specific READMEs for `RedSun`, `BlueHammer`, and `UnDefend`.
- Repository governance and support documentation:
  - `CONTRIBUTING.md`
  - `CODE_OF_CONDUCT.md`
  - `SECURITY.md`
  - `SUPPORT.md`
  - `DISCLAIMER.md`
  - `LICENSE.md`
  - `NOTICE`
  - `ROADMAP.md`
- GitHub templates:
  - `.github/PULL_REQUEST_TEMPLATE.md`
  - `.github/ISSUE_TEMPLATE/bug_report.md`
  - `.github/ISSUE_TEMPLATE/detection_tuning.md`
  - `.github/ISSUE_TEMPLATE/documentation.md`

### Changed

- Updated RedSun full-chain correlation to include the new Cloud Files, Storage Tiers COM, and Microsoft detection-name stages with severity handling for high-signal combinations.
- Updated BlueHammer Stage 5c to also flag the public password marker and updated the full-chain query so Microsoft detection-name telemetry can stand alone as a critical signal.
- Updated UnDefend Stage 6 to include Defender/update-context Event ID 2001 matching without treating generic Event ID 2001 as sufficient.
- Updated package and root README guidance for CVE-2026-33825, RedSun and UnDefend public-CVE status as of April 19, 2026, new false-positive sources, and health-vs-on-disk validation guidance.
- Replaced the license placeholder with Apache License 2.0.
- Added SPDX license, copyright, and AI-generated review-warning headers to all KQL files.
- Detection folders now use sequential file numbering starting at `01`.
- Full-chain queries are positioned as `01_*_full_attack_chain.kql` in each detection folder.
- Standalone query headers now point to the renamed `01_*_full_attack_chain.kql` files.

### Validation

- Added CI validation coverage for stage alignment and README KQL basename coverage.
- Confirmed each detection folder has contiguous numbering from `01`.
- Confirmed standalone stage queries match their corresponding full-chain stage blocks.
- Confirmed static syntax checks passed for KQL files.
- Confirmed README files are ASCII-only and do not reference old numbering.

## 2026-04-17

### Added

- Initial RedSun detection package.
- Initial BlueHammer detection package.
- Initial UnDefend detection package.
- Standalone stage queries for each detection package.
- Main full-chain correlation query for each detection package.

### Fixed

- Corrected KQL semantic and syntax issues encountered during validation.
- Tuned BlueHammer query logic to reduce memory pressure and common false-positive combinations.
- Aligned standalone query logic with full-chain stage blocks.
