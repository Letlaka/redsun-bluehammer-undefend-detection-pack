# Changelog

All notable repository changes should be recorded in this file.

This project does not currently follow a formal release process. Use the `Unreleased` section for work in progress, and create dated sections when changes are published or tagged.

## Unreleased

### Added

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

- Replaced the license placeholder with Apache License 2.0.
- Added SPDX license, copyright, and AI-generated review-warning headers to all KQL files.
- Detection folders now use sequential file numbering starting at `01`.
- Full-chain queries are positioned as `01_*_full_attack_chain.kql` in each detection folder.
- Standalone query headers now point to the renamed `01_*_full_attack_chain.kql` files.

### Validation

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
