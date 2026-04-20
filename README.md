# RedSun, BlueHammer, and UnDefend Detection Pack

**IMPORTANT: All code and detection logic in this repository is AI-generated. There is no guarantee that these scripts are correct, complete, safe, or suitable for any environment. Use these scripts entirely at your own risk. The repository author is not liable or responsible for any damage, outage, data loss, false positive, false negative, operational impact, or other harm caused by use of this content. Every script must be reviewed, tested, tuned, and verified by qualified personnel before deployment to any live production environment.**

## Overview

This repository, `redsun-bluehammer-undefend-detection-pack`, contains Microsoft Defender XDR Advanced Hunting queries written in Kusto Query Language (KQL). The queries are organized as technical detection packages for proof-of-concept attack chains involving RedSun, BlueHammer, UnDefend, Microsoft Defender, Cloud Files, Volume Shadow Copy Service (VSS), Windows service behavior, local account manipulation, symbolic links, reparse points, and related Windows telemetry.

The content is designed for security research, detection engineering, lab validation, and controlled hunting workflows. It is not a drop-in production detection set. Each environment has different Defender XDR sensor coverage, event volumes, endpoint baselines, software inventory, and legitimate administrative behavior. You must validate both syntax and detection quality in your own tenant before enabling these queries as scheduled custom detections.

Research reviewed through April 19, 2026 maps BlueHammer to CVE-2026-33825 and public reporting of a Microsoft Defender Antimalware Platform fix at version 4.18.26050.3011. The same report found no public CVE assignment or public Microsoft patch for RedSun or UnDefend as of that date. This repository detects behaviors and Defender telemetry; it does not determine patch compliance by itself.

## Repository Layout

Each detection family is isolated in its own folder. Inside each folder, numbering starts at `01` and is sequential.

| Folder | Main Query | Standalone Queries | Purpose |
| --- | --- | --- | --- |
| `RedSun` | `01_redsun_full_attack_chain.kql` | `02` through `11` | Correlates Cloud Files, temporary payload staging, reparse or oplock telemetry, Storage Tiers COM activation, Defender-origin file writes, SYSTEM execution artifacts, and Microsoft detection names. |
| `BlueHammer` | `01_bluehammer_full_attack_chain.kql` | `02` through `17` | Correlates Defender update abuse, Cloud Files callbacks, VSS/SAM access, offline registry activity, password changes, service creation, token/process behavior, and Microsoft detection names. |
| `UnDefend` | `01_undefend_full_attack_chain.kql` | `02` through `08` | Correlates Defender registry reconnaissance, signature file access, update directory monitoring, WinDefend service monitoring, update or engine failure, and MRT directory access. |

## Query Design Pattern

Each folder follows the same structure:

1. `01_*_full_attack_chain.kql` is the composite hunt. It runs all stage logic together and correlates evidence on the same device within a defined time window.
2. Numbered standalone scripts isolate individual stages. These are intended for troubleshooting, baseline analysis, custom detection prototyping, and false-positive review.
3. Standalone scripts are expected to match the corresponding stage block in the full-chain query, except for final display-only ordering such as `| order by Timestamp desc`.
4. Main queries emit normalized fields such as `Stage`, `StageDescription`, `ProcessName`, `ProcessCommandLine`, `AccountName`, `Evidence`, `AdditionalContext`, and `ReportRefs` so cross-stage output is easier to review.

## Microsoft Defender XDR Requirements

These queries are intended for Microsoft Defender XDR Advanced Hunting. They rely on table and column availability from Defender for Endpoint and related Defender XDR telemetry.

Commonly used tables include:

| Table | Typical Use |
| --- | --- |
| `DeviceFileEvents` | File creation, modification, access, reads, path evidence, VSS or Defender file interactions. |
| `DeviceProcessEvents` | Process creation, parent process context, command line, token and account context. |
| `DeviceImageLoadEvents` | DLL loads such as `cldapi.dll`, `wuapi.dll`, `samlib.dll`, and `offreg.dll`. |
| `DeviceRegistryEvents` | Registry key and value access, Cloud Files sync root registration, Defender path reconnaissance. |
| `DeviceNetworkEvents` | Defender update package download signals and CDN URL access. |
| `DeviceEvents` | Miscellaneous endpoint telemetry including named pipes, service events, antivirus detections, Microsoft detection names, service changes, FSCTL-like details, and sensor-dependent additional fields. |

Telemetry is not uniform across all tenants. Some low-level primitives, especially raw oplock, reparse point, object manager symbolic link, and service query telemetry, may not appear as explicit events. The queries therefore include opportunistic matching against `ActionType` and `AdditionalFields` where Defender XDR exposes those details.

## Recommended Validation Workflow

Before production use, validate each package in this order:

1. Run each standalone query in Advanced Hunting using a limited lookback.
2. Confirm the query compiles in your tenant.
3. Review the raw result volume and identify legitimate software or administrative workflows that match.
4. Add local exclusions for known-good tools, service accounts, software deployment systems, backup products, EDR tools, and vulnerability scanners.
5. Run the `01_*_full_attack_chain.kql` query for the same package.
6. Compare full-chain results against standalone results and confirm that correlated stages make operational sense.
7. Export results to CSV and review process paths, command lines, accounts, devices, and timestamps.
8. Only after tuning should you convert a query into a scheduled custom detection rule.

Repository CI also runs `.github/scripts/validate_repository.py` to confirm KQL headers, delimiter balance, contiguous numbering, standalone-to-full-chain stage alignment, and README coverage for every package KQL file.

## Production Deployment Guidance

Treat these queries as starting points. A production deployment should include:

- Tenant-specific allowlists for known-good processes and paths.
- Separate thresholds for hunting versus alerting.
- Narrower lookback windows for scheduled detections where possible.
- Documented severity mapping and triage runbooks.
- Test devices or lab simulations to confirm expected matches.
- Change control before enabling automated incident creation.
- Periodic review after Defender sensor updates or operating system upgrades.

Do not deploy all main queries as high-severity scheduled detections without tuning. Some stages intentionally detect weak or opportunistic signals that are useful for correlation but noisy as standalone alerts.

## Performance Notes

The main queries are designed to avoid wide unbounded joins where possible. They use normalized stage rows, early projection, and time-bucket correlation. However, performance still depends on tenant scale, lookback duration, and event volume.

If a query exceeds Defender XDR execution limits:

- Reduce `Lookback`.
- Run standalone stages first to identify the expensive stage.
- Add narrower process, path, account, or device filters.
- Keep only required projected columns.
- Prefer summarized stage output before joining or correlating.
- Use shuffle hints where supported and where high-cardinality grouping is required.

## Result Interpretation

The queries should be interpreted as detections of suspicious behavior patterns, not proof of compromise by themselves. A full-chain match is stronger than a standalone stage match, but every result still requires analyst review.

High-value review fields:

- `DeviceName` and `DeviceId`
- `FirstSeen` and `LastSeen`
- `StageCount`
- `Stages`
- `Processes`
- `ProcessCommandLines`
- `Accounts`
- `Evidence`
- `AdditionalContexts`
- `ReportRefs`

Analysts should pivot from these fields into Defender device timeline, process tree, file timeline, registry timeline, alert evidence, and identity activity.

## Folder Documentation

Each detection folder has its own README with package-specific technical details:

- `RedSun/README.md`
- `BlueHammer/README.md`
- `UnDefend/README.md`

Use the folder README before running that package. It describes the stage model, expected telemetry, likely false positives, tuning points, and deployment considerations.

## Repository Documentation

Common repository files:

- `CONTRIBUTING.md` describes contribution scope, KQL style, validation, and pull request expectations.
- `CHANGELOG.md` records notable changes.
- `CODE_OF_CONDUCT.md` defines expected behavior for collaboration.
- `SECURITY.md` describes how to report security-sensitive repository issues.
- `SUPPORT.md` explains what support information to provide when asking for help.
- `DISCLAIMER.md` repeats the no-warranty, use-at-own-risk position in a dedicated document.
- `LICENSE.md` contains the Apache License 2.0 terms for this repository.
- `NOTICE` contains repository attribution and the AI-generated detection notice.
- `ROADMAP.md` lists practical future improvements.
- `.github/PULL_REQUEST_TEMPLATE.md` provides pull request review prompts.
- `.github/ISSUE_TEMPLATE/*.md` provides issue templates for bugs, detection tuning, and documentation.

## Maintenance Notes

These KQL files should be revalidated whenever:

- Microsoft changes Defender XDR table schemas or event naming.
- Defender for Endpoint sensor behavior changes.
- Windows feature updates alter service, registry, Cloud Files, VSS, or MRT behavior.
- New legitimate enterprise software begins touching Defender, VSS, Cloud Files, or SAM-related surfaces.
- Query thresholds are changed for production alerting.

Keep a record of tenant-specific exclusions and why they were added. Avoid broad exclusions that suppress attacker-controlled user-writable paths.
