# Contributing

**Project notice: This repository contains AI-generated detection content. Contributions must be reviewed, tested, tuned, and verified before any production use. No contribution should be treated as production-ready only because it was merged.**

## Scope

This repository accepts contributions that improve Microsoft Defender XDR Advanced Hunting content, documentation, validation steps, tuning guidance, and repository maintenance.

Appropriate contributions include:

- KQL syntax fixes.
- Defender XDR schema compatibility fixes.
- False-positive reduction.
- Performance improvements.
- New standalone stage queries that map cleanly into a full-chain query.
- Documentation for triage, validation, and deployment.
- Sanitized sample result analysis.
- Test notes from lab or tenant validation.

Do not submit:

- Live tenant secrets, tenant IDs, device names, user names, IP addresses, or other sensitive data.
- Unredacted incident data.
- Exploit code or weaponized payloads.
- Broad allowlists that suppress suspicious user-writable paths without evidence.
- Claims that a query is production-safe without validation details.

## Repository Structure

Full-chain detection packages are stored in these folders:

- `RedSun`
- `BlueHammer`
- `UnDefend`
- `CrossFamily`

Support folders that do not follow the same full-chain pattern:

- `Exposure`
- `ExternalTelemetry`

Full-chain detection packages follow this file pattern:

- `01_*_full_attack_chain.kql` is the main composite query.
- `02_*` and higher are standalone stage queries.
- `README.md` documents the package, stages, tuning guidance, and deployment considerations.
- `production/*.kql`, where present, contains conservative scheduled-detection candidates and must not be labeled as `QueryType: Hunting`.

Support-folder expectations:

- `Exposure/01_bluehammer_defender_platform_exposure.kql` is an exposure-reporting template, not a composite attack-chain hunt.
- `ExternalTelemetry/README.md` is documentation-only and intentionally has no endpoint KQL.

Numbering must be sequential inside each KQL-bearing folder and must start at `01`.

## Branch Management Strategy

This repository uses a lightweight GitHub Flow model. The `main` branch is the public source of truth and should always represent content that is ready for public review and reuse.

Use short-lived branches for all changes:

- `fix/*` for KQL syntax and schema compatibility fixes.
- `tune/*` for false-positive reduction, performance tuning, and threshold changes.
- `docs/*` for documentation-only updates.
- `feature/*` for new detection stages, packages, or larger enhancements.
- `ci/*` for repository validation, automation, and GitHub Actions changes.

Keep each branch focused on one concern. Do not mix unrelated documentation, detection logic, tuning, and automation changes in the same branch or pull request.

Public branch and history expectations:

- Do not force-push or rewrite the public `main` branch.
- Merge changes into `main` through pull requests.
- Delete short-lived branches after merge.
- Use tags for public release points after the changelog is updated.
- Prefer dated release tags in the format `vYYYY.MM.DD` unless a semantic version is needed for downstream tooling.

Recommended `main` branch protection:

- Require pull requests before merging.
- Require review for detection logic, false-positive tuning, and CI changes.
- Require all conversations to be resolved before merge.
- Require validation checks once GitHub Actions checks are available.
- Disable force pushes and branch deletion on `main`.

## KQL Style Guidelines

Use these conventions for KQL changes:

- Define `Lookback` near the top of each query.
- Use `Timestamp >= ago(Lookback)` consistently.
- Filter early, before joins or summarizes.
- Project only fields needed for triage and correlation.
- Normalize output fields across stages where possible.
- Prefer `contains` or explicit path normalization for Windows path matching when tokenized `has` semantics may be misleading.
- Use `in~` for case-insensitive filename and process-name matching.
- Convert dynamic `AdditionalFields` to string before broad string matching.
- Avoid wide unbounded joins.
- Use bucketed correlation or summarized intermediate results for high-volume tables.
- Add shuffle hints only where the query has high-cardinality grouping or join keys and the target platform supports it.

Preferred normalized stage fields:

- `Timestamp`
- `DeviceId`
- `DeviceName`
- `ReportId`
- `Stage`
- `StageDescription`
- `ProcessName`
- `ProcessPath`
- `ProcessCommandLine`
- `AccountName`
- `AccountSid`
- `Evidence`
- `AdditionalContext`

Required KQL metadata fields:

- `Family`
- `QueryType`
- `Severity`
- `Confidence`
- `DataSources`
- `ATTACK`
- `SourceRefs`
- `ProductionReady`
- `LastVerified`

## Standalone and Full-Chain Alignment

When changing a standalone query, update the corresponding stage block in the full-chain query. When changing a full-chain stage block, update the standalone query.

Expected relationship:

- The detection logic should match.
- Helper functions and trusted process lists referenced by the stage should match.
- Standalone files may add final presentation ordering such as `| order by Timestamp desc`.
- The full-chain query may add correlation fields such as `StageTime`.

## Validation Checklist

Before submitting a change, perform these checks:

1. Confirm KQL parentheses, brackets, and braces are balanced.
2. Confirm all referenced tables and columns exist in Microsoft Defender XDR Advanced Hunting.
3. Run the standalone query in a lab or test tenant if possible.
4. Run the full-chain query if the changed stage participates in one.
5. Check result volume and identify likely false positives.
6. Confirm high-volume joins or summaries are bounded by time and projected columns.
7. Confirm documentation reflects the change.
8. Remove any sensitive data from examples, screenshots, and exported results.
9. Confirm the `// DetectionMetadata:` block is present and accurate.
10. Confirm `SourceRefs` points to the correct `SOURCES.md` anchor.

## Documentation Requirements

Every detection logic change should update at least one of:

- The package README.
- The root README.
- The changelog.
- Inline query comments.

Documentation should explain:

- What changed.
- Why the change was made.
- Which table or telemetry source is affected.
- How analysts should interpret the result.
- Any new false-positive or false-negative risk.

## Pull Request Expectations

A pull request should include:

- Summary of the change.
- Affected files.
- Validation performed.
- Known limitations.
- Any Defender XDR errors encountered.
- Any expected false-positive impact.

Use the pull request template in `.github/PULL_REQUEST_TEMPLATE.md`.

## Handling Sensitive Data

Do not commit raw production output. If sample data is needed:

- Remove tenant IDs.
- Remove device IDs.
- Remove user names.
- Remove public IP addresses unless they are intentionally public indicators.
- Remove hostnames.
- Remove file paths that include user names.
- Replace timestamps if they could identify an incident.

Prefer synthetic examples.

## License Contributions

This repository is licensed under the Apache License 2.0. Contributions intentionally submitted for inclusion in this repository are expected to be contributed under the same license unless explicitly stated otherwise in writing.

Do not add external licensed text, third-party query content, or copied documentation unless the license is compatible with Apache License 2.0 and attribution is documented.
