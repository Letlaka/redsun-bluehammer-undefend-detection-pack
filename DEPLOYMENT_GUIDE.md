# Deployment Guide

## 1. Lab Validation

- Run each standalone query with short and long lookbacks such as `24h` and `7d`.
- Record result count, top devices, top processes, and common false positives.
- Confirm the tenant exposes the required tables and fields before tuning.

## 2. Pilot Deployment

- Scope pilot testing to security-team devices, representative workstations, and a small server set.
- Validate that severity and result volume remain manageable after initial exclusions.
- Document expected allowlists with owner, reason, and expiry where possible.

## 3. Production Scheduled Detection

- Promote only the queries under `production/` to scheduled custom detections.
- Confirm alert threshold, expected incident volume, response owner, and rollback plan before enablement.
- Keep the top-level `01_*_full_attack_chain.kql` queries as hunting content unless explicitly promoted later.

## 4. Severity Model

- Reserve `Critical` for vendor detection names, exact BeigeBurrow evidence, or strong multi-stage chains.
- Treat filename-only and single weak-stage results as hunting signals, not high-severity alerts.
- Reassess severity after tenant-specific tuning and validation.

## 5. Analyst Response

- Pivot from `DeviceName`, `DeviceId`, `FirstSeen`, `LastSeen`, `Processes`, and `ReportRefs` into device timeline and process tree.
- Validate surrounding account, service, registry, and network context before concluding compromise.
- For exposure findings, verify tenant inventory freshness before treating an endpoint as patched or exposed.

## 6. Allowlist Governance

- Prefer narrow process-path, signer, or account-based exclusions over broad path suppressions.
- Avoid permanent exclusions for user-writable paths without documented business justification.
- Track owner, reason, approval date, and review cadence for each allowlist entry.

## 7. Rollback Plan

- Disable a scheduled detection if alert volume or operational impact becomes unacceptable.
- Reduce `Lookback`, tighten stage anchors, or remove noisy stage combinations before re-enabling.
- Re-enable the Cloud Files Mini Filter only after documenting the business exception if a RedSun mitigation test causes disruption.

## 8. Review Cadence

- Revalidate after Defender sensor or schema changes, Windows feature updates, or major software deployments.
- Review false positives and expired allowlists on a scheduled cadence.
- Update `SOURCES.md`, `IOCS.md`, `MITIGATIONS.md`, and the production queries when new verified intelligence changes the baseline.
