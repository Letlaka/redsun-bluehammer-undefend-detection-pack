# CrossFamily Detection Package

**IMPORTANT: All code and detection logic in this folder is AI-generated. There is no guarantee that these scripts are correct, complete, safe, or suitable for any environment. Use these scripts entirely at your own risk. The repository author is not liable or responsible for any damage, outage, data loss, false positive, false negative, operational impact, or other harm caused by use of this content. Every script must be reviewed, tested, tuned, and verified by qualified personnel before deployment to any live production environment.**

## Purpose

The CrossFamily package contains Microsoft Defender XDR Advanced Hunting queries that turn Huntress-observed shared intrusion indicators into hunting content across BlueHammer, RedSun, UnDefend, and BeigeBurrow follow-on activity.

This package is intentionally hunting-focused. Observed filenames, recon commands, and public VPN IPs are not deterministic proof of compromise by themselves. Use them to enrich analyst review, narrow investigations, and correlate stronger process, network, and hash evidence.

Source review verified on `2026-05-05`:

- Huntress documented the shared observed tooling, BeigeBurrow follow-on activity, and nearby recon commands used here.
- VPN source IPs remain documentation-only in this repository and are listed in `IOCS.md`. They are intentionally not used in endpoint KQL.
- Filename-only matches remain low-confidence because they are renameable.

## File Layout

| File | Role |
| --- | --- |
| `01_crossfamily_full_attack_chain.kql` | Main composite query. Correlates suspicious-path tooling execution, BeigeBurrow activity, and recon near suspicious tooling. |
| `02_crossfamily_stage1_observed_tooling_execution.kql` | Stage 1: observed tooling filenames executed from suspicious user-writable paths. |
| `03_crossfamily_stage2_beigeburrow_tunnel_activity.kql` | Stage 2: BeigeBurrow command-line, domain, or hash evidence. |
| `04_crossfamily_stage3_recon_near_observed_tooling.kql` | Stage 3: recon commands within 30 minutes of Stage 1 or Stage 2 activity. |
| `production/nightmare_eclipse_conservative_custom_detection.kql` | Conservative scheduled-detection candidate derived from the main hunting query. |

## Main Query Behavior

`01_crossfamily_full_attack_chain.kql` normalizes the three stages into one schema and correlates them over a 30-minute window.

Important behavior:

- `Lookback` is set to `4h`.
- `CorrelationWindow` is set to `30m`.
- Stage 1 is constrained to suspicious user-writable paths to reduce filename-only noise.
- Stage 1 also preserves nearby BlueHammer `.BZ` vendor-detection or EICAR context when it appears on the same device within 30 minutes.
- Stage 2 treats exact BeigeBurrow command-line or SHA-256 evidence as higher confidence than domain-only or loose `agent.exe` patterns.
- Stage 3 fires when recon commands occur within 30 minutes before or after Stage 1 or Stage 2 activity, or nearby BlueHammer `.BZ` or EICAR detection context, on the same device.
- The package can emit single-stage hunting results, but Stage 1 alone is not treated as critical.

## Stage Details

### Stage 1: Observed Tooling Execution

Detects execution of `FunnyApp.exe`, `RedSun.exe`, `undef.exe`, or `z.exe` from suspicious user-writable paths and preserves context for observed `undef.exe -aggressive` and `undef.exe -agressive` command-line variants.

Primary table:

- `DeviceProcessEvents`

Why it matters:

- Huntress documented these filenames in real intrusion activity.
- The path restriction reduces noise, but the filenames are still renameable and must not be treated as deterministic proof.

### Stage 2: BeigeBurrow Tunnel Activity

Detects BeigeBurrow follow-on activity through exact command-line, network-domain, or SHA-256 evidence.

Primary tables:

- `DeviceProcessEvents`
- `DeviceNetworkEvents`
- `DeviceFileEvents`

Why it matters:

- Exact `agent.exe -server staybud.dpdns.org:443 -hide` command-line matches and exact SHA-256 matches are higher-confidence signals.
- Loose `agent.exe` patterns are retained for hunting, not definitive alerting.

### Stage 3: Recon Near Observed Tooling

Detects `whoami /priv`, `cmdkey /list`, or `net group` within 30 minutes before or after Stage 1 or Stage 2 activity, or nearby BlueHammer `.BZ` or EICAR detection context.

Primary table:

- `DeviceProcessEvents`

Why it matters:

- Recon commands are common by themselves, but become more meaningful near suspicious tooling or BeigeBurrow activity.

## Result Interpretation

Recommended severity handling:

- Exact BeigeBurrow command line or SHA-256 match: high-confidence hunting, often incident-worthy.
- Observed tooling plus nearby BlueHammer `.BZ` vendor detection: high-confidence and often incident-worthy.
- BeigeBurrow plus nearby recon: highest-confidence result in this package.
- Observed tooling plus nearby recon: stronger than filename-only execution.
- Filename-only execution from a suspicious path: hunting or enrichment only.

## Expected Analyst Workflow

1. Run `02_crossfamily_stage1_observed_tooling_execution.kql` to baseline suspicious-path filename hits and nearby aggressive `undef.exe` variants.
2. Run `03_crossfamily_stage2_beigeburrow_tunnel_activity.kql` and validate exact command-line, domain, and hash matches against tenant context.
3. Run `04_crossfamily_stage3_recon_near_observed_tooling.kql` to understand how often the recon commands appear near suspicious tooling in your tenant.
4. Run `01_crossfamily_full_attack_chain.kql` to correlate Stage 1 through Stage 3 on the same device within the package window.
5. Prioritize results with exact BeigeBurrow command-line or SHA-256 evidence, or suspicious tooling plus nearby BlueHammer `.BZ` or EICAR context.
6. Use VPN IPs from `IOCS.md` only in firewall, VPN, identity, or SIEM pivots, not as endpoint proof.

## Production Deployment Guidance

For scheduled custom detection work, start from `production/nightmare_eclipse_conservative_custom_detection.kql` and keep `01_crossfamily_full_attack_chain.kql` as the broader hunting query.

Do not promote filename-only Stage 1 results as high-severity alerts. Favor:

- Exact BeigeBurrow command-line or SHA-256 matches.
- Stage 2 plus Stage 3 correlation.
- Stage 1 plus Stage 3 only after tenant-specific tuning confirms the suspicious-path logic is low-noise.

## Documentation References

- `SOURCES.md` records where each shared indicator and mitigation note came from.
- `IOCS.md` records confidence and handling guidance for each indicator.
- `MITIGATIONS.md` records source-backed mitigation notes used elsewhere in the repository.
