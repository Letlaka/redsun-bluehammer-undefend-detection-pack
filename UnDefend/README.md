# UnDefend Detection Package

**IMPORTANT: All code and detection logic in this folder is AI-generated. There is no guarantee that these scripts are correct, complete, safe, or suitable for any environment. Use these scripts entirely at your own risk. The repository author is not liable or responsible for any damage, outage, data loss, false positive, false negative, operational impact, or other harm caused by use of this content. Every script must be reviewed, tested, tuned, and verified by qualified personnel before deployment to any live production environment.**

## Purpose

The UnDefend package contains Microsoft Defender XDR Advanced Hunting queries for a Defender tampering and degradation pattern involving Defender registry reconnaissance, Defender signature file access, definition update directory monitoring, WinDefend service status monitoring, Defender service or update failure telemetry, and Microsoft Malicious Software Removal Tool (MRT) directory access.

The package is intended to identify suspicious behavior around Defender update and service surfaces. It does not prove tampering by itself. Analysts must correlate results with process lineage, user context, change-control history, software inventory, and Defender device timeline evidence.

As of the research report dated April 19, 2026, UnDefend did not have a public CVE assignment or public Microsoft patch identified. This package focuses on Defender degradation behavior, especially suspicious definition-file access followed by service or update failure effects.

## File Layout

| File | Role |
| --- | --- |
| `01_undefend_full_attack_chain.kql` | Main composite query. Runs all stages and correlates them by device and time window. |
| `02_undefend_stage1_defender_registry_recon.kql` | Stage 1: Defender registry path reconnaissance. |
| `03_undefend_stage2_signature_file_access.kql` | Stage 2: Defender signature or definition file access. |
| `04_undefend_stage3_defender_update_directory_monitoring.kql` | Stage 3: repeated Defender definition update directory access. |
| `05_undefend_stage4_windefend_service_monitoring.kql` | Stage 4: WinDefend service query or status monitoring. |
| `06_undefend_stage5_windefend_stop_after_suspicious_access.kql` | Stage 5: WinDefend stopped, disabled, or reconfigured. |
| `07_undefend_stage6_update_failure_after_signature_access.kql` | Stage 6: Defender update, signature, service, or engine failure telemetry. |
| `08_undefend_stage7_mrt_directory_access.kql` | Stage 7: MRT directory access by a non-system, non-MRT process. |

## Main Query Behavior

`01_undefend_full_attack_chain.kql` normalizes all stages into `AllStages`, expands events into stepped correlation windows, and summarizes by device and window.

Important behavior:

- `Lookback` is set to `2h`.
- `CorrelationWindow` is set to `1h`.
- `CorrelationStep` is set to `10m`.
- The query requires at least two distinct stages.
- The query requires an UnDefend anchor such as registry recon, signature file access, directory monitoring, service monitoring, or MRT access.
- Severity is increased when signature file access is paired with Defender failure or WinDefend stop telemetry.

## Stage Details

### Stage 1: Defender Registry Recon

Detects non-Defender processes reading Defender registry values such as `ProductAppDataPath` and `SignatureLocation`.

Primary table:

- `DeviceRegistryEvents`

Primary fields:

- `RegistryKey`
- `RegistryValueName`
- `RegistryValueData`
- `InitiatingProcessFileName`
- `InitiatingProcessFolderPath`

Why it matters:

- Defender path discovery can precede file locking, update directory watching, or tampering workflows.

Tuning notes:

- Validate enterprise security tools, inventory agents, compliance tools, and scripts that inspect Defender configuration.

### Stage 2: Signature File Access

Detects non-Defender processes accessing Defender signature files such as `mpavbase.vdm`, `mpasbase.vdm`, `mpavdlta.vdm`, and related `.lkg` files.

Primary table:

- `DeviceFileEvents`

Why it matters:

- Signature file access by unusual processes may indicate tampering, file locking, inspection, or race-condition preparation.

Tuning notes:

- Security tools may inspect these files.
- The stage is stronger when paired with update failures or service monitoring.

### Stage 3: Defender Update Directory Monitoring

Detects repeated access to Defender definition update directories by non-Defender processes.

Primary table:

- `DeviceFileEvents`

Behavior:

- Events are bucketed into 5-minute windows.
- The stage requires at least three accesses in the bucket.

Why it matters:

- Repeated directory access can approximate `ReadDirectoryChangesW`-style monitoring behavior.

Tuning notes:

- Baseline security scanners and inventory tools before alerting.

### Stage 4: WinDefend Service Monitoring

Detects non-standard, non-SYSTEM processes querying or monitoring WinDefend service status or configuration.

Primary table:

- `DeviceEvents`

Why it matters:

- Aggressive monitoring of Defender service state can support timing attacks, tampering, or update manipulation.

Limitations:

- Defender XDR service query telemetry can vary by tenant.
- Some legitimate admin tools query service state.

### Stage 5: WinDefend Stopped, Disabled, or Reconfigured

Detects telemetry indicating WinDefend service stop, disablement, or configuration change.

Primary table:

- `DeviceEvents`

Why it matters:

- Service interruption after suspicious Defender file or registry activity is a high-value correlation point.

Tuning notes:

- Review maintenance windows, Defender platform updates, troubleshooting sessions, and EDR management actions.

### Stage 6: Defender Update or Engine Failure

Detects Defender update, signature, service, or engine failure strings and action types. The stage also matches common Event ID 2001 shapes only when the same telemetry contains Defender or update context.

Primary table:

- `DeviceEvents`

Why it matters:

- Update or engine failure following suspicious access can indicate denial, tampering, or file locking effects.

Tuning notes:

- Defender update failures can occur for benign reasons such as network issues, proxy problems, disk issues, or service health problems.
- Treat this stage as stronger when paired with Stage 2 or Stage 3.
- Do not tune generic Event ID 2001 matches without confirming the Defender/update context, because unrelated Windows events can reuse the same numeric ID.

### Stage 7: MRT Directory Access

Detects non-system, non-MRT processes accessing `C:\Windows\System32\MRT`.

Primary table:

- `DeviceFileEvents`

Why it matters:

- MRT directory monitoring or access may be part of aggressive Defender-related tampering workflows.

Tuning notes:

- Confirm legitimate patching, Windows servicing, and vulnerability management behavior.

## Expected Analyst Workflow

1. Run standalone queries `02` through `08`.
2. Baseline legitimate Defender management and security software.
3. Tune trusted process arrays and trusted Defender paths.
4. Run `01_undefend_full_attack_chain.kql`.
5. Prioritize results with Stage 2 plus Stage 5 or Stage 6.
6. Review Defender service health, update history, device timeline, and process lineage.

## False Positive Sources

Potential benign sources include:

- Defender platform updates.
- Security monitoring products.
- Vulnerability scanners.
- EDR or antivirus coexistence tools.
- Windows servicing components.
- Compliance and inventory agents.
- Local admin troubleshooting.
- Proxy or update infrastructure failures.

## Production Deployment Guidance

Recommended higher-confidence production conditions:

- Stage 2 plus Stage 6.
- Stage 2 plus Stage 5.
- Stage 3 plus Stage 5.
- Stage 3 plus Stage 6.
- Three or more total stages with at least one Defender file or service stage.

Avoid high-severity scheduled detections based only on update failure telemetry. Defender update failures are common in some enterprise environments and require context.

## Investigation Checklist

For every main-query result, review:

- Device timeline around `FirstSeen` and `LastSeen`.
- Process tree for all entries in `Processes`.
- Command lines in `ProcessCommandLines`.
- Account context in `Accounts` and `AccountSids`.
- File and registry details in `Evidence`.
- Service control activity for `WinDefend`.
- Defender health, engine version, platform version, and signature update history.
- Dashboard-reported Defender health against on-disk definition timestamps and versions, because stale local definitions can matter even when management health looks normal.
- Any recent software deployment or endpoint management job.
