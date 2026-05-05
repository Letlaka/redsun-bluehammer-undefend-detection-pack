# RedSun Detection Package

**IMPORTANT: All code and detection logic in this folder is AI-generated. There is no guarantee that these scripts are correct, complete, safe, or suitable for any environment. Use these scripts entirely at your own risk. The repository author is not liable or responsible for any damage, outage, data loss, false positive, false negative, operational impact, or other harm caused by use of this content. Every script must be reviewed, tested, tuned, and verified by qualified personnel before deployment to any live production environment.**

## Purpose

The RedSun package contains Microsoft Defender XDR Advanced Hunting queries for a multi-stage Windows privilege escalation pattern involving temporary payload staging, Cloud Files API behavior, named pipe artifacts, Defender-mediated file writes, reparse point or junction activity, oplock or VSS-related telemetry, Storage Tiers Management COM activation, Microsoft Defender detection-name telemetry, and SYSTEM-level process creation.

The main query is intended to correlate multiple weak and medium-strength signals into a higher-confidence device-level alert. The standalone queries are intended for baseline review and stage-specific investigation.

As of the 2026-05-05 source review, no public Microsoft CVE or vendor patch was verified for RedSun. Huntress reported RedSun remained unpatched as of 2026-04-20. Treat this package as behavior-focused hunting content, not as proof that an endpoint is patched or unpatched. Source-backed compensating-control caveats for the Cloud Files Mini Filter are documented in `MITIGATIONS.md`.

## File Layout

| File | Role |
| --- | --- |
| `01_redsun_full_attack_chain.kql` | Main composite query. Runs all stages and correlates them by device and time window. |
| `02_redsun_stage1_temp_target_drop.kql` | Standalone Stage 1: target filename staged in temporary paths. |
| `03_redsun_stage2_cloud_filter_load.kql` | Standalone Stage 2: `cldapi.dll` loaded by a process running from a temporary path. |
| `04_redsun_stage3_pipe_artifact.kql` | Standalone Stage 3: `REDSUN` named pipe or pipe artifact. |
| `05_redsun_stage4_system32_tiering_write.kql` | Standalone Stage 4: `TieringEngineService.exe` write under `C:\Windows\System32`. |
| `06_redsun_stage5_system_conhost_spawn.kql` | Standalone Stage 5: `conhost.exe` spawned as SYSTEM from a non-standard parent. |
| `07_redsun_stage6_temp_reparse_pivot.kql` | Standalone Stage 6: temporary-path reparse point, symbolic link, or junction telemetry pointing toward System32. |
| `08_redsun_stage7_batch_oplock_vss.kql` | Standalone Stage 7: batch oplock or VSS-related telemetry from a temporary-path process. |
| `09_redsun_stage8_cloud_files_sync_root.kql` | Standalone Stage 8: Cloud Files sync root registration by a non-standard process. |
| `10_redsun_stage9_storage_tiers_com_activation.kql` | Standalone Stage 9: Storage Tiers Management COM activation marker. |
| `11_redsun_stage10_microsoft_detection_name.kql` | Standalone Stage 10: Microsoft Defender RedSun detection-name telemetry. |
| `production/redsun_conservative_custom_detection.kql` | Conservative scheduled-detection candidate derived from the main hunting query. |

## Main Query Behavior

`01_redsun_full_attack_chain.kql` defines each stage as a normalized subquery. The stages are unioned into `AllStages`, then correlated by `DeviceId` over a 60-minute window.

Important behavior:

- `Lookback` is set to `2h`.
- `CorrelationWindow` is set to `60m`.
- Stage output is normalized into common fields.
- The query requires at least two distinct stages unless Microsoft Defender RedSun detection-name telemetry is present.
- Severity becomes `Critical` when Microsoft detection-name telemetry is present, or when Storage Tiers COM activation is paired with System32 write or SYSTEM execution telemetry.
- Severity becomes `High` when Cloud Files sync-root registration is paired with reparse or oplock telemetry.
- The query produces stage sets, process sets, account sets, evidence sets, and report references for analyst pivoting.

## Stage Details

### Stage 1: Temporary Target Drop

Detects `TieringEngineService.exe` created, modified, or renamed in temporary paths such as user temp, Windows temp, or generic temp folders.

Primary table:

- `DeviceFileEvents`

Primary fields:

- `ActionType`
- `FileName`
- `FolderPath`
- `PreviousFolderPath`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`

Tuning notes:

- Review software installers and endpoint management tools that stage files in temporary directories.
- The filename is highly specific, so false positives should be lower than a generic executable-in-temp rule.

### Stage 2: Cloud Filter DLL Load

Detects `cldapi.dll` loaded by a process whose folder path or command line indicates temporary-path execution.

Primary table:

- `DeviceImageLoadEvents`

Why it matters:

- `cldapi.dll` is associated with Cloud Files API operations.
- Temporary execution plus Cloud Files loading is suspicious when not from known sync providers.

Tuning notes:

- Allowlist legitimate Cloud Files providers such as OneDrive, Dropbox, Box, and Google Drive.
- Validate whether enterprise sync clients use non-standard paths.

### Stage 3: REDSUN Pipe Artifact

Detects named pipe or pipe metadata containing `REDSUN`.

Primary table:

- `DeviceEvents`

Why it matters:

- Named pipes are often used for process coordination, privilege boundary crossing, and session handshakes.
- This stage is highly artifact-specific.

Limitations:

- Named pipe telemetry depends on Defender sensor visibility.
- The artifact string must be present in `AdditionalFields`.

### Stage 4: System32 TieringEngineService Write

Detects writes to `C:\Windows\System32\TieringEngineService.exe`.

Primary table:

- `DeviceFileEvents`

Why it matters:

- System32 writes are high-value.
- Defender or an unusual writer touching this specific filename is a strong pivot point in this package.

Tuning notes:

- Review legitimate Windows servicing processes.
- The query retains Defender writer context because Defender-mediated writes can be relevant to this attack chain.

### Stage 5: SYSTEM Conhost Spawn

Detects `conhost.exe` running as SYSTEM with a parent outside standard parent processes such as `csrss.exe`, `wininit.exe`, `svchost.exe`, and `services.exe`.

Primary table:

- `DeviceProcessEvents`

Why it matters:

- A SYSTEM `conhost.exe` with an unusual parent can indicate privilege escalation or session bridging.

Tuning notes:

- Validate remote management tools, terminal products, support tools, and automation agents.

### Stage 6: Temporary Reparse Pivot

Detects junction, symbolic link, reparse point, or `FSCTL_SET_REPARSE_POINT`-style telemetry involving temporary paths and System32 targets.

Primary table:

- `DeviceEvents`

Limitations:

- Low-level reparse and junction telemetry may not be available in every tenant.
- Matching depends heavily on `ActionType` and `AdditionalFields`.

### Stage 7: Batch Oplock or VSS Signal

Detects `FSCTL_REQUEST_BATCH_OPLOCK`, batch oplock strings, VSS strings, or Defender-related targets from temporary-path processes.

Primary table:

- `DeviceEvents`

Limitations:

- Oplock telemetry is sensor-dependent.
- Treat standalone matches as investigative leads unless correlated with other stages.

### Stage 8: Cloud Files Sync Root

Detects sync root registration under `SyncRootManager` by an untrusted process.

Primary table:

- `DeviceRegistryEvents`

Why it matters:

- Public RedSun analysis highlights Cloud Files registration as an important setup signal.
- This stage is stronger when paired with Stage 6 or Stage 7.

Tuning notes:

- Allowlist legitimate sync providers and their managed installation paths.

### Stage 9: Storage Tiers COM Activation

Detects Storage Tiers Management COM activation markers, including CLSID `{50d185b9-fff3-4656-92c7-e4018da4361d}`, from non-system or non-standard processes.

Primary table:

- `DeviceEvents`

Limitations:

- COM activation details are sensor-dependent and may only appear in `AdditionalFields`.
- Legitimate storage administration tooling can require tuning.

### Stage 10: Microsoft Detection Name

Detects Microsoft Defender antivirus telemetry that contains RedSun-associated detection names such as `Exploit:Win32/DfndrPERedSun.BB`, `HackTool:Win64/RedSun.DA!MTB`, or `Exploit:Win32/Redsun.A`.

Primary table:

- `DeviceEvents`

Why it matters:

- This is high-signal vendor detection telemetry and can be useful even without other RedSun stages.

## Expected Analyst Workflow

1. Run `02` through `11` individually to establish baseline behavior.
2. Review each result for legitimate software, account, path, and parent process patterns.
3. Add tenant-specific exclusions only after confirming they are safe.
4. Run `01_redsun_full_attack_chain.kql`.
5. Investigate devices with Stage 4, Stage 5, Stage 9, or Stage 10 present.
6. Pivot into device timeline and process tree using `ReportRefs`, `Processes`, and `Evidence`.

## False Positive Sources

Potential benign sources include:

- Cloud sync providers.
- Software installers.
- Endpoint management agents.
- Windows servicing components.
- Security tooling.
- Remote support tools.
- Developer tools that create junctions or symbolic links in temp paths.
- Storage administration tools and management consoles.
- Lab antivirus detections or validation simulations.

## Compensating Control Caveat

Qualys documented disabling the Cloud Files Mini Filter as a possible compensating control where business impact is acceptable.

Use that guidance carefully:

- this is not a vendor patch;
- test before broad deployment;
- validate OneDrive Files On-Demand and other Cloud Files placeholder or hydration workflows;
- document any exception or rollback decision.

## Production Deployment Guidance

Use the main query as a hunting query first. For scheduled custom detection work, start from `production/redsun_conservative_custom_detection.kql` and keep `01_redsun_full_attack_chain.kql` as the broader hunting query.

When tuning the production variant, consider requiring one of:

- Stage 4 plus any other stage.
- Stage 5 plus any other stage.
- Stage 9 plus Stage 4 or Stage 5.
- Stage 8 plus Stage 6 or Stage 7.
- Stage 10 as a high-priority vendor-detection signal.
- Stage 2 plus Stage 6 or Stage 7.
- Three or more total stages.

Avoid alerting on Stage 6 or Stage 7 alone unless your tenant reliably captures those events and you have tuned known-good activity.
