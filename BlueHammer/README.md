# BlueHammer Detection Package

**IMPORTANT: All code and detection logic in this folder is AI-generated. There is no guarantee that these scripts are correct, complete, safe, or suitable for any environment. Use these scripts entirely at your own risk. The repository author is not liable or responsible for any damage, outage, data loss, false positive, false negative, operational impact, or other harm caused by use of this content. Every script must be reviewed, tested, tuned, and verified by qualified personnel before deployment to any live production environment.**

## Purpose

The BlueHammer package contains Microsoft Defender XDR Advanced Hunting queries for a multi-stage proof-of-concept chain involving Windows Update API activity, Defender update package retrieval, Cloud Files callback abuse, VSS activity, SAM and registry access, local password changes, GUID-named service creation, unusual process spawning, and Microsoft Defender detection-name telemetry.

The package is built as a correlation hunt. Several individual stages are intentionally weak when viewed alone, but become meaningful when they occur together on the same device within the correlation window.

The research report dated April 19, 2026 maps BlueHammer to CVE-2026-33825 and notes public reporting of a Microsoft Defender Antimalware Platform fix at version 4.18.26050.3011. These queries are still behavior and telemetry hunts; they do not replace patch verification.

## File Layout

| File | Role |
| --- | --- |
| `01_bluehammer_full_attack_chain.kql` | Main composite query. Runs all stages and correlates them by device and time window. |
| `02_bluehammer_stage1_windows_update_api_load.kql` | Stage 1: Windows Update API DLL load by a non-standard process. |
| `03_bluehammer_stage2_defender_update_cdn_download.kql` | Stage 2: Defender update package URL requested by a non-update process. |
| `04_bluehammer_stage3a_eicar_temp_executable.kql` | Stage 3a: executable in temp near EICAR antivirus detection. |
| `05_bluehammer_stage3b_cloud_files_sync_root.kql` | Stage 3b: Cloud Files sync root registration by a non-standard process. |
| `06_bluehammer_stage3c_rstrtmgr_oplock_signal.kql` | Stage 3c: `RstrtMgr.dll` oplock or device-control signal. |
| `07_bluehammer_stage3d_vss_near_eicar.kql` | Stage 3d: VSS process activity near EICAR detection. |
| `08_bluehammer_stage4a_defender_private_rpc_signal.kql` | Stage 4a: Defender private RPC or ALPC marker. |
| `09_bluehammer_stage4b_session_namespace_symlink.kql` | Stage 4b: session namespace symbolic-link activity. |
| `10_bluehammer_stage4c_defender_definition_directory_read.kql` | Stage 4c: Defender definition update directory read or monitoring. |
| `11_bluehammer_stage4d_vss_hive_read.kql` | Stage 4d: SAM, SYSTEM, SECURITY, or NTDS hive read from VSS path. |
| `12_bluehammer_stage5a_lsa_bootkey_registry_read.kql` | Stage 5a: LSA boot-key registry subkey read. |
| `13_bluehammer_stage5b_samlib_or_offreg_load.kql` | Stage 5b: suspicious `samlib.dll` or `offreg.dll` load. |
| `14_bluehammer_stage5c_local_password_change_burst.kql` | Stage 5c: burst of local password changes, account modifications, or public password-marker telemetry. |
| `15_bluehammer_stage6a_guid_named_service_installed.kql` | Stage 6a: service installed with GUID-shaped service name. |
| `16_bluehammer_stage6b_nonstandard_conhost_spawn.kql` | Stage 6b: `conhost.exe` spawned from a non-standard parent chain. |
| `17_bluehammer_stage7_microsoft_detection_name.kql` | Stage 7: Microsoft Defender BlueHammer detection-name telemetry. |

## Main Query Behavior

`01_bluehammer_full_attack_chain.kql` normalizes all stage outputs into one schema and uses bucketed correlation to reduce memory pressure.

Important behavior:

- `Lookback` is set to `2h`.
- `CorrelationWindow` is set to `30m`.
- `CorrelationStep` is set to `5m`.
- Stages are materialized once into `AllStages`.
- The query expands stage rows into stepped time buckets instead of using a wide self-join.
- `summarize hint.strategy = shuffle` is used for the high-cardinality grouping step.
- The final result requires multiple stages and a BlueHammer anchor condition, except Microsoft Defender BlueHammer detection-name telemetry can stand alone as `Critical`.

The main query is preferred for incident-level review. Standalone queries are preferred for troubleshooting, tuning, and validating individual stage behavior.

## Stage Details

### Stage 1: Windows Update API DLL Load

Detects `wuapi.dll` or `wuaueng.dll` loaded by a non-standard process outside typical Windows system paths.

Primary table:

- `DeviceImageLoadEvents`

Tuning notes:

- Check software distribution tools, patch management agents, and update orchestration products.

### Stage 2: Defender Update CDN Download

Detects requests to the Defender update package URL pattern involving `go.microsoft.com` and `LinkID=121721` by a non-update process.

Primary table:

- `DeviceNetworkEvents`

Why it matters:

- The package URL can be used to retrieve Defender update binaries outside normal update workflows.

Tuning notes:

- Browser processes are excluded from the main trusted update agent list in the composite query to keep the signal focused on update agents.
- If enterprise proxies or update tools fetch this URL, tune by process path or account.

### Stage 3a: EICAR Temp Executable

Detects executable creation or modification in temp within 30 seconds of an EICAR antivirus detection.

Primary tables:

- `DeviceFileEvents`
- `DeviceEvents`

Why it matters:

- EICAR is used as a trigger signal in several research and proof-of-concept workflows.

Limitations:

- EICAR testing by security teams can produce benign results.

### Stage 3b: Cloud Files Sync Root

Detects sync root registration under `SyncRootManager` by an untrusted process.

Primary table:

- `DeviceRegistryEvents`

Tuning notes:

- Allowlist enterprise sync providers and their installation paths.

### Stage 3c: RstrtMgr Oplock Signal

Detects `RstrtMgr.dll`, batch oplock strings, or related file-control telemetry from non-standard processes.

Primary table:

- `DeviceEvents`

Limitations:

- Raw oplock telemetry is not guaranteed in every tenant.

### Stage 3d: VSS Near EICAR

Detects `vssvc.exe`, `vssadmin`, `VSSVC`, or shadow copy command-line activity within 10 minutes of EICAR detection.

Primary tables:

- `DeviceProcessEvents`
- `DeviceEvents`

Tuning notes:

- Backup and restore tools are common benign sources of VSS activity.

### Stage 4a: Defender Private RPC Signal

Detects Defender private RPC, ALPC, interface, or method markers in `DeviceEvents.AdditionalFields`.

Primary table:

- `DeviceEvents`

Limitations:

- This is opportunistic string-based telemetry. Absence of evidence is not evidence that RPC activity did not occur.

### Stage 4b: Session Namespace Symlink

Detects symbolic link activity involving `\Sessions\...\BaseNamedObjects`.

Primary table:

- `DeviceEvents`

Why it matters:

- Session namespace symbolic links may be used in time-of-check/time-of-use chains.

### Stage 4c: Defender Definition Directory Read

Detects reads or directory monitoring behavior under Defender definition update paths by non-standard processes.

Primary table:

- `DeviceFileEvents`

Tuning notes:

- Security tooling may legitimately inspect Defender definition directories.

### Stage 4d: VSS Hive Read

Detects SAM, SYSTEM, SECURITY, or NTDS hive access from `HarddiskVolumeShadowCopy` paths.

Primary table:

- `DeviceFileEvents`

Why it matters:

- This is a high-value credential access signal.

Tuning notes:

- Backup products, forensic tools, and disaster recovery tools may legitimately read these paths.

### Stage 5a: LSA Boot-Key Registry Read

Detects reads of `Control\Lsa\JD`, `Skew1`, `GBG`, or `Data`.

Primary table:

- `DeviceRegistryEvents`

Why it matters:

- These values are associated with boot-key reconstruction workflows.

### Stage 5b: Samlib or Offreg Load

Detects `samlib.dll` or `offreg.dll` loaded by a non-standard process, with added filtering to reduce normal Microsoft system activity.

Primary table:

- `DeviceImageLoadEvents`

Tuning notes:

- The stage requires `offreg.dll`, a user-writable process path, or a non-Microsoft company name for the initiating process.

### Stage 5c: Local Password Change Burst

Detects four or more local account password change or account modification events within a two-minute window by the same process. It also flags the public `$PWNed666!!!WDFAIL` marker when it appears in `AdditionalFields` or command-line telemetry.

Primary table:

- `DeviceEvents`

Tuning notes:

- Password rotation tools and local account management products may trigger this.
- Lab validation can intentionally trigger the public marker; record those tests before tuning.

### Stage 6a: GUID-Named Service Installed

Detects service installation where the service name is a GUID.

Primary table:

- `DeviceEvents`

Tuning notes:

- Some legitimate installers use GUID-like service names. Review service image path and parent process.

### Stage 6b: Nonstandard Conhost Spawn

Detects `conhost.exe` spawned from an unusual parent chain, with suppression for normal Windows system directory parents.

Primary table:

- `DeviceProcessEvents`

Tuning notes:

- Remote admin tooling, terminal products, and automation agents may require allowlisting.

### Stage 7: Microsoft Detection Name

Detects Microsoft Defender antivirus telemetry that contains BlueHammer-associated detection names or stable substrings such as `Behavior:Win32/CVE-2026-33825.Z!MTB`, `Exploit:Win32/DfndrPEBluHmr.BB`, `CVE-2026-33825`, or `DfndrPEBluHmr`.

Primary table:

- `DeviceEvents`

Why it matters:

- This is high-signal vendor detection telemetry and is treated as `Critical` by the full-chain query even if no other stage is visible.

## Anchor Logic

The composite query includes an anchor requirement to reduce false positives. This prevents weak combinations such as ordinary `samlib.dll` loads plus normal `conhost.exe` behavior from producing noisy results.

High-value anchors include:

- Defender update CDN download by non-update process.
- Microsoft Defender BlueHammer detection-name telemetry.
- Cloud Files sync root registration.
- VSS hive read.
- LSA boot-key registry read.
- GUID-named service installation.
- Other strong stage combinations defined in the full-chain query.

## Expected Analyst Workflow

1. Run standalone stages `02` through `17`.
2. Identify which stages are noisy in your tenant.
3. Tune trusted process arrays and path filters.
4. Run `01_bluehammer_full_attack_chain.kql`.
5. Prioritize devices with credential access, service creation, VSS hive reads, or multiple distinct stages.
6. Pivot into Defender process tree, device timeline, registry timeline, and identity timeline.

## False Positive Sources

Potential benign sources include:

- Patch management systems.
- Backup agents.
- Cloud sync clients.
- Security scanners.
- Forensic acquisition tools.
- Local account password rotation tools.
- Software installers.
- Remote support products.
- Developer or administrative scripts.
- Lab antivirus detections or validation simulations.

## Production Deployment Guidance

Use standalone queries for baselining first. For production alerting, consider requiring one of:

- VSS hive read plus any other stage.
- LSA boot-key read plus any other stage.
- GUID service installation plus any other stage.
- Defender update CDN download plus Cloud Files or VSS activity.
- Microsoft Defender BlueHammer detection-name telemetry.
- Four or more total stages in the main query.

Avoid scheduled alerts on weak standalone stages without tuning. Stages such as Windows Update DLL load, directory reads, `samlib.dll` loads, or `conhost.exe` behavior can be noisy in enterprise environments.

## Performance Guidance

If `01_bluehammer_full_attack_chain.kql` exceeds memory or CPU limits:

- Reduce `Lookback`.
- Run individual stages to locate the expensive source.
- Narrow high-volume tables such as `DeviceEvents` and `DeviceFileEvents`.
- Add device group or process filters for testing.
- Keep the bucketed correlation model rather than reverting to wide self-joins.
