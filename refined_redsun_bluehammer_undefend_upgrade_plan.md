# Refined Upgrade Plan: RedSun, BlueHammer, and UnDefend Detection Pack

**Repository:** `Letlaka/redsun-bluehammer-undefend-detection-pack`  
**Plan version:** `2026-05-05`  
**Purpose:** Upgrade the detection pack using verified repo findings and verified public-source intelligence.  
**Target branch:** `upgrade/verified-iocs-and-production-hardening`

---

## 1. Executive Summary

This upgrade must achieve four outcomes:

1. **Correct the BlueHammer exposure baseline** from `4.18.26050.3011` to the verified fixed Defender platform baseline `4.18.26030.3011`.
2. **Add verified real-world intrusion indicators** from Huntress as cross-family hunting and enrichment logic.
3. **Separate hunting logic from production scheduled detections** to reduce false positives and operational noise.
4. **Improve documentation and CI controls** so every CVE, IOC, mitigation, detection-name string, and platform baseline is source-traceable.

The current repository already warns that its detection logic is AI-generated, not production-ready, and must be reviewed and tested before use. That warning must remain in place.

---

## 2. Verified Facts, Assumptions, and Limits

### 2.1 Verified Facts

| Area | Verified Detail | Source |
|---|---|---|
| BlueHammer CVE | `CVE-2026-33825` applies to Microsoft Defender and allows local privilege escalation due to insufficient access-control granularity. | NVD |
| BlueHammer severity | CVSS v3.1 `7.8 HIGH`, vector `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`. | NVD |
| BlueHammer KEV status | Added to CISA KEV on `2026-04-22`; due date `2026-05-06`. | NVD / CISA reference |
| BlueHammer fixed baseline | Defender Antimalware Platform versions below `4.18.26030.3011` are affected. | NVD affected CPE + Microsoft Defender release notes |
| Microsoft Defender platform release | Windows Antivirus Platform `4.18.26030.3011`, Engine `1.1.26030.3008`, Security Intelligence `1.449.16.0`. | Microsoft Defender release notes |
| BlueHammer added detection name | `Exploit:Win32/DfndrPEBluHmr.BZ` observed by Huntress. | Huntress |
| Observed tooling names | `FunnyApp.exe`, `RedSun.exe`, `undef.exe`, `z.exe`. | Huntress |
| Observed recon commands | `whoami /priv`, `cmdkey /list`, `net group`. | Huntress |
| BeigeBurrow tooling | `agent.exe -server staybud.dpdns[.]org:443 -hide`, domain `staybud.dpdns[.]org`, SHA-256 `a2b6c7a9c4490df70de3cdbfa5fc801a3e1cf6a872749259487e354de2876b7c`. | Huntress |
| FortiGate SSL VPN source IPs | `78.29.48[.]29`, `212.232.23[.]69`, `179.43.140[.]214`. | Huntress |
| RedSun mitigation caveat | Disabling Cloud Files Mini Filter prevents the Windows Cloud Files platform from loading and blocks cloud placeholder / on-demand hydration functionality such as OneDrive Files On-Demand. | Qualys |

### 2.2 Assumptions

| Assumption | Reason |
|---|---|
| The repository will continue to target Microsoft Defender XDR Advanced Hunting KQL. | Current repo structure and README are built around Defender XDR Advanced Hunting. |
| BlueHammer platform exposure reporting can be added as a separate query or template. | The repo currently states it does not determine patch compliance. |
| Some tenant environments may not expose `AvPlatformVersion` directly in Advanced Hunting. | MDE tenant telemetry differs; the repo already warns about schema and sensor variance. |
| Production detections should be conservative. | Current repo docs warn that weak standalone stages can be noisy. |

### 2.3 Limits / Do Not Overclaim

| Limit | Required Handling |
|---|---|
| No verified public CVE for RedSun found in this review. | Keep RedSun as behavior-focused; do not invent a CVE. |
| No verified public CVE for UnDefend found in this review. | Keep UnDefend as behavior-focused; do not invent a CVE. |
| Huntress filenames are renameable. | Use as hunting/enrichment, not as standalone critical proof. |
| Huntress VPN IPs are intrusion-cluster indicators, not endpoint exploit proof. | Keep them in external telemetry documentation only. |
| Cloud Files Mini Filter mitigation can break business functionality. | Document as a tested compensating control only, not a universal fix. |

---

## 3. Upgrade Scope

### 3.1 In Scope

- Correcting BlueHammer version baseline.
- Adding source traceability.
- Adding BlueHammer platform exposure reporting.
- Updating BlueHammer detection-name logic.
- Adding cross-family observed tooling detection.
- Adding BeigeBurrow follow-on tunnel detection.
- Adding recon-near-tooling correlation detection.
- Adding RedSun mitigation documentation.
- Adding UnDefend observed tooling and Defender-health guidance.
- Creating production-safe detection variants.
- Strengthening repository validation.

### 3.2 Out of Scope

- Directly enabling scheduled detections in production.
- Pushing tenant-specific allowlists into the public repo.
- Adding unverified CVEs, hashes, domains, or IPs.
- Treating third-party blog statements as stronger than Microsoft/NVD where Microsoft/NVD data exists.
- Making Cloud Files Mini Filter disablement a blanket enterprise recommendation.

---

## 4. Branch and Change-Control Plan

### 4.1 Create Upgrade Branch

```bash
git checkout main
git pull origin main
git checkout -b upgrade/verified-iocs-and-production-hardening
```

### 4.2 Commit Strategy

Use small, reviewable commits:

| Commit | Purpose |
|---|---|
| `docs: correct bluehammer fixed platform baseline` | README and package README correction. |
| `docs: add source traceability and mitigation references` | `SOURCES.md`, `MITIGATIONS.md`, `IOCS.md`. |
| `feat: add bluehammer platform exposure query` | Exposure reporting. |
| `feat: add cross-family nightmare eclipse detections` | Tooling, BeigeBurrow, recon correlation. |
| `feat: add production conservative detection variants` | Scheduled-detection-safe variants. |
| `ci: enforce metadata and source traceability` | Validation upgrades. |
| `docs: add deployment guide and attack mapping` | Operational rollout docs. |

### 4.3 Pre-Merge Review Requirements

- KQL syntax reviewed in Defender Advanced Hunting.
- New IOCs mapped in `SOURCES.md`.
- No critical severity assigned to filename-only matches.
- `4.18.26050.3011` no longer appears as the fixed BlueHammer version.
- Production variants are separated from hunting variants.
- Known operational impacts documented.

---

## 5. Repository Structure Changes

### 5.1 Proposed Final Structure

```text
redsun-bluehammer-undefend-detection-pack/
├── README.md
├── CHANGELOG.md
├── SOURCES.md
├── MITIGATIONS.md
├── ATTACK_MAPPING.md
├── DEPLOYMENT_GUIDE.md
├── IOCS.md
├── Exposure/
│   ├── README.md
│   └── 01_bluehammer_defender_platform_exposure.kql
├── BlueHammer/
│   ├── README.md
│   ├── 01_bluehammer_full_attack_chain.kql
│   ├── 02_...existing...
│   ├── 17_bluehammer_stage7_microsoft_detection_name.kql
│   └── production/
│       └── bluehammer_conservative_custom_detection.kql
├── RedSun/
│   ├── README.md
│   ├── 01_redsun_full_attack_chain.kql
│   └── production/
│       └── redsun_conservative_custom_detection.kql
├── UnDefend/
│   ├── README.md
│   ├── 01_undefend_full_attack_chain.kql
│   ├── 09_undefend_defender_health_and_signature_staleness.kql
│   └── production/
│       └── undefend_conservative_custom_detection.kql
├── CrossFamily/
│   ├── README.md
│   ├── 01_observed_nightmare_eclipse_tooling_execution.kql
│   ├── 02_beigeburrow_follow_on_tunnel_activity.kql
│   ├── 03_recon_near_observed_tooling.kql
│   └── production/
│       └── nightmare_eclipse_conservative_custom_detection.kql
├── ExternalTelemetry/
│   └── README.md
└── .github/
    ├── workflows/
    │   └── validate.yml
    └── scripts/
        └── validate_repository.py
```

### 5.2 Reason for New Folders

| Folder | Reason |
|---|---|
| `Exposure/` | Separates patch/platform exposure reporting from exploit behavior detection. |
| `CrossFamily/` | Holds intrusion-cluster detections that cut across BlueHammer, RedSun, UnDefend, and BeigeBurrow. |
| `ExternalTelemetry/` | Stores VPN/firewall/SIEM indicators that do not belong in endpoint-only KQL. |
| `production/` subfolders | Holds conservative scheduled-detection candidates separate from broader hunting queries. |

---

## 6. BlueHammer Updates

### 6.1 Correct Fixed Defender Platform Baseline

#### Files

```text
README.md
BlueHammer/README.md
CHANGELOG.md
SOURCES.md
Exposure/README.md
```

#### Replace

```text
4.18.26050.3011
```

#### With

```text
4.18.26030.3011
```

#### Required Wording

```markdown
BlueHammer maps to CVE-2026-33825. Public NVD and Microsoft release data identify Microsoft Defender Antimalware Platform versions before 4.18.26030.3011 as affected. Treat 4.18.26030.3011 or later as the minimum verified patched Defender platform baseline for BlueHammer exposure reporting.
```

#### Verification Command

```bash
grep -R "4.18.26050.3011" .
```

Expected result:

```text
No output
```

### 6.2 Update BlueHammer Detection Names

#### Files

```text
BlueHammer/17_bluehammer_stage7_microsoft_detection_name.kql
BlueHammer/01_bluehammer_full_attack_chain.kql
BlueHammer/README.md
SOURCES.md
CHANGELOG.md
```

#### Current Matching Logic Includes

```text
Behavior:Win32/CVE-2026-33825.Z!MTB
Exploit:Win32/DfndrPEBluHmr.BB
CVE-2026-33825
DfndrPEBluHmr
```

#### Add

```kql
or AdditionalFieldsText contains "Exploit:Win32/DfndrPEBluHmr.BZ"
```

#### Documentation Note

```markdown
The generic `DfndrPEBluHmr` substring should catch related family names, but exact observed names are retained for analyst clarity and source traceability.
```

### 6.3 Add BlueHammer Platform Exposure Query

#### New File

```text
Exposure/01_bluehammer_defender_platform_exposure.kql
```

#### Required Query Output

| Column | Purpose |
|---|---|
| `DeviceName` | Device identity. |
| `DeviceId` | Defender device ID. |
| `AvPlatformVersion` | Defender platform version. |
| `RequiredPlatformVersion` | Static baseline: `4.18.26030.3011`. |
| `ExposureStatus` | `Patched`, `Exposed`, `Unknown`. |
| `RecommendedAction` | Upgrade or verify platform telemetry. |
| `SourceRefs` | `SOURCES.md#bluehammer`. |

#### Version Comparison Rule

Do **not** compare version strings directly.

Correct approach:

```kql
let RequiredMajor = 4;
let RequiredMinor = 18;
let RequiredBuild = 26030;
let RequiredRevision = 3011;
```

Then parse version components numerically.

#### Implementation Guidance

Because Defender XDR tenant schemas may differ, implement this as a **template** if `AvPlatformVersion` is not consistently available in your Advanced Hunting tables.

Recommended comment block:

```kql
// Replace SourceTable and AvPlatformVersion column with the tenant-verified
// Defender platform version source. Examples include Intune Defender Antivirus
// reporting exports, custom inventory ingestion, or tenant-specific Defender
// health telemetry if available in Advanced Hunting.
```

#### Documentation Requirement

`Exposure/README.md` must explain:

- this is not exploit detection,
- this is exposure reporting,
- the source of `AvPlatformVersion` must be tenant-verified,
- stale or missing platform data must be treated as `Unknown`, not automatically `Patched`.

---

## 7. RedSun Updates

### 7.1 Keep RedSun as Behavior-Focused

Do not add a CVE unless Microsoft/NVD publishes one.

#### Files

```text
RedSun/README.md
README.md
SOURCES.md
```

#### Required Wording

```markdown
No public Microsoft CVE or vendor patch for RedSun was verified during the 2026-05-05 review. This package remains behavior-focused and should not be presented as patch-compliance detection.
```

### 7.2 Add Cloud Files Mini Filter Mitigation Documentation

#### Files

```text
RedSun/README.md
MITIGATIONS.md
SOURCES.md
CHANGELOG.md
```

#### Add Section

```markdown
## Compensating Control: Cloud Files Mini Filter

Where operationally acceptable, assess disabling the Cloud Files Mini Filter service on systems that do not require OneDrive Files On-Demand or other Cloud Files placeholder functionality.

This is a compensating control, not a vendor patch. It must be tested before broad deployment because it can prevent the Windows Cloud Files platform from loading and can block cloud file placeholder and on-demand hydration functionality.
```

#### Add Warning

```markdown
Do not apply this mitigation globally without business validation. It may affect OneDrive Files On-Demand and other Cloud Files API integrations.
```

### 7.3 RedSun Production Variant

#### New File

```text
RedSun/production/redsun_conservative_custom_detection.kql
```

#### Production Conditions

Trigger production alert only if one of these is true:

| Condition | Severity |
|---|---|
| Microsoft RedSun detection-name telemetry | Critical |
| Storage Tiers COM activation + System32 `TieringEngineService.exe` write | Critical |
| Storage Tiers COM activation + SYSTEM `conhost.exe` spawn | Critical |
| Cloud Files sync-root registration + reparse/junction/oplock evidence | High |
| `TieringEngineService.exe` staged in temp + System32 write | High |
| Three or more RedSun stages | High |

#### Do Not Alert Production On

- `cldapi.dll` load alone.
- temp file staging alone.
- reparse/oplock telemetry alone.
- Cloud Files sync-root registration alone.

---

## 8. UnDefend Updates

### 8.1 Keep UnDefend as Behavior-Focused

Do not add a CVE unless Microsoft/NVD publishes one.

#### Files

```text
UnDefend/README.md
README.md
SOURCES.md
```

#### Required Wording

```markdown
No public Microsoft CVE or vendor patch for UnDefend was verified during the 2026-05-05 review. This package remains behavior-focused and should focus on Defender degradation, signature-file access, update failures, and health-staleness evidence.
```

### 8.2 Add Observed Tooling Logic

#### Recommended Location

Primary:

```text
CrossFamily/01_observed_nightmare_eclipse_tooling_execution.kql
```

Optional UnDefend-specific standalone query:

```text
UnDefend/09_undefend_observed_tooling_execution.kql
```

#### Indicators

```text
undef.exe
z.exe
undef.exe -h
undef.exe -aggressive
undef.exe -agressive
```

Include both spellings:

| Spelling | Reason |
|---|---|
| `-aggressive` | Correct spelling. |
| `-agressive` | Observed misspelling in Huntress report. |

#### Severity Rule

| Match | Severity |
|---|---|
| `undef.exe` or `z.exe` from user-writable path + Defender failure/update failure | High |
| `undef.exe -aggressive` / `-agressive` + Defender failure/update failure | Critical |
| Filename only | Medium / hunting |

### 8.3 Add Defender Health and Signature Staleness Query

#### New File

```text
UnDefend/09_undefend_defender_health_and_signature_staleness.kql
```

If `09` conflicts with an observed-tooling query, use:

```text
UnDefend/10_undefend_defender_health_and_signature_staleness.kql
```

#### Purpose

Detect cases where Defender appears present but:

- platform version is stale,
- signature version is stale,
- update failures recur,
- service/update telemetry indicates degradation,
- Defender signature files were accessed by non-Defender processes before degradation.

#### Required Output

| Column | Purpose |
|---|---|
| `DeviceName` | Device identity. |
| `DeviceId` | Defender device ID. |
| `FirstSuspiciousAccess` | First Defender signature/definition access by non-Defender process. |
| `FirstFailure` | First update/engine/service failure after suspicious access. |
| `SuspiciousProcesses` | Processes touching Defender files. |
| `FailureEvents` | Update/service failure context. |
| `RecommendedAction` | Validate Defender health, update history, and local service status. |

#### Production Rule

Do not make stale signatures alone a critical alert. Use it as a health signal unless paired with suspicious process activity or observed UnDefend tooling.

---

## 9. Cross-Family Updates

### 9.1 Add Observed Nightmare-Eclipse Tooling Detection

#### New File

```text
CrossFamily/01_observed_nightmare_eclipse_tooling_execution.kql
```

#### Indicators

```text
FunnyApp.exe
RedSun.exe
undef.exe
z.exe
```

#### Path Focus

Prioritise:

```text
\Users\
\Pictures\
\Downloads\
\AppData\Local\Temp\
\Windows\Temp\
```

#### Severity Model

| Condition | Severity |
|---|---|
| Observed filename + vendor Defender detection | Critical |
| Observed filename + user-writable path + recon nearby | High |
| Observed filename + user-writable path | Medium |
| Observed filename outside suspicious context | Low / hunting |

#### Required Comment

```kql
// Filename-only matches are renameable and must not be treated as deterministic compromise.
```

### 9.2 Add BeigeBurrow Follow-On Tunnel Detection

#### New File

```text
CrossFamily/02_beigeburrow_follow_on_tunnel_activity.kql
```

#### Indicators

```text
agent.exe -server staybud.dpdns[.]org:443 -hide
staybud.dpdns[.]org
a2b6c7a9c4490df70de3cdbfa5fc801a3e1cf6a872749259487e354de2876b7c
```

#### Data Sources

```text
DeviceProcessEvents
DeviceNetworkEvents
DeviceFileEvents
```

#### Severity Model

| Condition | Severity |
|---|---|
| SHA-256 match | Critical |
| Exact `agent.exe -server staybud.dpdns.org:443 -hide` | Critical |
| Network event to `staybud.dpdns.org` | High |
| Similar `agent.exe -server * -hide` from user context | Medium / hunting |

#### Documentation Note

```markdown
BeigeBurrow is follow-on intrusion tooling. It is not one of the Defender exploit primitives, but it materially increases incident severity when observed near BlueHammer, RedSun, or UnDefend activity.
```

### 9.3 Add Recon-Near-Tooling Correlation

#### New File

```text
CrossFamily/03_recon_near_observed_tooling.kql
```

#### Recon Commands

```text
whoami /priv
cmdkey /list
net group
```

#### Correlation Window

```text
30 minutes before or after suspicious tooling execution
```

#### Correlate Against

```text
FunnyApp.exe
RedSun.exe
undef.exe
z.exe
agent.exe
Exploit:Win32/DfndrPEBluHmr.BZ
suspicious EICAR alert tied to unknown binary
```

#### Severity Model

| Condition | Severity |
|---|---|
| Recon + BeigeBurrow | Critical |
| Recon + observed tooling | High |
| Recon alone | Low / hunting |
| Recon from admin automation account | Tune / allowlist after validation |

---

## 10. External Telemetry and IOC Documentation

### 10.1 Create External Telemetry Documentation

#### New File

```text
ExternalTelemetry/README.md
```

#### Add VPN IP Indicators

```text
78.29.48.29
212.232.23.69
179.43.140.214
```

#### Required Warning

```markdown
These IP addresses were observed in one intrusion cluster involving Nightmare-Eclipse tooling and suspicious FortiGate SSL VPN access. They should be used for VPN, firewall, identity, and SIEM correlation. They must not be treated as deterministic endpoint exploit indicators.
```

### 10.2 Create IOCS.md

#### New File

```text
IOCS.md
```

#### Required Table

```markdown
| Indicator | Type | Family / Context | Confidence | Recommended Use | Source |
|---|---|---|---|---|---|
| Exploit:Win32/DfndrPEBluHmr.BZ | Defender detection name | BlueHammer | High | Endpoint detection and triage | Huntress |
| FunnyApp.exe | Filename | BlueHammer observed tooling | Medium | Hunting/enrichment | Huntress |
| RedSun.exe | Filename | RedSun observed tooling | Medium | Hunting/enrichment | Huntress |
| undef.exe | Filename | UnDefend observed tooling | Medium | Hunting/enrichment | Huntress |
| z.exe | Filename | UnDefend renamed companion binary | Medium | Hunting/enrichment | Huntress |
| staybud.dpdns.org | Domain | BeigeBurrow | High | Endpoint/network correlation | Huntress |
| a2b6c7a9c4490df70de3cdbfa5fc801a3e1cf6a872749259487e354de2876b7c | SHA-256 | BeigeBurrow agent.exe | High | Hash detection | Huntress |
| 78.29.48.29 | IP | FortiGate SSL VPN source IP | Medium | VPN/firewall correlation only | Huntress |
| 212.232.23.69 | IP | FortiGate SSL VPN source IP | Medium | VPN/firewall correlation only | Huntress |
| 179.43.140.214 | IP | FortiGate SSL VPN source IP | Medium | VPN/firewall correlation only | Huntress |
```

---

## 11. Production Detection Separation

### 11.1 Rule

The existing `01_*_full_attack_chain.kql` queries remain **hunting queries**.

Production scheduled detections must live under:

```text
BlueHammer/production/
RedSun/production/
UnDefend/production/
CrossFamily/production/
```

### 11.2 Production Query Requirements

Every production query must include:

```text
AlertSeverity
DetectionReason
RecommendedAction
SourceRefs
TTP
FirstSeen
LastSeen
DeviceName
DeviceId
StageCount
Evidence
ReportRefs
```

### 11.3 Production Exclusion Rules

Do not create production high/critical alerts from:

| Weak Condition | Reason |
|---|---|
| Filename only | Renameable. |
| EICAR alone | Common in testing and PoC validation. |
| `cldapi.dll` load alone | Legitimate sync clients. |
| Defender update failure alone | Common benign network/proxy/service issue. |
| Service query alone | Common admin and monitoring behavior. |
| Recon command alone | Common admin behavior. |

### 11.4 Conservative Production Conditions

#### BlueHammer

| Condition | Severity |
|---|---|
| Microsoft Defender BlueHammer detection-name telemetry | Critical |
| VSS hive read + GUID service or suspicious conhost | Critical |
| LSA boot-key read + `samlib.dll`/`offreg.dll` + execution stage | High |
| Defender update CDN download + Cloud Files or VSS activity | High |
| Four or more BlueHammer stages | High |

#### RedSun

| Condition | Severity |
|---|---|
| Microsoft RedSun detection-name telemetry | Critical |
| Storage Tiers COM activation + System32 write | Critical |
| Storage Tiers COM activation + SYSTEM conhost | Critical |
| Cloud Files sync-root + reparse/oplock evidence | High |
| Three or more RedSun stages | High |

#### UnDefend

| Condition | Severity |
|---|---|
| Observed UnDefend tooling + Defender update/service failure | Critical |
| Signature file access + Defender update/engine failure | High |
| Defender directory monitoring + WinDefend stop/reconfigure | High |
| Three or more UnDefend stages with Defender file/service stage | High |

#### CrossFamily

| Condition | Severity |
|---|---|
| BeigeBurrow SHA-256 or exact command line | Critical |
| Observed tooling + recon nearby | High |
| Observed tooling + suspicious Defender detection | Critical |
| VPN IOC + endpoint tooling + same user context | Critical in SIEM correlation |

---

## 12. Documentation Updates

### 12.1 README.md

Add a section near the top:

```markdown
## Verified Research Baseline

Last verified: 2026-05-05

- BlueHammer: CVE-2026-33825, fixed baseline Microsoft Defender Antimalware Platform 4.18.26030.3011 or later.
- RedSun: no public Microsoft CVE or vendor patch verified during this review; behavior-focused detection and compensating controls required.
- UnDefend: no public Microsoft CVE or vendor patch verified during this review; behavior-focused detection and Defender-health validation required.
- Huntress observed real-world intrusion activity involving BlueHammer, RedSun, UnDefend, and BeigeBurrow follow-on tooling.
```

### 12.2 SOURCES.md

Add source-traceability table.

Required fields:

```text
Family
Item
Type
Source
Date verified
Repo files updated
Notes
```

### 12.3 MITIGATIONS.md

Required sections:

```markdown
# Mitigations and Compensating Controls

## BlueHammer
- Upgrade Defender Antimalware Platform to 4.18.26030.3011 or later.
- Validate platform version from trusted tenant inventory.

## RedSun
- No verified vendor patch during this review.
- Assess Cloud Files Mini Filter disablement only where operationally acceptable.
- Test impact on OneDrive Files On-Demand and Cloud Files integrations.

## UnDefend
- Monitor Defender update health and signature staleness.
- Investigate suspicious signature-file access followed by update or engine failures.
```

### 12.4 ATTACK_MAPPING.md

Required table:

```markdown
| Family | Detection Area | ATT&CK Technique | Reason |
|---|---|---|---|
| BlueHammer | Local privilege escalation | T1068 | Defender vulnerability abuse for elevated execution. |
| BlueHammer | SAM / hive access | T1003.002 | Credential material access from SAM/VSS paths. |
| RedSun | Local privilege escalation | T1068 | Defender behavior abused for privileged file write. |
| RedSun | Reparse/junction pivot | T1574.010 | File/path redirection behavior. |
| UnDefend | Defender degradation | T1562.001 | Impairing security tooling/update capability. |
| CrossFamily | BeigeBurrow tunneling | T1572 / T1090 | Reverse tunnel / proxy-style follow-on access. |
| CrossFamily | Recon commands | T1033 / T1087 | Privilege and account/group discovery. |
```

### 12.5 DEPLOYMENT_GUIDE.md

Required sections:

1. Lab validation.
2. Pilot deployment.
3. Production scheduled detection.
4. Severity model.
5. Analyst response.
6. Allowlist governance.
7. Rollback plan.
8. Review cadence.

### 12.6 CHANGELOG.md

Add:

```markdown
## 2026-05-05

### Changed
- Corrected BlueHammer fixed Defender platform baseline to 4.18.26030.3011.
- Clarified RedSun and UnDefend as behavior-focused packages without verified public Microsoft CVEs during this review.

### Added
- Source traceability file.
- BlueHammer Defender platform exposure query.
- BlueHammer `Exploit:Win32/DfndrPEBluHmr.BZ` detection-name coverage.
- Cross-family observed Nightmare-Eclipse tooling detections.
- BeigeBurrow follow-on tunneling detection.
- Reconnaissance-near-tooling correlation detection.
- External telemetry IOC documentation.
- Conservative production detection folder structure.
- Deployment guide, mitigation guide, and ATT&CK mapping.
```

---

## 13. KQL Metadata Standard

### 13.1 Required Metadata Block

Add this block below the existing SPDX / copyright / AI-generated warning header in every KQL file:

```kql
// DetectionMetadata:
//   Family: BlueHammer
//   QueryType: Hunting
//   Severity: High
//   Confidence: Medium
//   DataSources: DeviceEvents, DeviceProcessEvents
//   ATTACK: T1068, T1003.002
//   SourceRefs: SOURCES.md#bluehammer
//   ProductionReady: No
//   LastVerified: 2026-05-05
```

### 13.2 Allowed Values

| Field | Allowed Values |
|---|---|
| `QueryType` | `Hunting`, `Exposure`, `Production`, `Triage`, `ExternalCorrelation` |
| `Severity` | `Informational`, `Low`, `Medium`, `High`, `Critical` |
| `Confidence` | `Low`, `Medium`, `High` |
| `ProductionReady` | `Yes`, `No` |

### 13.3 SourceRefs Rule

Every KQL file with an IOC must point to a source anchor:

```text
SOURCES.md#bluehammer
SOURCES.md#redsun
SOURCES.md#undefend
SOURCES.md#crossfamily
SOURCES.md#externaltelemetry
```

---

## 14. CI Validation Upgrade

### 14.1 Existing Validator

The current validation script already checks:

- required KQL header,
- `let Lookback =`,
- balanced delimiters,
- contiguous file numbering,
- full-chain first-file naming,
- standalone stage alignment,
- README KQL basename coverage.

Keep these checks.

### 14.2 Add New Checks

Update:

```text
.github/scripts/validate_repository.py
```

Add checks for:

| Check | Failure Condition |
|---|---|
| Metadata block exists | Missing `// DetectionMetadata:` block. |
| Required metadata keys exist | Any required key missing. |
| Production placement | `ProductionReady: Yes` outside `/production/`. |
| Hunting placement | `QueryType: Hunting` inside `/production/`. |
| SourceRefs exists | IOC-bearing query has no `SourceRefs`. |
| Wrong BlueHammer fixed version | `4.18.26050.3011` appears anywhere except historical changelog notes. |
| Filename-only critical severity | `FunnyApp.exe`, `RedSun.exe`, `undef.exe`, or `z.exe` query sets `Severity: Critical` without correlation condition. |
| IOC source mapping | IOC appears in KQL but not in `SOURCES.md` or `IOCS.md`. |

### 14.3 Suggested Python Validation Logic

```python
REQUIRED_METADATA_KEYS = {
    "Family",
    "QueryType",
    "Severity",
    "Confidence",
    "DataSources",
    "ATTACK",
    "SourceRefs",
    "ProductionReady",
    "LastVerified",
}

FORBIDDEN_FIXED_VERSION = "4.18.26050.3011"

IOC_STRINGS = {
    "Exploit:Win32/DfndrPEBluHmr.BZ",
    "FunnyApp.exe",
    "RedSun.exe",
    "undef.exe",
    "z.exe",
    "staybud.dpdns.org",
    "a2b6c7a9c4490df70de3cdbfa5fc801a3e1cf6a872749259487e354de2876b7c",
}
```

### 14.4 Workflow

Current workflow can remain simple:

```yaml
- name: Run repository validation
  run: python .github/scripts/validate_repository.py
```

Add Markdown link/style validation later if needed.

---

## 15. Tenant Testing Plan

### 15.1 Lab Validation

Run each standalone and new cross-family query with:

```text
Lookback = 24h
Lookback = 7d
```

Record:

- result count,
- top devices,
- top processes,
- top accounts,
- common false positives,
- event availability by table.

### 15.2 Pilot Validation

Scope to:

- test device group,
- security team devices,
- representative server OU,
- known Defender platform versions.

Validate:

- KQL compiles,
- telemetry fields exist,
- no runaway result volume,
- severity is reasonable,
- expected allowlists are documented.

### 15.3 Production Candidate Review

Only promote queries under `/production/`.

Before enabling scheduled custom detection:

- confirm action threshold,
- confirm result volume,
- confirm incident severity,
- confirm owner,
- confirm response runbook,
- confirm rollback plan.

### 15.4 Rollback

Rollback options:

| Issue | Rollback |
|---|---|
| Too many alerts | Disable scheduled detection; keep hunting query. |
| Query timeout | Reduce lookback, tighten anchors, remove weak stages. |
| False positives from known tools | Add scoped allowlist with expiry and owner. |
| Business impact from RedSun mitigation | Re-enable Cloud Files Mini Filter and document exception. |

---

## 16. Acceptance Criteria

| Area | Acceptance Criteria |
|---|---|
| Version correction | `4.18.26050.3011` is removed as fixed BlueHammer baseline. |
| BlueHammer baseline | `4.18.26030.3011` is documented as minimum verified patched platform baseline. |
| BlueHammer detection | `.BZ` detection name is present in standalone and full-chain query. |
| Exposure reporting | `Exposure/01_bluehammer_defender_platform_exposure.kql` exists. |
| RedSun documentation | RedSun states no verified public Microsoft CVE/patch during review and documents Cloud Files mitigation risk. |
| UnDefend documentation | UnDefend states no verified public Microsoft CVE/patch during review and adds health/staleness guidance. |
| CrossFamily | Observed tooling, BeigeBurrow, and recon correlation queries exist. |
| ExternalTelemetry | VPN IPs are documented outside endpoint KQL. |
| Production separation | Conservative production variants exist under `/production/`. |
| Source traceability | `SOURCES.md` maps all CVEs, versions, IOCs, and mitigations. |
| CI | Metadata and source mapping are enforced. |
| Safety | Filename-only indicators are not critical detections. |
| Deployment | `DEPLOYMENT_GUIDE.md` exists with lab, pilot, production, and rollback steps. |

---

## 17. Priority Implementation Order

### Priority 1: Correctness

1. Correct BlueHammer fixed platform version to `4.18.26030.3011`.
2. Add `SOURCES.md`.
3. Update `README.md`, `BlueHammer/README.md`, and `CHANGELOG.md`.
4. Add `.BZ` BlueHammer detection name.

### Priority 2: Detection Coverage

1. Add platform exposure query.
2. Add observed tooling query.
3. Add BeigeBurrow query.
4. Add recon-near-tooling query.
5. Add UnDefend health/staleness query.

### Priority 3: Production Safety

1. Add `/production/` query variants.
2. Apply conservative severity logic.
3. Add production deployment guide.

### Priority 4: Governance

1. Add KQL metadata standard.
2. Extend CI validation.
3. Add ATT&CK mapping.
4. Add mitigation and external telemetry docs.

---

## 18. Final PR Checklist

Status as of `2026-05-05`: repository-side implementation items below are complete. Live Defender Advanced Hunting execution remains tenant-specific and is still pending as an operational validation step.

- [x] BlueHammer fixed baseline corrected to `4.18.26030.3011`.
- [x] No unsupported RedSun or UnDefend CVE added.
- [x] `SOURCES.md` includes the documented CVEs, versions, IOCs, and mitigation references used by the repository.
- [x] BlueHammer `.BZ` detection added to the standalone and full-chain query.
- [x] `CrossFamily/` added with the shared-hunting queries and production variant.
- [x] `Exposure/` added with the BlueHammer platform exposure template query.
- [x] `ExternalTelemetry/` documents VPN IPs outside endpoint KQL.
- [x] RedSun mitigation guidance includes the Cloud Files impact warning.
- [x] UnDefend health and staleness guidance added.
- [x] Production queries live under `/production/`.
- [x] Filename-only detections are not treated as `Critical`.
- [x] KQL metadata blocks added across the current query inventory.
- [x] The validator checks metadata and source traceability.
- [ ] Queries tested in Defender Advanced Hunting across a live tenant.
- [x] False-positive sources and allowlist governance are documented.
- [x] `CHANGELOG.md` updated.

---

## 19. Source Links

| Source | Use |
|---|---|
| NVD CVE-2026-33825: https://nvd.nist.gov/vuln/detail/CVE-2026-33825 | CVE, severity, affected platform versions, CISA KEV status. |
| Microsoft Defender release notes: https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-releases | Defender platform `4.18.26030.3011`. |
| Huntress Nightmare-Eclipse intrusion report: https://www.huntress.com/blog/nightmare-eclipse-intrusion | Real-world BlueHammer, RedSun, UnDefend, BeigeBurrow, recon, VPN IOCs. |
| Qualys RedSun mitigation guidance: https://blog.qualys.com/qualys-insights/2026/04/22/dont-wait-for-a-patch-mitigate-redsun-risk-in-microsoft-defender-today | RedSun Cloud Files Mini Filter mitigation and operational impact. |

---

## 20. Recommended Next Step

Create the upgrade branch and implement **Priority 1** first. Do not begin production detection variants until the baseline correction, source traceability, and BlueHammer `.BZ` update are complete.
