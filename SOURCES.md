# Sources

This file maps repository claims and additions to the public sources used to verify them.

Last reviewed: `2026-05-05`

## BlueHammer

Metadata reference anchor for BlueHammer-related queries and documentation.

## RedSun

Metadata reference anchor for RedSun-related queries and documentation.

## UnDefend

Metadata reference anchor for UnDefend-related queries and documentation.

## CrossFamily

Metadata reference anchor for CrossFamily-related queries and documentation.

## ExternalTelemetry

Metadata reference anchor for documentation-only external telemetry indicators.

| Family | Item | Type | Source | Date verified | Repo files updated | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| BlueHammer | `CVE-2026-33825` | CVE | NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-33825 | 2026-05-05 | `README.md`, `BlueHammer/README.md`, `SOURCES.md` | Local privilege escalation in Microsoft Defender; repository uses it as context, not as patch-compliance proof. |
| BlueHammer | Defender Antimalware Platform `4.18.26030.3011` minimum verified patched baseline | Platform baseline | NVD affected-platform data and Microsoft Defender release notes: https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-releases | 2026-05-05 | `README.md`, `BlueHammer/README.md`, `MITIGATIONS.md`, `SOURCES.md` | Conflicting third-party references to `4.18.26050.3011` are treated as non-authoritative until Microsoft publishes that baseline for this CVE. |
| BlueHammer | `Exploit:Win32/DfndrPEBluHmr.BZ` | Defender detection name | Huntress: https://www.huntress.com/blog/nightmare-eclipse-intrusion | 2026-05-05 | `BlueHammer/01_bluehammer_full_attack_chain.kql`, `BlueHammer/17_bluehammer_stage7_microsoft_detection_name.kql`, `BlueHammer/README.md`, `IOCS.md` | Exact observed vendor detection retained alongside the broader `DfndrPEBluHmr` family substring. |
| CrossFamily | `FunnyApp.exe`, `RedSun.exe`, `undef.exe`, `z.exe` | Observed filenames | Huntress: https://www.huntress.com/blog/nightmare-eclipse-intrusion | 2026-05-05 | `CrossFamily/README.md`, `CrossFamily/01_crossfamily_full_attack_chain.kql`, `CrossFamily/02_crossfamily_stage1_observed_tooling_execution.kql`, `IOCS.md` | Filename-only matches are renameable and must remain hunting or enrichment signals. |
| CrossFamily | BeigeBurrow `agent.exe -server staybud.dpdns.org:443 -hide` | Command line | Huntress: https://www.huntress.com/blog/nightmare-eclipse-intrusion | 2026-05-05 | `CrossFamily/README.md`, `CrossFamily/01_crossfamily_full_attack_chain.kql`, `CrossFamily/03_crossfamily_stage2_beigeburrow_tunnel_activity.kql`, `IOCS.md` | Exact command-line matches are higher confidence than loose `agent.exe` patterns. |
| CrossFamily | `staybud.dpdns.org` | Domain | Huntress: https://www.huntress.com/blog/nightmare-eclipse-intrusion | 2026-05-05 | `CrossFamily/README.md`, `CrossFamily/01_crossfamily_full_attack_chain.kql`, `CrossFamily/03_crossfamily_stage2_beigeburrow_tunnel_activity.kql`, `IOCS.md` | Domain matches are useful for endpoint and network correlation; not proof by themselves. |
| CrossFamily | `a2b6c7a9c4490df70de3cdbfa5fc801a3e1cf6a872749259487e354de2876b7c` | SHA-256 | Huntress: https://www.huntress.com/blog/nightmare-eclipse-intrusion | 2026-05-05 | `CrossFamily/README.md`, `CrossFamily/01_crossfamily_full_attack_chain.kql`, `CrossFamily/03_crossfamily_stage2_beigeburrow_tunnel_activity.kql`, `IOCS.md` | Used for high-confidence BeigeBurrow hunting when the hash is present in endpoint telemetry. |
| CrossFamily | `whoami /priv`, `cmdkey /list`, `net group` near suspicious tooling | Recon behavior | Huntress: https://www.huntress.com/blog/nightmare-eclipse-intrusion | 2026-05-05 | `CrossFamily/README.md`, `CrossFamily/01_crossfamily_full_attack_chain.kql`, `CrossFamily/04_crossfamily_stage3_recon_near_observed_tooling.kql`, `IOCS.md` | Treated as context-strengthening behavior, not a standalone high-severity condition. |
| CrossFamily | `78.29.48.29`, `212.232.23.69`, `179.43.140.214` | VPN source IPs | Huntress: https://www.huntress.com/blog/nightmare-eclipse-intrusion | 2026-05-05 | `IOCS.md`, `CrossFamily/README.md`, `SOURCES.md` | Documentation-only. These IPs are intentionally not used in endpoint KQL in this repository. |
| RedSun | No public Microsoft CVE or vendor patch verified during the 2026-05-05 review | Review status | Huntress: https://www.huntress.com/blog/nightmare-eclipse-intrusion | 2026-05-05 | `README.md`, `RedSun/README.md`, `SOURCES.md` | Repository review inference: Huntress reported RedSun remained unpatched as of 2026-04-20. |
| RedSun | Cloud Files Mini Filter compensating-control caveat | Mitigation note | Qualys: https://blog.qualys.com/qualys-insights/2026/04/22/dont-wait-for-a-patch-mitigate-redsun-risk-in-microsoft-defender-today | 2026-05-05 | `RedSun/README.md`, `MITIGATIONS.md`, `SOURCES.md` | This is a compensating control only and can impact OneDrive Files On-Demand and related placeholder functionality. |
| UnDefend | No public Microsoft CVE or vendor patch verified during the 2026-05-05 review | Review status | Huntress: https://www.huntress.com/blog/nightmare-eclipse-intrusion | 2026-05-05 | `README.md`, `UnDefend/README.md`, `SOURCES.md` | Repository review inference: Huntress reported UnDefend remained unpatched as of 2026-04-20. |
