# IOCs

Observed indicators are useful for hunting and triage, but confidence varies sharply by indicator type.

Last reviewed: `2026-05-05`

| Indicator | Type | Family / Context | Confidence | Recommended use | Source | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `Exploit:Win32/DfndrPEBluHmr.BZ` | Defender detection name | BlueHammer | High | Endpoint detection and analyst triage | Huntress | Exact vendor telemetry. Keep the broader `DfndrPEBluHmr` family substring as related coverage. |
| `FunnyApp.exe` | Filename | BlueHammer observed tooling | Medium | Hunting and enrichment | Huntress | Renameable. Combine with suspicious path, parent chain, or nearby recon. |
| `RedSun.exe` | Filename | RedSun observed tooling | Medium | Hunting and enrichment | Huntress | Renameable. Do not treat as deterministic compromise proof. |
| `undef.exe` | Filename | UnDefend observed tooling | Medium | Hunting and enrichment | Huntress | Renameable. Prefer correlation with Defender degradation signals. |
| `z.exe` | Filename | UnDefend companion binary | Medium | Hunting and enrichment | Huntress | Renameable and low-context by itself. |
| `agent.exe -server staybud.dpdns.org:443 -hide` | Command line | BeigeBurrow | High | Endpoint detection and case escalation | Huntress | Exact command line is stronger than loose `agent.exe` matching. |
| `staybud.dpdns.org` | Domain | BeigeBurrow | High | Endpoint or network correlation | Huntress | Useful across endpoint and network telemetry. Not endpoint exploit proof by itself. |
| `a2b6c7a9c4490df70de3cdbfa5fc801a3e1cf6a872749259487e354de2876b7c` | SHA-256 | BeigeBurrow `agent.exe` | High | File-hash detection and triage | Huntress | High-confidence indicator when present in endpoint telemetry. |
| `whoami /priv` | Recon command | Cross-family recon | Medium | Context correlation near suspicious tooling | Huntress | Common admin command alone. Treat as context only. |
| `cmdkey /list` | Recon command | Cross-family recon | Medium | Context correlation near suspicious tooling | Huntress | Common admin command alone. Treat as context only. |
| `net group` | Recon command | Cross-family recon | Medium | Context correlation near suspicious tooling | Huntress | Common admin command alone. Treat as context only. |
| `78.29.48.29` | IP | FortiGate SSL VPN source IP | Medium | VPN, firewall, identity, and SIEM correlation only | Huntress | Documentation-only in this repository. Not used in endpoint KQL. |
| `212.232.23.69` | IP | FortiGate SSL VPN source IP | Medium | VPN, firewall, identity, and SIEM correlation only | Huntress | Documentation-only in this repository. Not used in endpoint KQL. |
| `179.43.140.214` | IP | FortiGate SSL VPN source IP | Medium | VPN, firewall, identity, and SIEM correlation only | Huntress | Documentation-only in this repository. Not used in endpoint KQL. |
