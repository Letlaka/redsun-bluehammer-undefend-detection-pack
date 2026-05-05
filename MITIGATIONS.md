# Mitigations and Compensating Controls

This file only records mitigation guidance that is explicitly backed by the public sources used for this repository revision.

Last reviewed: `2026-05-05`

## BlueHammer

- Verified baseline: Microsoft Defender Antimalware Platform `4.18.26030.3011` or later.
- Source basis: NVD affected-platform data for `CVE-2026-33825` plus Microsoft Defender release notes.
- Repository handling: this baseline is documented for analyst guidance only. `Exposure/01_bluehammer_defender_platform_exposure.kql` is a template, not a tenant-agnostic compliance query, because no universal `AvPlatformVersion` source is verified here.

## RedSun

- No public Microsoft vendor patch was verified during the 2026-05-05 source review.
- Qualys documented disabling the Cloud Files Mini Filter as a possible compensating control where business impact is acceptable.
- Treat that control as environment-specific, not universal:
  - test first;
  - validate OneDrive Files On-Demand and other Cloud Files placeholder or hydration workflows;
  - document rollback steps before broad deployment.
- Do not apply this mitigation globally without business validation. It may affect OneDrive Files On-Demand and other Cloud Files API integrations.

## UnDefend

- No public Microsoft vendor patch was verified during the 2026-05-05 source review.
- Monitor Defender update health, signature freshness, and local WinDefend state after suspicious definition-file access.
- Investigate suspicious signature-file access followed by update, engine, or service-health failures before concluding benign platform drift.
