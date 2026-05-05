# Exposure Reporting

This folder contains exposure-oriented queries and templates. These are not exploit-detection queries.

Last reviewed: `2026-05-05`

## Scope

- Use these queries to identify endpoints that may still be exposed based on platform or inventory state.
- Treat all exposure results as inventory guidance that must be validated against tenant-specific data sources.
- Missing or stale inventory must be treated as `Unknown`, not automatically `Patched`.

## Current Content

| File | Role |
| --- | --- |
| `01_bluehammer_defender_platform_exposure.kql` | Template query for identifying BlueHammer exposure based on a tenant-verified Defender platform version source. |

## Important Notes

- `AvPlatformVersion` is not consistently exposed in the same Advanced Hunting table across tenants.
- `01_bluehammer_defender_platform_exposure.kql` therefore ships as a template with a compile-safe placeholder dataset.
- Replace the placeholder source with your tenant-verified platform inventory before operational use.
