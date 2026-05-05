# External Telemetry

This folder stores correlation guidance for indicators that do not belong in endpoint-only hunting queries.

Last reviewed: `2026-05-05`

Source basis: Huntress intrusion reporting as mapped in `SOURCES.md`.

## FortiGate SSL VPN Source IPs

Observed in one Huntress-documented intrusion cluster:

- `78.29.48.29`
- `212.232.23.69`
- `179.43.140.214`

## Warning

These IP addresses should be used for VPN, firewall, identity, and SIEM correlation. They must not be treated as deterministic endpoint exploit indicators, and they are intentionally not embedded in the endpoint KQL queries in this repository.
