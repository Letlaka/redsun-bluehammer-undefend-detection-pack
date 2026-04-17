# Roadmap

This roadmap tracks practical improvements that would make the repository easier to validate, tune, and operate. It is not a commitment or release schedule.

## Short-Term

- Add sanitized sample outputs for each detection package.
- Add known false-positive examples for each stage.
- Add recommended custom detection thresholds for lab, pilot, and production modes.
- Add query comments that describe tenant-specific tuning points.
- Add a validation checklist for Microsoft Defender portal testing.

## Medium-Term

- Add lightweight static validation scripts for KQL files.
- Add a stage-to-table dependency matrix.
- Add a schema compatibility checklist linked to Defender XDR documentation.
- Add example triage runbooks for RedSun, BlueHammer, and UnDefend.
- Add severity mapping guidance for scheduled detections.
- Add CSV analysis examples for exported Defender results.

## Long-Term

- Add automated linting for query style and file numbering.
- Add controlled lab replay notes for each detection package.
- Add versioned releases.
- Add CI checks for Markdown formatting and KQL structure.
- Add ATT&CK mapping review notes.
- Add production deployment profiles with conservative and aggressive variants.

## Open Questions

- Which license should govern external use?
- Should the repository include generated detections only, or also manually reviewed stable detections?
- Should high-risk queries be separated from low-risk hunting queries?
- Should custom detection rule versions be stored separately from hunting versions?
