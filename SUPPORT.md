# Support

## Support Scope

This repository is provided as detection engineering content for Microsoft Defender XDR Advanced Hunting. It is not a commercial product, managed detection service, or emergency response service.

Support may be provided for:

- KQL syntax errors.
- Defender XDR schema compatibility issues.
- Query performance problems.
- False-positive tuning.
- Documentation corrections.
- File organization and repository maintenance.

Support is not provided for:

- Emergency incident response.
- Production deployment approval.
- Legal review.
- Tenant-specific managed detection operations.
- Microsoft product support.
- Exploit development or offensive use.

## Before Asking for Help

Before opening an issue, collect:

- Query file name.
- Exact Defender XDR error JSON or error message.
- Table and column that failed, if known.
- Lookback period used.
- Whether the standalone query or full-chain query failed.
- Approximate result volume.
- Sanitized sample rows if relevant.
- Any tenant-specific exclusions already added.

Do not include sensitive data.

## Good Support Request Format

Use this structure:

```text
Package: RedSun, BlueHammer, or UnDefend
File: path to KQL file
Query type: standalone or full-chain
Problem: syntax error, schema error, memory limit, noisy results, missing expected result
Error: exact sanitized error text
What I tried: filters, shorter lookback, standalone stage, etc.
Expected behavior: what should have happened
Actual behavior: what happened instead
```

## Operational Guidance

If a query creates too much noise:

1. Run the related standalone scripts.
2. Identify which stage is noisy.
3. Tune trusted process names and paths.
4. Reduce lookback.
5. Add device group filters for testing.
6. Re-run the full-chain query.

If a query exceeds memory or CPU limits:

1. Reduce `Lookback`.
2. Run standalone stages to isolate high-volume tables.
3. Add early filters.
4. Reduce projected columns.
5. Summarize before correlation.
