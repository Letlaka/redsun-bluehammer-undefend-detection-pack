# Security Policy

**Project notice: This repository contains AI-generated detection content. The scripts are not guaranteed to be correct or safe. Review, test, tune, and verify every script before production deployment.**

## Supported Content

This repository contains Microsoft Defender XDR Advanced Hunting queries and documentation. It does not provide a supported product, managed service, or emergency incident response channel.

Security reports may relate to:

- Query logic that creates severe false negatives.
- Query logic that creates severe false positives with operational impact.
- Unsafe documentation that could lead to harmful deployment behavior.
- Sensitive data accidentally committed to the repository.
- Detection content that unintentionally includes offensive implementation detail.
- GitHub workflow, template, or repository hygiene issues that expose data.

## Reporting a Security Issue

If this repository is hosted on GitHub, use GitHub private vulnerability reporting if enabled. If private reporting is not enabled, contact the repository owner through the configured project contact channel.

Do not open a public issue for:

- Secrets.
- Sensitive tenant data.
- Unredacted logs.
- Live incident details.
- Vulnerability details that could cause immediate harm.

When reporting, include:

- A short summary.
- Affected file path.
- Why it is a security issue.
- Reproduction or evidence, sanitized where required.
- Recommended fix if known.
- Whether the issue affects production deployment decisions.

## Sensitive Data Handling

Do not include unredacted:

- Tenant IDs.
- Device IDs.
- User names.
- Hostnames.
- IP addresses tied to internal environments.
- File paths containing personal or customer identifiers.
- Command lines containing secrets.
- Defender alert evidence from active investigations.

Use synthetic examples or redact values before sharing.

## Response Expectations

This repository does not guarantee response times. It is not an emergency security contact.

For active compromise, suspected compromise, or urgent operational impact:

- Follow your organization's incident response process.
- Use Microsoft Defender XDR incident response workflows.
- Contact Microsoft support or your security provider through official channels.

## Production Safety

Before deploying any query from this repository as a scheduled detection:

1. Run the query in Advanced Hunting.
2. Confirm the query compiles in your tenant.
3. Validate table and column availability.
4. Review result volume.
5. Tune known-good software, paths, accounts, and service activity.
6. Test alert routing and severity.
7. Document residual false-positive and false-negative risk.
