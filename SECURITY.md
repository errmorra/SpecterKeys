# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SpecterKeys itself, **do not open a public issue.**

Email the security team directly at: security@yourorg.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive a response within 48 hours. We follow responsible disclosure and will credit reporters in the release notes.

## Operational Security

SpecterKeys is a **restricted security tool**. Its existence, deployment locations, and registered honey keys must never be disclosed to anyone outside the security team.

- Do not document honey drop locations in any wiki, runbook, or ticket system accessible to general staff
- Store credentials for the deployer IAM role in a secrets vault with strict access controls
- Rotate the deployer role's own credentials every 90 days
- Audit access to this repository quarterly
