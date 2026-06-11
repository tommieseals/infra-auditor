# Security Policy

## Supported Versions

Only the latest release receives security fixes.

| Version | Supported |
|---------|-----------|
| 1.1.x   | Yes       |
| < 1.1   | No        |

## Reporting a Vulnerability

Please do not open a public issue for security problems.

Report vulnerabilities privately via GitHub: go to the repository's
**Security** tab and click **Report a vulnerability** (GitHub private
vulnerability reporting).

Include what you can: affected version, reproduction steps, and impact.
You can expect an acknowledgement within 7 days. Once a fix is released,
the advisory will be published and you will be credited unless you ask
otherwise.

## Scope notes

- infra-auditor executes commands on audit targets (locally or over SSH).
  Treat policy files from untrusted sources as untrusted input.
- SSH host key verification is on by default (`StrictHostKeyChecking=accept-new`).
  Disabling it with `--insecure-host-key` / `insecure_host_key: true` is at
  your own risk and is logged with a warning.
