# infra-auditor

[![CI](https://github.com/tommieseals/infra-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/tommieseals/infra-auditor/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Infrastructure compliance and security auditor** — scan systems for security drift from desired state.

Define your security policy in YAML, then audit local or remote systems to ensure compliance. Built for DevOps, SRE, and security teams who need automated infrastructure validation.

## Features

- **Policy as code** — define desired security state in YAML
- **Multi-platform** — macOS, Linux, and Windows support
- **SSH support** — audit remote systems over SSH (uses the system `ssh` binary, no extra dependencies; host keys are verified by default)
- **Modular checks** — pluggable architecture for custom checks
- **Multiple outputs** — terminal, JSON, and Markdown reports
- **CI/CD friendly** — meaningful exit codes for pipeline integration

## Quick Start

### Installation

```bash
# From a clone
git clone https://github.com/tommieseals/infra-auditor.git
cd infra-auditor
pip install -e .

# Or straight from GitHub
pip install git+https://github.com/tommieseals/infra-auditor
```

### Basic Usage

```bash
# Audit localhost with all checks
infra-auditor

# Only print failing checks
infra-auditor --quiet

# Audit a remote host
infra-auditor --host 192.168.1.10 --user admin

# Use a policy file
infra-auditor --config policy.yaml

# Output JSON for processing
infra-auditor --format json --output report.json
```

### SSH host key verification

Remote audits run `ssh` with `StrictHostKeyChecking=accept-new`: keys of
hosts seen for the first time are recorded in `known_hosts`, and a
connection is refused if a known host's key changes (possible
man-in-the-middle). To skip verification entirely — for example against
short-lived VMs with regenerated keys — pass `--insecure-host-key` on the
CLI or set `insecure_host_key: true` on the target in the policy file.
Both log a warning, because an attacker who can intercept the connection
can then read your audit traffic and credentials.

## Windows endpoint auditing

The Windows checks query the OS directly through PowerShell — `Get-NetFirewallProfile` for the firewall profiles, `Get-BitLockerVolume` for disk encryption, `netstat` for listening ports, and the `Microsoft.Update.Session` COM API for pending updates.

Real run on a Windows 11 machine (unelevated shell):

```
════════════════════════════════════════════════════════════
  Infrastructure Audit Report
════════════════════════════════════════════════════════════

  Target:     localhost
  OS:         windows
  Timestamp:  2026-06-11 06:06:11 UTC

────────────────────────────────────────────────────────────
  Compliance Score: 25.0%
  1 passed  2 failed  1 warnings  3 skipped
────────────────────────────────────────────────────────────

  CHECK RESULTS

  ✗ Open Ports
    [MEDIUM] Found 2 potentially dangerous open port(s)
    → Fix: Close unnecessary ports or add to allowed_ports

  ✗ Security Updates
    [HIGH] 3 Windows updates available
    → Fix: Open Settings > Update & Security

  ⚠ Disk Encryption
    [CRITICAL] Could not determine BitLocker status (Get-BitLockerVolume requires an elevated session)

  ✓ Firewall Status
    [HIGH] Windows Firewall is enabled on all profiles

  ○ SSH Hardening
    [HIGH] Check not supported on windows

  ○ Services
    [MEDIUM] No services configured to check

  ○ Stealth Mode
    [MEDIUM] Stealth mode is a macOS-specific feature

════════════════════════════════════════════════════════════
  Exit Code: 1 (FAILED)
════════════════════════════════════════════════════════════
```

The same machine with `--quiet` (failures only — handy in scripts and scheduled tasks):

```
✗ Open Ports
  [MEDIUM] Found 2 potentially dangerous open port(s)
  → Fix: Close unnecessary ports or add to allowed_ports
✗ Security Updates
  [HIGH] 3 Windows updates available
  → Fix: Open Settings > Update & Security

localhost: 1/4 checks passed (25.0%)
```

Notes from real-world use:

- `Get-BitLockerVolume` requires an elevated session; without one the check reports a warning instead of guessing.
- The Windows Update check counts pending updates via the COM updates session, the same source `Get-WindowsUpdate` uses, with no module installation required.
- Piped or redirected output (`infra-auditor | tee`, `> report.txt`) is emitted as UTF-8; if the stream's encoding can't be switched, the report falls back to ASCII glyphs (`x`, `=`, `[OK]`) instead of crashing with `UnicodeEncodeError` on legacy Windows codecs like cp1252.

### JSON output

Captured from the same machine (`infra-auditor --checks firewall --format json`):

```json
{
  "target": "localhost",
  "os_type": "windows",
  "timestamp": "2026-06-11T12:22:25.125440+00:00",
  "summary": {
    "total": 1,
    "passed": 1,
    "failed": 0,
    "warnings": 0,
    "skipped": 0,
    "errors": 0,
    "compliance_score": 100.0
  },
  "checks": [
    {
      "check_id": "firewall",
      "name": "Firewall Status",
      "status": "pass",
      "severity": "high",
      "message": "Windows Firewall is enabled on all profiles",
      "details": null,
      "remediation": null
    }
  ],
  "metadata": {
    "port": 22,
    "username": null
  }
}
```

## Policy Configuration

Create a YAML file to define your security policy:

```yaml
# policy.yaml
targets:
  - host: localhost
  # - host: server.example.com
  #   username: admin
  #   key_file: ~/.ssh/id_rsa
  #   insecure_host_key: false  # true disables SSH host key verification (not recommended)

checks:
  firewall:
    enabled: true
    severity: high

  disk_encryption:
    enabled: true
    severity: critical

  ssh_hardening:
    enabled: true
    severity: high

  open_ports:
    enabled: true
    params:
      allowed_ports: [22, 80, 443]
      disallowed_ports: [21, 23, 3389]

  services:
    enabled: true
    params:
      required: [sshd]
      forbidden: [telnetd]

  security_updates:
    enabled: true
    severity: high

  stealth_mode:
    enabled: true  # macOS only
```

If a check has no `severity` entry, its built-in default applies (for example `disk_encryption` defaults to critical).

## Available Checks

There are 7 built-in checks:

| Check ID | Name | Description | Platforms |
|----------|------|-------------|-----------|
| `firewall` | Firewall Status | Verify system firewall is enabled | macOS, Linux, Windows |
| `disk_encryption` | Disk Encryption | Check FileVault/LUKS/BitLocker | macOS, Linux, Windows |
| `ssh_hardening` | SSH Hardening | Validate SSH server configuration | macOS, Linux |
| `open_ports` | Open Ports | Detect dangerous listening ports | macOS, Linux, Windows |
| `services` | Services | Verify required/forbidden services | macOS, Linux, Windows |
| `security_updates` | Security Updates | Check for pending updates | macOS, Linux, Windows |
| `stealth_mode` | Stealth Mode | macOS firewall stealth mode | macOS |

List all checks:
```bash
infra-auditor --list-checks
```

## CI/CD Integration

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed |
| `1` | One or more checks failed |
| `2` | Error during audit execution |

### GitHub Actions

```yaml
- name: Security Audit
  run: |
    pip install git+https://github.com/tommieseals/infra-auditor
    infra-auditor --config policy.yaml --format json --output audit.json

- name: Upload Report
  uses: actions/upload-artifact@v4
  with:
    name: security-audit
    path: audit.json
```

### GitLab CI

```yaml
security_audit:
  script:
    - pip install git+https://github.com/tommieseals/infra-auditor
    - infra-auditor --config policy.yaml
  allow_failure: false
```

### Jenkins

```groovy
stage('Security Audit') {
    steps {
        sh 'pip install git+https://github.com/tommieseals/infra-auditor'
        sh 'infra-auditor --config policy.yaml --format json --output audit.json'
    }
    post {
        always {
            archiveArtifacts artifacts: 'audit.json'
        }
    }
}
```

## CLI Reference

```
usage: infra-auditor [options]

Infrastructure compliance and security auditor

Target:
  --host, -H          Target host (default: localhost)
  --port, -p          SSH port (default: 22)
  --user, -u          SSH username
  --key, -i           SSH private key file
  --insecure-host-key Disable SSH host key verification (insecure)
  --os-type           Override OS detection

Configuration:
  --config, -c        Path to YAML configuration file
  --checks            Comma-separated list of checks to run
  --skip-checks       Comma-separated list of checks to skip

Output:
  --format, -f        Output format: terminal, json, markdown
  --output, -o        Output file path
  --no-color          Disable colored output
  --quiet, -q         Only show failures

Other:
  --list-checks       List available checks and exit
  --version, -V       Show version and exit
```

## Extending with Custom Checks

Create your own check by extending `BaseCheck`:

```python
from infra_auditor.checks.base import BaseCheck, CheckRegistry
from infra_auditor.results import Severity

@CheckRegistry.register("my_custom_check")
class MyCustomCheck(BaseCheck):
    name = "My Custom Check"
    description = "Description of what this checks"
    supported_os = ["macos", "linux"]
    default_severity = Severity.MEDIUM

    def run(self):
        result = self.executor.run("my-command")

        if "expected" in result.output:
            return self.passed("Check passed!")
        else:
            return self.failed(
                "Check failed!",
                remediation="How to fix this"
            )
```

## Project Structure

```
infra-auditor/
├── infra_auditor/
│   ├── __init__.py         # Package exports
│   ├── auditor.py          # Main orchestrator
│   ├── config.py           # YAML config parser
│   ├── executor.py         # Local/SSH command execution
│   ├── results.py          # Result data structures
│   ├── cli.py              # Command-line interface
│   ├── checks/             # Check plugins
│   │   ├── base.py         # Base check class
│   │   ├── firewall.py
│   │   ├── encryption.py
│   │   ├── ssh_hardening.py
│   │   ├── ports.py
│   │   ├── services.py
│   │   ├── stealth.py
│   │   └── updates.py
│   └── reporters/          # Output formatters
│       ├── terminal.py
│       ├── json_reporter.py
│       └── markdown.py
├── examples/               # Example policies
├── tests/                  # Test suite
├── pyproject.toml          # Package configuration
└── README.md
```

## Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for setup and workflow. Areas of interest:

- Additional security checks
- Cloud provider checks (AWS, GCP, Azure)
- Kubernetes/container checks
- Windows-specific hardening checks
- Integration with compliance frameworks (CIS, NIST)

To report a security vulnerability, see [SECURITY.md](SECURITY.md).

## About this repo

Published as a curated snapshot of tooling I maintain; history was consolidated for publication.

## License

MIT License - see [LICENSE](LICENSE) for details.
