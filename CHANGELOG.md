# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-06-11

### Fixed

- `UnicodeEncodeError` crash when stdout is piped or redirected on Windows
  (legacy codecs like cp1252 cannot encode the report glyphs): the CLI now
  reconfigures stdout/stderr to UTF-8 at startup, and the terminal and
  Markdown reporters fall back to ASCII glyphs (`x`, `=`, `[OK]`) when the
  effective stream encoding cannot represent the unicode ones.
- Replaced deprecated `datetime.utcnow()` with timezone-aware
  `datetime.now(timezone.utc)`; JSON report timestamps now carry an
  explicit `+00:00` offset.

### Changed

- **SSH host key verification is now on by default.** Remote audits run
  `ssh` with `StrictHostKeyChecking=accept-new` instead of `no`: new hosts
  are recorded, changed host keys are refused. The previous behavior is
  available explicitly via `--insecure-host-key` (CLI) or
  `insecure_host_key: true` (per target in the policy file), both of which
  log a warning.

### Added

- `SECURITY.md` (private vulnerability reporting via GitHub) and
  `CONTRIBUTING.md` (dev setup, gates, and PR workflow).
- Regression tests for ASCII-only output encodings and the SSH host key
  policy.

## [1.0.1] - 2026-06-11

Maintenance release: real bug fixes, working CI, and documentation that
matches the code.

### Fixed

- `Auditor.audit(target)` discarded an explicitly passed target when
  `config.targets` was empty (operator-precedence bug), silently auditing
  localhost instead — `Auditor.quick_audit(host=...)` now audits the
  requested host.
- The Linux firewall check parsed `ufw status` with a substring match, so
  `Status: inactive` was reported as an active firewall.
- Config's default severity ("medium") overrode every check's declared
  default; `disk_encryption` is reported as critical and `firewall` as
  high again unless a policy explicitly overrides them.
- The Windows firewall and BitLocker checks parse PowerShell stdout
  explicitly; an unelevated `Get-BitLockerVolume` query now produces a
  warning instead of a JSON parse error.
- Report files are written as UTF-8, fixing a `UnicodeEncodeError` with
  `--output` on Windows.
- `requirements.txt` declared six packages the code never imports
  (paramiko, click, rich, jinja2, requests, python-dotenv); it now lists
  only PyYAML, matching `pyproject.toml`.

### Added

- `--quiet` / `-q` flag (documented since 1.0.0 but never implemented):
  prints only failed/errored checks plus a one-line summary.
- Test coverage for the check plugins, the auditor orchestration, the
  CLI, and quiet reporting (70+ tests, previously 21 covering only
  config and results).

### Changed

- CI now gates honestly: `ruff check` without `--exit-zero`, `pytest`
  without `|| true`, `black --check`, package installed with
  `pip install -e .[dev]`, matrix on Linux and Windows; Python 3.9
  dropped from the matrix (pyproject has always required >=3.10).
- Codebase reformatted with black (was compressed one-statement-per-line
  style).
- README rewritten so every claim is verifiable: sample outputs are
  captured from a real Windows 11 audit run, PyPI install instructions
  replaced with a GitHub install, decorative badge and filler removed.

## [1.0.0] - 2026-02-19

### Added

- Initial release: policy-as-YAML infrastructure auditing for macOS,
  Linux, and Windows with 7 built-in checks (firewall, disk encryption,
  SSH hardening, open ports, services, security updates, stealth mode),
  local and SSH executors, and terminal/JSON/Markdown reporters.
