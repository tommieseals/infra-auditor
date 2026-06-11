"""Tests for the command-line interface."""

import io
import sys
from unittest.mock import patch

import pytest

from infra_auditor import cli
from infra_auditor.results import AuditResult, CheckResult, Severity, Status


def fake_audit_result():
    result = AuditResult(target="localhost", os_type="windows")
    result.checks = [
        CheckResult("firewall", "Firewall Status", Status.PASS, "Firewall enabled"),
        CheckResult(
            "disk_encryption",
            "Disk Encryption",
            Status.FAIL,
            "BitLocker not enabled on: C:",
            severity=Severity.CRITICAL,
            remediation="Enable BitLocker",
        ),
    ]
    return result


def run_cli(argv, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["infra-auditor"] + argv)
    with patch("infra_auditor.auditor.Auditor.audit", return_value=fake_audit_result()):
        exit_code = cli.main()
    return exit_code, capsys.readouterr().out


class TestQuietFlag:
    def test_quiet_flag_is_accepted(self, monkeypatch, capsys):
        """Regression: --quiet used to be documented but not implemented,
        so the parser exited with status 2."""
        exit_code, _ = run_cli(["--quiet"], monkeypatch, capsys)
        assert exit_code == 1  # audit has one failing check, not a usage error

    def test_quiet_shows_only_failures(self, monkeypatch, capsys):
        _, out = run_cli(["--quiet", "--no-color"], monkeypatch, capsys)
        assert "Disk Encryption" in out
        assert "Firewall Status" not in out

    def test_short_q_flag(self, monkeypatch, capsys):
        _, out = run_cli(["-q", "--no-color"], monkeypatch, capsys)
        assert "Disk Encryption" in out
        assert "Firewall Status" not in out

    def test_default_output_shows_everything(self, monkeypatch, capsys):
        _, out = run_cli(["--no-color"], monkeypatch, capsys)
        assert "Disk Encryption" in out
        assert "Firewall Status" in out


class TestCliBasics:
    def test_exit_code_zero_when_all_pass(self, monkeypatch, capsys):
        result = AuditResult(target="localhost", os_type="windows")
        result.checks = [CheckResult("firewall", "Firewall", Status.PASS, "OK")]
        monkeypatch.setattr(sys, "argv", ["infra-auditor"])
        with patch("infra_auditor.auditor.Auditor.audit", return_value=result):
            assert cli.main() == 0

    def test_list_checks(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["infra-auditor", "--list-checks"])
        assert cli.main() == 0
        out = capsys.readouterr().out
        assert "firewall" in out
        assert "disk_encryption" in out

    def test_output_file(self, monkeypatch, capsys, tmp_path):
        out_file = tmp_path / "report.json"
        exit_code, out = run_cli(
            ["--format", "json", "--output", str(out_file)], monkeypatch, capsys
        )
        assert out_file.exists()
        assert '"target": "localhost"' in out_file.read_text()

    def test_unknown_flag_exits_2(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["infra-auditor", "--definitely-not-a-flag"])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 2


class _NoReconfigureStream:
    """Wraps a text stream but hides ``reconfigure``, mimicking replaced
    stdout objects that cannot switch encoding."""

    def __init__(self, stream):
        self._stream = stream

    def __getattr__(self, name):
        if name == "reconfigure":
            raise AttributeError(name)
        return getattr(self._stream, name)


class TestRedirectedStdoutEncoding:
    """Regression: ``infra-auditor | ...`` on Windows used to crash with
    UnicodeEncodeError because the piped stdout codec (cp1252) cannot
    encode the report glyphs (cli.py print(report))."""

    def _run_with_stdout(self, stdout, argv, monkeypatch):
        monkeypatch.setattr(sys, "stdout", stdout)
        monkeypatch.setattr(sys, "argv", ["infra-auditor"] + argv)
        with patch(
            "infra_auditor.auditor.Auditor.audit", return_value=fake_audit_result()
        ):
            return cli.main()

    def test_cli_reconfigures_redirected_stdout_to_utf8(self, monkeypatch):
        raw = io.BytesIO()
        stdout = io.TextIOWrapper(raw, encoding="cp1252")
        exit_code = self._run_with_stdout(stdout, ["--no-color"], monkeypatch)
        stdout.flush()
        assert exit_code == 1  # ran to completion, no UnicodeEncodeError
        assert "Disk Encryption" in raw.getvalue().decode("utf-8")

    def test_cli_falls_back_to_ascii_when_reconfigure_unavailable(self, monkeypatch):
        raw = io.BytesIO()
        stdout = _NoReconfigureStream(io.TextIOWrapper(raw, encoding="ascii"))
        exit_code = self._run_with_stdout(stdout, ["--no-color"], monkeypatch)
        stdout.flush()
        out = raw.getvalue().decode("ascii")  # must decode as pure ASCII
        assert exit_code == 1
        assert "x Disk Encryption" in out

    def test_cli_markdown_format_under_ascii_stdout(self, monkeypatch):
        raw = io.BytesIO()
        stdout = _NoReconfigureStream(io.TextIOWrapper(raw, encoding="ascii"))
        exit_code = self._run_with_stdout(stdout, ["--format", "markdown"], monkeypatch)
        stdout.flush()
        out = raw.getvalue().decode("ascii")
        assert exit_code == 1
        assert "Infrastructure Audit Report" in out
