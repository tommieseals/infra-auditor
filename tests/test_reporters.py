"""Tests for report output, including quiet mode and encoding fallback."""

import io
import sys

from infra_auditor.reporters import MarkdownReporter, TerminalReporter
from infra_auditor.results import AuditResult, CheckResult, Severity, Status


def make_result():
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
        CheckResult("stealth_mode", "Stealth Mode", Status.SKIP, "macOS only"),
        CheckResult(
            "security_updates", "Security Updates", Status.ERROR, "Lookup failed"
        ),
    ]
    return result


class TestTerminalReporter:
    def test_full_report_includes_all_checks(self):
        report = TerminalReporter(use_color=False).report(make_result())
        assert "Firewall Status" in report
        assert "Disk Encryption" in report
        assert "Stealth Mode" in report
        assert "Security Updates" in report
        assert "Infrastructure Audit Report" in report

    def test_quiet_report_only_shows_failures_and_errors(self):
        report = TerminalReporter(use_color=False, quiet=True).report(make_result())
        assert "Disk Encryption" in report
        assert "Security Updates" in report
        assert "Firewall Status" not in report
        assert "Stealth Mode" not in report

    def test_quiet_report_includes_remediation(self):
        report = TerminalReporter(use_color=False, quiet=True).report(make_result())
        assert "Enable BitLocker" in report

    def test_quiet_report_all_passing_is_one_summary_line(self):
        result = AuditResult(target="localhost", os_type="linux")
        result.checks = [
            CheckResult("firewall", "Firewall Status", Status.PASS, "OK"),
            CheckResult("open_ports", "Open Ports", Status.PASS, "OK"),
        ]
        report = TerminalReporter(use_color=False, quiet=True).report(result)
        assert report == "localhost: 2/2 checks passed (100.0%)"


class TestEncodingFallback:
    """Regression tests: rendering must survive an ASCII-only stdout codec.

    On Windows a piped or redirected stdout defaults to a legacy codec
    (e.g. cp1252) that cannot encode the unicode report glyphs; printing
    the report used to raise UnicodeEncodeError.
    """

    def _ascii_stdout(self, monkeypatch):
        stream = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
        monkeypatch.setattr(sys, "stdout", stream)
        return stream

    def test_terminal_report_encodes_under_ascii_codec(self, monkeypatch):
        self._ascii_stdout(monkeypatch)
        report = TerminalReporter(use_color=False).report(make_result())
        report.encode("ascii")  # must not raise
        assert "x Disk Encryption" in report
        assert "=" * 60 in report
        assert "-> Fix: Enable BitLocker" in report

    def test_quiet_terminal_report_encodes_under_ascii_codec(self, monkeypatch):
        self._ascii_stdout(monkeypatch)
        report = TerminalReporter(use_color=False, quiet=True).report(make_result())
        report.encode("ascii")  # must not raise

    def test_markdown_report_encodes_under_ascii_codec(self, monkeypatch):
        self._ascii_stdout(monkeypatch)
        report = MarkdownReporter().report(make_result())
        report.encode("ascii")  # must not raise
        assert "| FAIL | Disk Encryption |" in report

    def test_terminal_report_printable_under_ascii_stdout(self, monkeypatch):
        stream = self._ascii_stdout(monkeypatch)
        report = TerminalReporter(use_color=False).report(make_result())
        print(report, file=stream)  # must not raise
        stream.flush()

    def test_unicode_glyphs_kept_when_explicitly_requested(self, monkeypatch):
        self._ascii_stdout(monkeypatch)
        report = TerminalReporter(use_color=False, unicode_glyphs=True).report(
            make_result()
        )
        assert "✗ Disk Encryption" in report
        assert "═" * 60 in report

    def test_unicode_glyphs_used_when_stdout_is_utf8(self, monkeypatch):
        stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        monkeypatch.setattr(sys, "stdout", stream)
        report = TerminalReporter(use_color=False).report(make_result())
        assert "✗ Disk Encryption" in report
