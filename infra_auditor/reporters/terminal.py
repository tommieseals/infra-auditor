"""Terminal/console report output."""

import sys
from typing import Optional

from ..results import AuditResult, Status, Severity
from .encoding import stdout_can_encode


class TerminalReporter:
    COLORS = {
        "reset": "\033[0m",
        "bold": "\033[1m",
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "gray": "\033[90m",
    }
    STATUS_COLORS = {
        Status.PASS: "green",
        Status.FAIL: "red",
        Status.WARN: "yellow",
        Status.SKIP: "gray",
        Status.ERROR: "magenta",
    }
    STATUS_ICONS = {
        Status.PASS: "✓",
        Status.FAIL: "✗",
        Status.WARN: "⚠",
        Status.SKIP: "○",
        Status.ERROR: "⚡",
    }
    STATUS_ICONS_ASCII = {
        Status.PASS: "[OK]",
        Status.FAIL: "x",
        Status.WARN: "!",
        Status.SKIP: "o",
        Status.ERROR: "!!",
    }
    SEVERITY_COLORS = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "blue",
    }

    def __init__(
        self,
        use_color: bool = True,
        quiet: bool = False,
        unicode_glyphs: Optional[bool] = None,
    ):
        self.use_color = use_color and sys.stdout.isatty()
        self.quiet = quiet
        if unicode_glyphs is None:
            # Auto-detect: a redirected stream on Windows may use a legacy
            # codec (e.g. cp1252) that cannot encode the report glyphs.
            sample = "".join(self.STATUS_ICONS.values()) + "═─→"
            unicode_glyphs = stdout_can_encode(sample)
        self.status_icons = (
            self.STATUS_ICONS if unicode_glyphs else self.STATUS_ICONS_ASCII
        )
        self._heavy_rule = ("═" if unicode_glyphs else "=") * 60
        self._light_rule = ("─" if unicode_glyphs else "-") * 60
        self._fix_label = "→ Fix:" if unicode_glyphs else "-> Fix:"

    def _color(self, text: str, color: str) -> str:
        if not self.use_color:
            return text
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['reset']}"

    def report(self, result: AuditResult) -> str:
        if self.quiet:
            return self._report_quiet(result)
        lines = [
            "",
            self._color(self._heavy_rule, "cyan"),
            self._color("  Infrastructure Audit Report", "bold"),
            self._color(self._heavy_rule, "cyan"),
            "",
        ]
        lines.extend(
            [
                f"  Target:     {self._color(result.target, 'cyan')}",
                f"  OS:         {result.os_type}",
                f"  Timestamp:  {result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                "",
            ]
        )
        score = result.compliance_score
        score_color = "green" if score >= 80 else "yellow" if score >= 60 else "red"
        lines.extend(
            [
                self._color(self._light_rule, "gray"),
                f"  Compliance Score: {self._color(f'{score}%', score_color)}",
                f"  {self._color(str(result.passed), 'green')} passed  {self._color(str(result.failed), 'red')} failed  "
                f"{self._color(str(result.warnings), 'yellow')} warnings  {self._color(str(result.skipped), 'gray')} skipped",
                self._color(self._light_rule, "gray"),
                "",
                self._color("  CHECK RESULTS", "bold"),
                "",
            ]
        )
        sorted_checks = sorted(
            result.checks,
            key=lambda c: (
                c.status != Status.FAIL,
                c.status != Status.WARN,
                c.status != Status.PASS,
            ),
        )
        for check in sorted_checks:
            icon = self.status_icons.get(check.status, "?")
            color = self.STATUS_COLORS.get(check.status, "reset")
            sev_color = self.SEVERITY_COLORS.get(check.severity, "reset")
            lines.append(self._color(f"  {icon} {check.name}", color))
            lines.append(
                f"    {self._color(f'[{check.severity.value.upper()}]', sev_color)} {check.message}"
            )
            if check.status == Status.FAIL and check.remediation:
                lines.append(
                    f"    {self._color(self._fix_label, 'yellow')} {check.remediation}"
                )
            lines.append("")
        exit_msg = "PASSED" if result.exit_code == 0 else "FAILED"
        exit_color = "green" if result.exit_code == 0 else "red"
        lines.extend(
            [
                self._color(self._heavy_rule, "cyan"),
                f"  Exit Code: {result.exit_code} ({self._color(exit_msg, exit_color)})",
                self._color(self._heavy_rule, "cyan"),
                "",
            ]
        )
        return "\n".join(lines)

    def _report_quiet(self, result: AuditResult) -> str:
        """Compact report listing only failed and errored checks."""
        lines = []
        problems = [c for c in result.checks if c.status in (Status.FAIL, Status.ERROR)]
        for check in problems:
            icon = self.status_icons.get(check.status, "?")
            color = self.STATUS_COLORS.get(check.status, "reset")
            sev_color = self.SEVERITY_COLORS.get(check.severity, "reset")
            lines.append(self._color(f"{icon} {check.name}", color))
            lines.append(
                f"  {self._color(f'[{check.severity.value.upper()}]', sev_color)} {check.message}"
            )
            if check.status == Status.FAIL and check.remediation:
                lines.append(
                    f"  {self._color(self._fix_label, 'yellow')} {check.remediation}"
                )
        summary = (
            f"{result.target}: {result.passed}/{result.total - result.skipped} "
            f"checks passed ({result.compliance_score}%)"
        )
        summary_color = "green" if result.exit_code == 0 else "red"
        if lines:
            lines.append("")
        lines.append(self._color(summary, summary_color))
        return "\n".join(lines)

    def print(self, result: AuditResult):
        print(self.report(result))
