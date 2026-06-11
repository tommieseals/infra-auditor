"""Stealth mode check (macOS specific)."""

from .base import BaseCheck, CheckRegistry
from ..results import Severity


@CheckRegistry.register("stealth_mode")
class StealthModeCheck(BaseCheck):
    name = "Stealth Mode"
    description = (
        "Verify stealth mode is enabled to ignore unsolicited network requests"
    )
    supported_os = ["macos"]
    default_severity = Severity.MEDIUM

    def run(self):
        if not self.is_supported():
            return self.skip("Stealth mode is a macOS-specific feature")
        result = self.executor.run(
            "/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode"
        )
        if not result.success:
            return self.error(f"Failed to check stealth mode: {result.stderr}")
        if "enabled" in result.output.lower():
            return self.passed("Stealth mode is enabled")
        return self.failed(
            "Stealth mode is disabled",
            remediation="Enable via: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
        )
