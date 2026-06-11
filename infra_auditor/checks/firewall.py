"""Firewall status check."""

from .base import BaseCheck, CheckRegistry
from ..results import Severity


@CheckRegistry.register("firewall")
class FirewallCheck(BaseCheck):
    name = "Firewall Status"
    description = "Verify that the system firewall is enabled and active"
    supported_os = ["macos", "linux", "windows"]
    default_severity = Severity.HIGH

    def run(self):
        if not self.is_supported():
            return self.skip(f"Check not supported on {self.os_type}")
        if self.os_type == "macos":
            return self._check_macos()
        elif self.os_type == "linux":
            return self._check_linux()
        elif self.os_type == "windows":
            return self._check_windows()
        return self.skip(f"Unknown OS: {self.os_type}")

    def _check_macos(self):
        result = self.executor.run(
            "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
        )
        if not result.success:
            return self.error(f"Failed to check firewall: {result.stderr}")
        if "enabled" in result.output.lower():
            return self.passed(
                "macOS Application Firewall is enabled",
                details={"output": result.output.strip()},
            )
        return self.failed(
            "macOS Application Firewall is disabled",
            remediation="Enable via: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
        )

    def _check_linux(self):
        result = self.executor.run("ufw status 2>/dev/null")
        if result.success and "status:" in result.output.lower():
            # "inactive" contains "active", so match the full status value
            if "status: active" in result.output.lower():
                return self.passed(
                    "UFW firewall is active", details={"firewall": "ufw"}
                )
            return self.failed(
                "UFW firewall is inactive", remediation="Enable via: sudo ufw enable"
            )
        result = self.executor.run("systemctl is-active firewalld 2>/dev/null")
        if result.success and result.output.strip().lower() == "active":
            return self.passed("firewalld is active", details={"firewall": "firewalld"})
        return self.failed(
            "No active firewall detected", remediation="Enable ufw or firewalld"
        )

    def _check_windows(self):
        result = self.executor.run(
            'powershell -Command "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"'
        )
        if not result.success or not result.stdout.strip():
            return self.error(f"Failed to check Windows Firewall: {result.stderr}")
        try:
            import json

            profiles = json.loads(result.stdout)
            if not isinstance(profiles, list):
                profiles = [profiles]
            disabled = [p["Name"] for p in profiles if not p["Enabled"]]
            if not disabled:
                return self.passed("Windows Firewall is enabled on all profiles")
            return self.failed(f"Windows Firewall disabled on: {', '.join(disabled)}")
        except Exception as e:
            return self.error(f"Failed to parse firewall status: {e}")
