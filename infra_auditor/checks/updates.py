"""Security updates check."""

from .base import BaseCheck, CheckRegistry
from ..results import Severity


@CheckRegistry.register("security_updates")
class SecurityUpdatesCheck(BaseCheck):
    name = "Security Updates"
    description = "Check for pending security updates"
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
        result = self.executor.run("softwareupdate -l 2>&1")
        if "no new software available" in result.output.lower():
            return self.passed("System is up to date")
        updates = [
            line.strip()
            for line in result.output.split("\n")
            if line.strip().startswith("*") or "security" in line.lower()
        ]
        if updates:
            return self.failed(
                f"Updates available: {len(updates)} pending",
                remediation="Run: sudo softwareupdate -ia",
                details={"updates": updates},
            )
        return self.passed("No critical updates pending")

    def _check_linux(self):
        result = self.executor.run(
            "apt list --upgradable 2>/dev/null | grep -i security | wc -l"
        )
        if result.success:
            try:
                count = int(result.output.strip())
                if count > 0:
                    return self.failed(
                        f"{count} security updates available",
                        remediation="Run: sudo apt update && sudo apt upgrade",
                    )
                return self.passed("No security updates pending (apt)")
            except ValueError:
                pass
        return self.skip("Could not determine update status")

    def _check_windows(self):
        result = self.executor.run(
            "powershell -Command \"(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0').Updates.Count\""
        )
        if not result.success:
            return self.warn("Could not check Windows Update status")
        try:
            count = int(result.output.strip())
            if count > 0:
                return self.failed(
                    f"{count} Windows updates available",
                    remediation="Open Settings > Update & Security",
                )
            return self.passed("Windows is up to date")
        except ValueError:
            return self.warn("Could not parse Windows Update status")
