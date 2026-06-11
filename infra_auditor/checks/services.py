"""Services check."""

from .base import BaseCheck, CheckRegistry
from ..results import Severity


@CheckRegistry.register("services")
class ServicesCheck(BaseCheck):
    name = "Services"
    description = (
        "Verify required services are running and unwanted services are stopped"
    )
    supported_os = ["macos", "linux", "windows"]
    default_severity = Severity.MEDIUM

    def run(self):
        if not self.is_supported():
            return self.skip(f"Check not supported on {self.os_type}")
        required = self.params.get("required", [])
        forbidden = self.params.get("forbidden", [])
        if not required and not forbidden:
            return self.skip("No services configured to check")
        issues = []
        details = {"required": {}, "forbidden": {}}
        for service in required:
            if self.os_type == "macos":
                result = self.executor.run(f"launchctl list | grep -i '{service}'")
            elif self.os_type == "linux":
                result = self.executor.run(f"systemctl is-active {service} 2>/dev/null")
            else:
                result = self.executor.run(
                    f"powershell -Command \"(Get-Service -Name '{service}' -ErrorAction SilentlyContinue).Status\""
                )
            running = (
                result.success
                and result.output.strip()
                and (
                    "active" in result.output.lower()
                    or "running" in result.output.lower()
                    or service in result.output.lower()
                )
            )
            details["required"][service] = "running" if running else "not running"
            if not running:
                issues.append(f"Required service not running: {service}")
        for service in forbidden:
            if self.os_type == "macos":
                result = self.executor.run(f"launchctl list | grep -i '{service}'")
            elif self.os_type == "linux":
                result = self.executor.run(f"systemctl is-active {service} 2>/dev/null")
            else:
                result = self.executor.run(
                    f"powershell -Command \"(Get-Service -Name '{service}' -ErrorAction SilentlyContinue).Status\""
                )
            running = (
                result.success
                and result.output.strip()
                and (
                    "active" in result.output.lower()
                    or "running" in result.output.lower()
                    or service in result.output.lower()
                )
            )
            details["forbidden"][service] = "running" if running else "not running"
            if running:
                issues.append(f"Forbidden service is running: {service}")
        if issues:
            return self.failed(
                f"Service policy violations: {len(issues)}", details=details
            )
        return self.passed("All service requirements met", details=details)
