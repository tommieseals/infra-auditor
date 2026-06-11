"""Disk encryption check."""

from .base import BaseCheck, CheckRegistry
from ..results import Severity


@CheckRegistry.register("disk_encryption")
class DiskEncryptionCheck(BaseCheck):
    name = "Disk Encryption"
    description = "Verify that disk/volume encryption is enabled"
    supported_os = ["macos", "linux", "windows"]
    default_severity = Severity.CRITICAL

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
        result = self.executor.run("fdesetup status")
        if not result.success:
            return self.error(f"Failed to check FileVault: {result.stderr}")
        if "filevault is on" in result.output.lower():
            return self.passed("FileVault disk encryption is enabled")
        return self.failed(
            "FileVault disk encryption is disabled",
            remediation="Enable via: System Preferences > Security & Privacy > FileVault",
        )

    def _check_linux(self):
        result = self.executor.run("dmsetup ls --target crypt 2>/dev/null")
        if (
            result.success
            and result.output.strip()
            and "No devices" not in result.output
        ):
            return self.passed("Disk encryption (LUKS) is configured")
        return self.warn(
            "Could not determine encryption status - manual verification recommended"
        )

    def _check_windows(self):
        result = self.executor.run(
            'powershell -Command "Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus | ConvertTo-Json"'
        )
        if not result.success:
            return self.warn("Could not check BitLocker")
        # Get-BitLockerVolume exits 0 even when it fails (e.g. without an
        # elevated session it writes Access Denied to stderr) -- parse
        # stdout only and treat an empty response as "could not determine".
        if not result.stdout.strip():
            return self.warn(
                "Could not determine BitLocker status (Get-BitLockerVolume requires an elevated session)"
            )
        try:
            import json

            volumes = json.loads(result.stdout)
            if not isinstance(volumes, list):
                volumes = [volumes]
            unprotected = [
                v.get("MountPoint") for v in volumes if v.get("ProtectionStatus") != 1
            ]
            if unprotected:
                return self.failed(
                    f"BitLocker not enabled on: {', '.join(unprotected)}"
                )
            return self.passed("BitLocker enabled on all volumes")
        except Exception as e:
            return self.error(f"Failed to parse BitLocker status: {e}")
