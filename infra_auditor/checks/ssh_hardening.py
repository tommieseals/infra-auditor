"""SSH configuration hardening check."""

from typing import Optional
from .base import BaseCheck, CheckRegistry
from ..results import Severity


@CheckRegistry.register("ssh_hardening")
class SSHHardeningCheck(BaseCheck):
    name = "SSH Hardening"
    description = "Verify SSH server configuration follows security best practices"
    supported_os = ["macos", "linux"]
    default_severity = Severity.HIGH
    SECURE_SETTINGS = {
        "PermitRootLogin": ("no", "prohibit-password"),
        "PasswordAuthentication": ("no",),
        "PubkeyAuthentication": ("yes",),
        "PermitEmptyPasswords": ("no",),
    }

    def run(self):
        if not self.is_supported():
            return self.skip(f"Check not supported on {self.os_type}")
        result = self.executor.run("cat /etc/ssh/sshd_config 2>/dev/null")
        if not result.success:
            return self.skip("SSH server not configured or not accessible")
        config_content = result.output
        issues = []
        for setting, secure_values in self.SECURE_SETTINGS.items():
            current_value = self._get_setting(config_content, setting)
            if current_value and current_value.lower() not in [
                v.lower() for v in secure_values
            ]:
                issues.append(
                    {
                        "setting": setting,
                        "current": current_value,
                        "recommended": secure_values[0],
                    }
                )
        if issues:
            return self.failed(
                f"SSH configuration has {len(issues)} security issue(s)",
                remediation="; ".join(
                    [f"Set {i['setting']} {i['recommended']}" for i in issues]
                ),
                details={"issues": issues},
            )
        return self.passed("SSH configuration follows security best practices")

    def _get_setting(self, config: str, setting: str) -> Optional[str]:
        for line in config.split("\n"):
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].lower() == setting.lower():
                return parts[1]
        return None
