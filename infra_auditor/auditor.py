"""Main auditor class that orchestrates compliance checks."""

from datetime import datetime, timezone
from typing import List
from .config import Config, TargetConfig
from .executor import create_executor
from .results import AuditResult, Severity
from .checks.base import CheckRegistry

# Importing the checks package registers all built-in checks.
from . import checks  # noqa: F401


class Auditor:
    def __init__(self, config: Config = None):
        self.config = config or Config()

    def audit(self, target: TargetConfig = None) -> AuditResult:
        if target is None:
            target = (
                self.config.targets[0]
                if self.config.targets
                else TargetConfig(host="localhost")
            )
        executor = create_executor(
            host=target.host,
            port=target.port,
            username=target.username,
            key_file=target.key_file,
            insecure_host_key=target.insecure_host_key,
        )
        try:
            os_type = target.os_type or executor.detect_os()
            result = AuditResult(
                target=target.host,
                os_type=os_type,
                timestamp=datetime.now(timezone.utc),
                metadata={"port": target.port, "username": target.username},
            )
            for check_id, check_class in CheckRegistry.all().items():
                if not self.config.is_check_enabled(check_id):
                    continue
                severity_str = self.config.get_check_severity(check_id)
                params = self.config.get_check_params(check_id)
                check = check_class(executor, os_type, params)
                if severity_str:
                    try:
                        check.default_severity = Severity(severity_str)
                    except ValueError:
                        pass
                check_result = check.run()
                result.checks.append(check_result)
            return result
        finally:
            executor.close()

    def audit_all(self) -> List[AuditResult]:
        return [self.audit(target) for target in self.config.targets]

    @classmethod
    def from_yaml(cls, config_path: str) -> "Auditor":
        return cls(Config.from_yaml(config_path))

    @classmethod
    def quick_audit(cls, host: str = "localhost", **kwargs) -> AuditResult:
        target = TargetConfig(host=host, **kwargs)
        return cls().audit(target)
