"""Base class for compliance checks."""

from abc import ABC, abstractmethod
from typing import Optional, Type, Dict, List
from ..results import CheckResult, Status, Severity
from ..executor import Executor


class CheckRegistry:
    _checks: Dict[str, Type["BaseCheck"]] = {}

    @classmethod
    def register(cls, check_id: str):
        def decorator(check_class: Type["BaseCheck"]):
            cls._checks[check_id] = check_class
            check_class.check_id = check_id
            return check_class

        return decorator

    @classmethod
    def get(cls, check_id: str) -> Optional[Type["BaseCheck"]]:
        return cls._checks.get(check_id)

    @classmethod
    def all(cls) -> Dict[str, Type["BaseCheck"]]:
        return cls._checks.copy()

    @classmethod
    def list_checks(cls) -> List[str]:
        return list(cls._checks.keys())


class BaseCheck(ABC):
    check_id: str = "base"
    name: str = "Base Check"
    description: str = "Base check class"
    supported_os: List[str] = ["macos", "linux", "windows"]
    default_severity: Severity = Severity.MEDIUM

    def __init__(self, executor: Executor, os_type: str, params: dict = None):
        self.executor, self.os_type, self.params = executor, os_type, params or {}

    @abstractmethod
    def run(self) -> CheckResult:
        pass

    def is_supported(self) -> bool:
        return self.os_type in self.supported_os

    def skip(self, reason: str) -> CheckResult:
        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.SKIP,
            severity=self.default_severity,
            message=reason,
        )

    def passed(self, message: str, details: dict = None) -> CheckResult:
        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.PASS,
            severity=self.default_severity,
            message=message,
            details=details,
        )

    def failed(
        self,
        message: str,
        remediation: str = None,
        details: dict = None,
        severity: Severity = None,
    ) -> CheckResult:
        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.FAIL,
            severity=severity or self.default_severity,
            message=message,
            remediation=remediation,
            details=details,
        )

    def warn(self, message: str, details: dict = None) -> CheckResult:
        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.WARN,
            severity=self.default_severity,
            message=message,
            details=details,
        )

    def error(self, message: str, details: dict = None) -> CheckResult:
        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=Status.ERROR,
            severity=self.default_severity,
            message=message,
            details=details,
        )
