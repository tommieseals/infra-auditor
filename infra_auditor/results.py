"""Audit result data structures."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List
from datetime import datetime, timezone


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other):
        order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        return order.index(self) < order.index(other)


class Status(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
    ERROR = "error"


@dataclass
class CheckResult:
    check_id: str
    name: str
    status: Status
    message: str
    severity: Severity = Severity.MEDIUM
    details: Optional[dict] = None
    remediation: Optional[str] = None

    @property
    def passed(self) -> bool:
        return self.status == Status.PASS

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "name": self.name,
            "status": self.status.value,
            "severity": self.severity.value,
            "message": self.message,
            "details": self.details,
            "remediation": self.remediation,
        }


@dataclass
class AuditResult:
    target: str
    os_type: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    checks: List[CheckResult] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == Status.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == Status.FAIL)

    @property
    def warnings(self) -> int:
        return sum(1 for c in self.checks if c.status == Status.WARN)

    @property
    def skipped(self) -> int:
        return sum(1 for c in self.checks if c.status == Status.SKIP)

    @property
    def errors(self) -> int:
        return sum(1 for c in self.checks if c.status == Status.ERROR)

    @property
    def total(self) -> int:
        return len(self.checks)

    @property
    def compliance_score(self) -> float:
        if self.total == 0:
            return 100.0
        applicable = self.total - self.skipped
        if applicable == 0:
            return 100.0
        return round((self.passed / applicable) * 100, 1)

    @property
    def exit_code(self) -> int:
        if self.errors > 0:
            return 2
        if self.failed > 0:
            return 1
        return 0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "os_type": self.os_type,
            "timestamp": self.timestamp.isoformat(),
            "summary": {
                "total": self.total,
                "passed": self.passed,
                "failed": self.failed,
                "warnings": self.warnings,
                "skipped": self.skipped,
                "errors": self.errors,
                "compliance_score": self.compliance_score,
            },
            "checks": [c.to_dict() for c in self.checks],
            "metadata": self.metadata,
        }
