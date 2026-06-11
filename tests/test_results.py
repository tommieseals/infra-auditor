"""Tests for audit result structures."""

from datetime import datetime
from infra_auditor.results import AuditResult, CheckResult, Status, Severity


class TestCheckResult:
    """Test individual check results."""

    def test_passed_property(self):
        """Test passed property."""
        result = CheckResult(
            check_id="test",
            name="Test Check",
            status=Status.PASS,
            message="All good",
        )
        assert result.passed

        result.status = Status.FAIL
        assert not result.passed

    def test_to_dict(self):
        """Test serialization to dict."""
        result = CheckResult(
            check_id="firewall",
            name="Firewall Check",
            status=Status.PASS,
            message="Firewall is enabled",
            severity=Severity.HIGH,
            details={"output": "enabled"},
        )

        d = result.to_dict()
        assert d["check_id"] == "firewall"
        assert d["status"] == "pass"
        assert d["severity"] == "high"


class TestAuditResult:
    """Test complete audit results."""

    def test_summary_counts(self):
        """Test summary count properties."""
        result = AuditResult(target="localhost", os_type="macos")
        result.checks = [
            CheckResult("c1", "Check 1", Status.PASS, "OK"),
            CheckResult("c2", "Check 2", Status.PASS, "OK"),
            CheckResult("c3", "Check 3", Status.FAIL, "Failed"),
            CheckResult("c4", "Check 4", Status.WARN, "Warning"),
            CheckResult("c5", "Check 5", Status.SKIP, "Skipped"),
        ]

        assert result.passed == 2
        assert result.failed == 1
        assert result.warnings == 1
        assert result.skipped == 1
        assert result.total == 5

    def test_compliance_score(self):
        """Test compliance score calculation."""
        result = AuditResult(target="localhost", os_type="linux")
        result.checks = [
            CheckResult("c1", "Check 1", Status.PASS, "OK"),
            CheckResult("c2", "Check 2", Status.PASS, "OK"),
            CheckResult("c3", "Check 3", Status.PASS, "OK"),
            CheckResult("c4", "Check 4", Status.FAIL, "Failed"),
        ]

        # 3 passed out of 4 = 75%
        assert result.compliance_score == 75.0

    def test_compliance_score_excludes_skipped(self):
        """Test that skipped checks don't affect compliance score."""
        result = AuditResult(target="localhost", os_type="linux")
        result.checks = [
            CheckResult("c1", "Check 1", Status.PASS, "OK"),
            CheckResult("c2", "Check 2", Status.PASS, "OK"),
            CheckResult("c3", "Check 3", Status.SKIP, "Skipped"),
        ]

        # 2 passed out of 2 applicable = 100%
        assert result.compliance_score == 100.0

    def test_exit_code_success(self):
        """Test exit code for all passing checks."""
        result = AuditResult(target="localhost", os_type="macos")
        result.checks = [
            CheckResult("c1", "Check 1", Status.PASS, "OK"),
            CheckResult("c2", "Check 2", Status.PASS, "OK"),
        ]

        assert result.exit_code == 0

    def test_exit_code_failure(self):
        """Test exit code when checks fail."""
        result = AuditResult(target="localhost", os_type="macos")
        result.checks = [
            CheckResult("c1", "Check 1", Status.PASS, "OK"),
            CheckResult("c2", "Check 2", Status.FAIL, "Failed"),
        ]

        assert result.exit_code == 1

    def test_exit_code_error(self):
        """Test exit code for errors."""
        result = AuditResult(target="localhost", os_type="macos")
        result.checks = [
            CheckResult("c1", "Check 1", Status.PASS, "OK"),
            CheckResult("c2", "Check 2", Status.ERROR, "Error"),
        ]

        assert result.exit_code == 2

    def test_to_dict(self):
        """Test serialization to dict."""
        result = AuditResult(
            target="example.com",
            os_type="linux",
            timestamp=datetime(2025, 1, 15, 12, 0, 0),
        )
        result.checks = [
            CheckResult("firewall", "Firewall", Status.PASS, "Enabled"),
        ]

        d = result.to_dict()
        assert d["target"] == "example.com"
        assert d["os_type"] == "linux"
        assert d["summary"]["total"] == 1
        assert len(d["checks"]) == 1
