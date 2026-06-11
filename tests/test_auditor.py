"""Tests for the Auditor orchestrator."""

from unittest.mock import patch

from infra_auditor.auditor import Auditor
from infra_auditor.config import Config, TargetConfig
from infra_auditor.executor import CommandResult


class FakeExecutor:
    """Executor stand-in that records commands and returns empty results."""

    def __init__(self, os_type="linux"):
        self.os_type = os_type
        self.commands = []
        self.closed = False

    def run(self, command, timeout=30):
        self.commands.append(command)
        return CommandResult(stdout="", stderr="", returncode=1)

    def detect_os(self):
        return self.os_type

    def close(self):
        self.closed = True


class TestAuditTargetResolution:
    """Regression tests for target resolution in Auditor.audit()."""

    def test_explicit_target_wins_when_config_has_no_targets(self):
        """An explicitly passed target must be audited even if config.targets
        is empty.

        Regression test: an operator-precedence bug used to resolve the
        target expression as `(target or targets[0]) if config.targets
        else TargetConfig("localhost")`, silently auditing localhost
        instead of the requested host.
        """
        fake = FakeExecutor()
        with patch("infra_auditor.auditor.create_executor", return_value=fake) as ce:
            result = Auditor(Config()).audit(TargetConfig(host="remote-box"))
        ce.assert_called_once_with(
            host="remote-box",
            port=22,
            username=None,
            key_file=None,
            insecure_host_key=False,
        )
        assert result.target == "remote-box"

    def test_explicit_target_wins_over_config_targets(self):
        fake = FakeExecutor()
        config = Config(targets=[TargetConfig(host="from-config")])
        with patch("infra_auditor.auditor.create_executor", return_value=fake):
            result = Auditor(config).audit(TargetConfig(host="explicit-host"))
        assert result.target == "explicit-host"

    def test_defaults_to_first_config_target(self):
        fake = FakeExecutor()
        config = Config(
            targets=[TargetConfig(host="first"), TargetConfig(host="second")]
        )
        with patch("infra_auditor.auditor.create_executor", return_value=fake):
            result = Auditor(config).audit()
        assert result.target == "first"

    def test_defaults_to_localhost_when_nothing_configured(self):
        fake = FakeExecutor()
        with patch("infra_auditor.auditor.create_executor", return_value=fake):
            result = Auditor(Config()).audit()
        assert result.target == "localhost"

    def test_quick_audit_uses_requested_host(self):
        """Auditor.quick_audit(host=...) must audit that host, not localhost."""
        fake = FakeExecutor()
        with patch("infra_auditor.auditor.create_executor", return_value=fake):
            result = Auditor.quick_audit(host="remote-box")
        assert result.target == "remote-box"

    def test_executor_closed_after_audit(self):
        fake = FakeExecutor()
        with patch("infra_auditor.auditor.create_executor", return_value=fake):
            Auditor(Config()).audit()
        assert fake.closed

    def test_check_default_severities_survive_default_config(self):
        """Without explicit overrides, each check keeps its own severity
        (firewall=high, disk_encryption=critical), instead of being
        flattened to medium by the config default."""
        from infra_auditor.results import Severity

        fake = FakeExecutor()
        with patch("infra_auditor.auditor.create_executor", return_value=fake):
            result = Auditor(Config()).audit()
        by_id = {c.check_id: c for c in result.checks}
        assert by_id["firewall"].severity == Severity.HIGH
        assert by_id["disk_encryption"].severity == Severity.CRITICAL

    def test_configured_severity_overrides_check_default(self):
        from infra_auditor.results import Severity

        fake = FakeExecutor()
        config = Config.from_dict({"checks": {"firewall": {"severity": "low"}}})
        config.targets = []
        with patch("infra_auditor.auditor.create_executor", return_value=fake):
            result = Auditor(config).audit()
        by_id = {c.check_id: c for c in result.checks}
        assert by_id["firewall"].severity == Severity.LOW
