"""Tests for configuration parsing."""

from infra_auditor.config import Config, TargetConfig, CheckConfig


class TestConfig:
    """Test configuration loading and parsing."""

    def test_default_config(self):
        """Test default configuration values."""
        config = Config()
        assert len(config.targets) == 0
        assert len(config.checks) == 0

    def test_from_dict_minimal(self):
        """Test loading minimal config from dict."""
        data = {}
        config = Config.from_dict(data)

        # Should default to localhost
        assert len(config.targets) == 1
        assert config.targets[0].host == "localhost"

    def test_from_dict_with_targets(self):
        """Test loading config with targets."""
        data = {
            "targets": [
                {"host": "server1.example.com", "username": "admin"},
                {"host": "server2.example.com", "port": 2222},
            ]
        }
        config = Config.from_dict(data)

        assert len(config.targets) == 2
        assert config.targets[0].host == "server1.example.com"
        assert config.targets[0].username == "admin"
        assert config.targets[1].port == 2222

    def test_from_dict_with_checks(self):
        """Test loading config with check settings."""
        data = {
            "checks": {
                "firewall": {"enabled": True, "severity": "critical"},
                "ssh_hardening": False,
            }
        }
        config = Config.from_dict(data)

        assert config.is_check_enabled("firewall")
        assert not config.is_check_enabled("ssh_hardening")
        assert config.get_check_severity("firewall") == "critical"

    def test_is_check_enabled_default(self):
        """Test that unconfigured checks are enabled by default."""
        config = Config()
        assert config.is_check_enabled("unconfigured_check")

    def test_severity_not_overridden_by_default(self):
        """Unconfigured checks must not get a severity override, so each
        check's own default (e.g. disk_encryption=critical) survives."""
        config = Config()
        assert config.get_check_severity("disk_encryption") is None

        # Enabling a check without specifying severity is not an override
        config = Config.from_dict({"checks": {"disk_encryption": {"enabled": True}}})
        assert config.get_check_severity("disk_encryption") is None

    def test_string_targets(self):
        """Test that string targets are accepted."""
        data = {"targets": ["host1.example.com", "host2.example.com"]}
        config = Config.from_dict(data)

        assert len(config.targets) == 2
        assert config.targets[0].host == "host1.example.com"


class TestTargetConfig:
    """Test target configuration."""

    def test_defaults(self):
        """Test default target values."""
        target = TargetConfig(host="example.com")

        assert target.port == 22
        assert target.username is None
        assert target.key_file is None
        assert target.os_type is None


class TestCheckConfig:
    """Test check configuration."""

    def test_defaults(self):
        """Test default check config values."""
        check = CheckConfig()

        assert check.enabled
        assert check.severity is None  # no override; check default applies
        assert check.params == {}
