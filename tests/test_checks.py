"""Tests for the check plugins, with subprocess/PowerShell calls mocked out."""

import json

from infra_auditor.checks.base import CheckRegistry
from infra_auditor.checks.encryption import DiskEncryptionCheck
from infra_auditor.checks.firewall import FirewallCheck
from infra_auditor.checks.ports import OpenPortsCheck
from infra_auditor.checks.ssh_hardening import SSHHardeningCheck
from infra_auditor.checks.stealth import StealthModeCheck
from infra_auditor.checks.updates import SecurityUpdatesCheck
from infra_auditor.executor import CommandResult, Executor
from infra_auditor.results import Status


class ScriptedExecutor(Executor):
    """Executor that returns canned results instead of shelling out.

    Responses are (command_substring, CommandResult) pairs; the first
    substring found in the issued command wins.
    """

    def __init__(self, responses=None, os_type="linux"):
        self.responses = responses or []
        self.os_type = os_type
        self.commands = []

    def run(self, command, timeout=30):
        self.commands.append(command)
        for substring, result in self.responses:
            if substring in command:
                return result
        return CommandResult(stdout="", stderr="no script for command", returncode=1)

    def detect_os(self):
        return self.os_type


def ok(stdout):
    return CommandResult(stdout=stdout, stderr="", returncode=0)


def fail(stderr="boom"):
    return CommandResult(stdout="", stderr=stderr, returncode=1)


class TestCheckRegistry:
    def test_registry_has_exactly_seven_checks(self):
        assert len(CheckRegistry.all()) == 7

    def test_registered_check_ids(self):
        assert sorted(CheckRegistry.list_checks()) == [
            "disk_encryption",
            "firewall",
            "open_ports",
            "security_updates",
            "services",
            "ssh_hardening",
            "stealth_mode",
        ]


class TestFirewallCheck:
    def test_windows_all_profiles_enabled(self):
        profiles = [
            {"Name": "Domain", "Enabled": True},
            {"Name": "Private", "Enabled": True},
            {"Name": "Public", "Enabled": True},
        ]
        executor = ScriptedExecutor(
            [("Get-NetFirewallProfile", ok(json.dumps(profiles)))], os_type="windows"
        )
        result = FirewallCheck(executor, "windows").run()
        assert result.status == Status.PASS

    def test_windows_profile_disabled(self):
        profiles = [
            {"Name": "Domain", "Enabled": True},
            {"Name": "Public", "Enabled": False},
        ]
        executor = ScriptedExecutor(
            [("Get-NetFirewallProfile", ok(json.dumps(profiles)))], os_type="windows"
        )
        result = FirewallCheck(executor, "windows").run()
        assert result.status == Status.FAIL
        assert "Public" in result.message

    def test_windows_command_failure_is_error(self):
        executor = ScriptedExecutor(
            [("Get-NetFirewallProfile", fail("access denied"))], os_type="windows"
        )
        result = FirewallCheck(executor, "windows").run()
        assert result.status == Status.ERROR

    def test_macos_enabled(self):
        executor = ScriptedExecutor(
            [("socketfilterfw", ok("Firewall is enabled. (State = 1)"))],
            os_type="macos",
        )
        result = FirewallCheck(executor, "macos").run()
        assert result.status == Status.PASS

    def test_linux_ufw_active(self):
        executor = ScriptedExecutor([("ufw status", ok("Status: active"))])
        result = FirewallCheck(executor, "linux").run()
        assert result.status == Status.PASS

    def test_linux_ufw_inactive(self):
        executor = ScriptedExecutor([("ufw status", ok("Status: inactive"))])
        result = FirewallCheck(executor, "linux").run()
        assert result.status == Status.FAIL

    def test_linux_falls_back_to_firewalld(self):
        executor = ScriptedExecutor(
            [("ufw status", fail()), ("firewalld", ok("active"))]
        )
        result = FirewallCheck(executor, "linux").run()
        assert result.status == Status.PASS
        assert result.details == {"firewall": "firewalld"}

    def test_unsupported_os_is_skipped(self):
        result = FirewallCheck(ScriptedExecutor(), "freebsd").run()
        assert result.status == Status.SKIP


class TestDiskEncryptionCheck:
    def test_windows_bitlocker_all_protected(self):
        volumes = [{"MountPoint": "C:", "ProtectionStatus": 1}]
        executor = ScriptedExecutor(
            [("Get-BitLockerVolume", ok(json.dumps(volumes)))], os_type="windows"
        )
        result = DiskEncryptionCheck(executor, "windows").run()
        assert result.status == Status.PASS

    def test_windows_bitlocker_unprotected_volume(self):
        volumes = [
            {"MountPoint": "C:", "ProtectionStatus": 1},
            {"MountPoint": "D:", "ProtectionStatus": 0},
        ]
        executor = ScriptedExecutor(
            [("Get-BitLockerVolume", ok(json.dumps(volumes)))], os_type="windows"
        )
        result = DiskEncryptionCheck(executor, "windows").run()
        assert result.status == Status.FAIL
        assert "D:" in result.message

    def test_windows_bitlocker_single_volume_object(self):
        # ConvertTo-Json emits a bare object (not a list) for one volume
        volume = {"MountPoint": "C:", "ProtectionStatus": 1}
        executor = ScriptedExecutor(
            [("Get-BitLockerVolume", ok(json.dumps(volume)))], os_type="windows"
        )
        result = DiskEncryptionCheck(executor, "windows").run()
        assert result.status == Status.PASS

    def test_windows_bitlocker_query_failure_warns(self):
        # Get-BitLockerVolume needs admin rights; without them we warn
        executor = ScriptedExecutor(
            [("Get-BitLockerVolume", fail("requires elevation"))], os_type="windows"
        )
        result = DiskEncryptionCheck(executor, "windows").run()
        assert result.status == Status.WARN

    def test_windows_bitlocker_unelevated_session_warns(self):
        # Without elevation, powershell still exits 0 but stdout is empty
        # and Access Denied goes to stderr. This must warn, not error.
        unelevated = CommandResult(
            stdout="", stderr="Get-CimInstance : Access denied", returncode=0
        )
        executor = ScriptedExecutor(
            [("Get-BitLockerVolume", unelevated)], os_type="windows"
        )
        result = DiskEncryptionCheck(executor, "windows").run()
        assert result.status == Status.WARN
        assert "elevated" in result.message

    def test_macos_filevault_on(self):
        executor = ScriptedExecutor(
            [("fdesetup", ok("FileVault is On."))], os_type="macos"
        )
        result = DiskEncryptionCheck(executor, "macos").run()
        assert result.status == Status.PASS

    def test_macos_filevault_off(self):
        executor = ScriptedExecutor(
            [("fdesetup", ok("FileVault is Off."))], os_type="macos"
        )
        result = DiskEncryptionCheck(executor, "macos").run()
        assert result.status == Status.FAIL

    def test_linux_luks_configured(self):
        executor = ScriptedExecutor([("dmsetup", ok("sda3_crypt\t(254, 0)"))])
        result = DiskEncryptionCheck(executor, "linux").run()
        assert result.status == Status.PASS

    def test_linux_no_crypt_devices_warns(self):
        executor = ScriptedExecutor([("dmsetup", ok("No devices found"))])
        result = DiskEncryptionCheck(executor, "linux").run()
        assert result.status == Status.WARN


class TestOpenPortsCheck:
    LINUX_SS = "\n".join(
        [
            "State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port",
            "LISTEN  0       128     0.0.0.0:22          0.0.0.0:*",
            "LISTEN  0       128     0.0.0.0:23          0.0.0.0:*",
            "LISTEN  0       70      127.0.0.1:3306      0.0.0.0:*",
        ]
    )

    def test_dangerous_ports_flagged(self):
        executor = ScriptedExecutor([("ss -tlnp", ok(self.LINUX_SS))])
        result = OpenPortsCheck(executor, "linux").run()
        assert result.status == Status.FAIL
        flagged = {c["port"] for c in result.details["concerns"]}
        assert flagged == {23, 3306}  # Telnet and MySQL; 22 is not dangerous

    def test_allowed_ports_suppress_dangerous_defaults(self):
        executor = ScriptedExecutor([("ss -tlnp", ok(self.LINUX_SS))])
        check = OpenPortsCheck(executor, "linux", {"allowed_ports": [23, 3306]})
        result = check.run()
        assert result.status == Status.PASS

    def test_disallowed_ports_always_flagged(self):
        executor = ScriptedExecutor([("ss -tlnp", ok(self.LINUX_SS))])
        check = OpenPortsCheck(executor, "linux", {"disallowed_ports": [22]})
        result = check.run()
        assert result.status == Status.FAIL
        reasons = {c["port"]: c["reason"] for c in result.details["concerns"]}
        assert reasons[22] == "Explicitly disallowed"

    def test_windows_netstat_parsing(self):
        output = "\n".join(
            [
                "  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING",
                "  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING",
            ]
        )
        executor = ScriptedExecutor([("netstat", ok(output))], os_type="windows")
        result = OpenPortsCheck(executor, "windows").run()
        assert result.status == Status.FAIL
        flagged = {c["port"] for c in result.details["concerns"]}
        assert 3389 in flagged  # RDP

    def test_no_dangerous_ports_passes(self):
        output = "LISTEN  0  128  0.0.0.0:443  0.0.0.0:*"
        executor = ScriptedExecutor([("ss -tlnp", ok(output))])
        result = OpenPortsCheck(executor, "linux").run()
        assert result.status == Status.PASS


class TestSSHHardeningCheck:
    def test_hardened_config_passes(self):
        config = "\n".join(
            [
                "PermitRootLogin no",
                "PasswordAuthentication no",
                "PubkeyAuthentication yes",
                "PermitEmptyPasswords no",
            ]
        )
        executor = ScriptedExecutor([("sshd_config", ok(config))])
        result = SSHHardeningCheck(executor, "linux").run()
        assert result.status == Status.PASS

    def test_password_auth_enabled_fails(self):
        executor = ScriptedExecutor([("sshd_config", ok("PasswordAuthentication yes"))])
        result = SSHHardeningCheck(executor, "linux").run()
        assert result.status == Status.FAIL
        assert result.details["issues"][0]["setting"] == "PasswordAuthentication"

    def test_commented_settings_are_ignored(self):
        executor = ScriptedExecutor([("sshd_config", ok("#PermitRootLogin yes"))])
        result = SSHHardeningCheck(executor, "linux").run()
        assert result.status == Status.PASS

    def test_no_sshd_config_skips(self):
        executor = ScriptedExecutor([("sshd_config", fail("No such file"))])
        result = SSHHardeningCheck(executor, "linux").run()
        assert result.status == Status.SKIP

    def test_not_supported_on_windows(self):
        result = SSHHardeningCheck(ScriptedExecutor(), "windows").run()
        assert result.status == Status.SKIP


class TestStealthModeCheck:
    def test_enabled_passes(self):
        executor = ScriptedExecutor(
            [("getstealthmode", ok("Stealth mode enabled"))], os_type="macos"
        )
        result = StealthModeCheck(executor, "macos").run()
        assert result.status == Status.PASS

    def test_macos_only(self):
        result = StealthModeCheck(ScriptedExecutor(), "windows").run()
        assert result.status == Status.SKIP


class TestSecurityUpdatesCheck:
    def test_windows_no_pending_updates(self):
        executor = ScriptedExecutor(
            [("Microsoft.Update.Session", ok("0"))], os_type="windows"
        )
        result = SecurityUpdatesCheck(executor, "windows").run()
        assert result.status == Status.PASS

    def test_windows_pending_updates_fail(self):
        executor = ScriptedExecutor(
            [("Microsoft.Update.Session", ok("4"))], os_type="windows"
        )
        result = SecurityUpdatesCheck(executor, "windows").run()
        assert result.status == Status.FAIL
        assert "4" in result.message

    def test_windows_com_failure_warns(self):
        executor = ScriptedExecutor(
            [("Microsoft.Update.Session", fail("COM error"))], os_type="windows"
        )
        result = SecurityUpdatesCheck(executor, "windows").run()
        assert result.status == Status.WARN

    def test_linux_security_updates_pending(self):
        executor = ScriptedExecutor([("apt list", ok("12"))])
        result = SecurityUpdatesCheck(executor, "linux").run()
        assert result.status == Status.FAIL

    def test_linux_up_to_date(self):
        executor = ScriptedExecutor([("apt list", ok("0"))])
        result = SecurityUpdatesCheck(executor, "linux").run()
        assert result.status == Status.PASS
