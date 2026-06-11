"""Tests for command executors, focused on SSH host key policy."""

import logging

from infra_auditor.executor import LocalExecutor, SSHExecutor, create_executor


class TestSSHHostKeyPolicy:
    def test_host_key_verification_enabled_by_default(self):
        executor = SSHExecutor(host="server.example.com")
        cmd = executor._build_ssh_command("uname -s")
        assert "StrictHostKeyChecking=accept-new" in cmd
        assert "StrictHostKeyChecking=no" not in cmd

    def test_insecure_flag_disables_verification(self):
        executor = SSHExecutor(host="server.example.com", insecure_host_key=True)
        cmd = executor._build_ssh_command("uname -s")
        assert "StrictHostKeyChecking=no" in cmd

    def test_insecure_flag_logs_warning(self, caplog):
        with caplog.at_level(logging.WARNING, logger="infra_auditor.executor"):
            SSHExecutor(host="server.example.com", insecure_host_key=True)
        assert any(
            "host key verification is DISABLED" in record.getMessage()
            and record.levelno == logging.WARNING
            for record in caplog.records
        )

    def test_secure_default_logs_no_warning(self, caplog):
        with caplog.at_level(logging.WARNING, logger="infra_auditor.executor"):
            SSHExecutor(host="server.example.com")
        assert not caplog.records


class TestCreateExecutor:
    def test_localhost_uses_local_executor(self):
        assert isinstance(create_executor("localhost"), LocalExecutor)
        assert isinstance(create_executor("127.0.0.1"), LocalExecutor)

    def test_remote_host_uses_ssh_executor(self):
        executor = create_executor("server.example.com", username="admin")
        assert isinstance(executor, SSHExecutor)

    def test_insecure_host_key_passed_through(self):
        executor = create_executor("server.example.com", insecure_host_key=True)
        assert executor.insecure_host_key is True
