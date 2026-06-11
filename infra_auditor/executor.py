"""Command executor for local and remote systems."""

import logging
import subprocess
import platform
from abc import ABC, abstractmethod
from typing import Optional, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    returncode: int

    @property
    def success(self) -> bool:
        return self.returncode == 0

    @property
    def output(self) -> str:
        return self.stdout.strip() or self.stderr.strip()


class Executor(ABC):
    @abstractmethod
    def run(self, command: str, timeout: int = 30) -> CommandResult:
        pass

    @abstractmethod
    def detect_os(self) -> str:
        pass

    def close(self):
        pass


class LocalExecutor(Executor):
    def __init__(self):
        self._os_type = None

    def run(self, command: str, timeout: int = 30) -> CommandResult:
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return CommandResult(
                stdout=result.stdout, stderr=result.stderr, returncode=result.returncode
            )
        except subprocess.TimeoutExpired:
            return CommandResult(stdout="", stderr="Command timed out", returncode=-1)
        except Exception as e:
            return CommandResult(stdout="", stderr=str(e), returncode=-1)

    def detect_os(self) -> str:
        if self._os_type:
            return self._os_type
        system = platform.system().lower()
        if system == "darwin":
            self._os_type = "macos"
        elif system == "linux":
            self._os_type = "linux"
        elif system == "windows":
            self._os_type = "windows"
        else:
            self._os_type = "unknown"
        return self._os_type


class SSHExecutor(Executor):
    def __init__(
        self,
        host: str,
        port: int = 22,
        username: Optional[str] = None,
        key_file: Optional[str] = None,
        insecure_host_key: bool = False,
    ):
        self.host, self.port, self.username, self.key_file = (
            host,
            port,
            username,
            key_file,
        )
        self.insecure_host_key = insecure_host_key
        if insecure_host_key:
            logger.warning(
                "SSH host key verification is DISABLED for %s "
                "(insecure_host_key=True): connections are vulnerable to "
                "man-in-the-middle attacks. Remove the flag to restore "
                "verification.",
                host,
            )
        self._os_type = None

    def _build_ssh_command(self, command: str) -> List[str]:
        # accept-new (OpenSSH >= 7.6) records keys of hosts seen for the
        # first time but refuses connections when a known key changes.
        host_key_policy = "no" if self.insecure_host_key else "accept-new"
        ssh_cmd = [
            "ssh",
            "-o",
            f"StrictHostKeyChecking={host_key_policy}",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
        ]
        if self.key_file:
            ssh_cmd.extend(["-i", self.key_file])
        if self.port != 22:
            ssh_cmd.extend(["-p", str(self.port)])
        target = f"{self.username}@{self.host}" if self.username else self.host
        ssh_cmd.extend([target, command])
        return ssh_cmd

    def run(self, command: str, timeout: int = 30) -> CommandResult:
        try:
            ssh_cmd = self._build_ssh_command(command)
            result = subprocess.run(
                ssh_cmd, capture_output=True, text=True, timeout=timeout
            )
            return CommandResult(
                stdout=result.stdout, stderr=result.stderr, returncode=result.returncode
            )
        except subprocess.TimeoutExpired:
            return CommandResult(
                stdout="", stderr="SSH command timed out", returncode=-1
            )
        except Exception as e:
            return CommandResult(stdout="", stderr=str(e), returncode=-1)

    def detect_os(self) -> str:
        if self._os_type:
            return self._os_type
        result = self.run("uname -s")
        if result.success:
            uname = result.stdout.strip().lower()
            if uname == "darwin":
                self._os_type = "macos"
            elif uname == "linux":
                self._os_type = "linux"
            else:
                self._os_type = uname
            return self._os_type
        result = self.run("ver")
        if result.success and "windows" in result.stdout.lower():
            self._os_type = "windows"
            return self._os_type
        self._os_type = "unknown"
        return self._os_type


def create_executor(host: str = "localhost", **kwargs) -> Executor:
    if host == "localhost" or host == "127.0.0.1":
        return LocalExecutor()
    return SSHExecutor(host=host, **kwargs)
