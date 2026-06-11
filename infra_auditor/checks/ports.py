"""Open ports check."""

from .base import BaseCheck, CheckRegistry
from ..results import Severity


@CheckRegistry.register("open_ports")
class OpenPortsCheck(BaseCheck):
    name = "Open Ports"
    description = "Identify potentially unnecessary open network ports"
    supported_os = ["macos", "linux", "windows"]
    default_severity = Severity.MEDIUM
    DANGEROUS_PORTS = {
        21: "FTP",
        23: "Telnet",
        445: "SMB",
        3389: "RDP",
        5900: "VNC",
        6379: "Redis",
        27017: "MongoDB",
        3306: "MySQL",
        5432: "PostgreSQL",
    }

    def run(self):
        if not self.is_supported():
            return self.skip(f"Check not supported on {self.os_type}")
        allowed = set(self.params.get("allowed_ports", []))
        disallowed = set(self.params.get("disallowed_ports", []))
        if self.os_type == "macos":
            result = self.executor.run("netstat -an | grep LISTEN")
        elif self.os_type == "linux":
            result = self.executor.run(
                "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"
            )
        else:
            result = self.executor.run("netstat -an | findstr LISTENING")
        concerns = []
        listening = []
        for line in result.output.split("\n"):
            for part in line.split():
                if ":" in part or "." in part:
                    try:
                        port = int(part.rsplit(":", 1)[-1].rsplit(".", 1)[-1])
                        if port < 49152:
                            listening.append(port)
                            if port in disallowed:
                                concerns.append(
                                    {"port": port, "reason": "Explicitly disallowed"}
                                )
                            elif port in self.DANGEROUS_PORTS and port not in allowed:
                                concerns.append(
                                    {"port": port, "reason": self.DANGEROUS_PORTS[port]}
                                )
                    except ValueError:
                        pass
        listening = sorted(set(listening))
        if concerns:
            return self.failed(
                f"Found {len(concerns)} potentially dangerous open port(s)",
                remediation="Close unnecessary ports or add to allowed_ports",
                details={"concerns": concerns, "all_listening_ports": listening},
            )
        return self.passed(
            f"No dangerous ports detected ({len(listening)} ports open)",
            details={"listening_ports": listening},
        )
