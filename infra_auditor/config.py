"""Configuration parser."""

import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Union, List, Dict


@dataclass
class CheckConfig:
    enabled: bool = True
    # None means "not overridden": the check's own default severity applies.
    severity: Optional[str] = None
    params: dict = field(default_factory=dict)


@dataclass
class TargetConfig:
    host: str
    port: int = 22
    username: Optional[str] = None
    key_file: Optional[str] = None
    os_type: Optional[str] = None
    # Disables SSH host key verification (StrictHostKeyChecking=no).
    # Insecure; off by default.
    insecure_host_key: bool = False


@dataclass
class Config:
    targets: List[TargetConfig] = field(default_factory=list)
    checks: Dict[str, CheckConfig] = field(default_factory=dict)
    global_settings: dict = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: Union[str, Path]) -> "Config":
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        config = cls()
        for target_data in data.get("targets", []):
            if isinstance(target_data, str):
                config.targets.append(TargetConfig(host=target_data))
            else:
                config.targets.append(
                    TargetConfig(
                        host=target_data.get("host", "localhost"),
                        port=target_data.get("port", 22),
                        username=target_data.get("username"),
                        key_file=target_data.get("key_file"),
                        os_type=target_data.get("os_type"),
                        insecure_host_key=bool(
                            target_data.get("insecure_host_key", False)
                        ),
                    )
                )
        if not config.targets:
            config.targets.append(TargetConfig(host="localhost"))
        for check_id, check_data in data.get("checks", {}).items():
            if isinstance(check_data, bool):
                config.checks[check_id] = CheckConfig(enabled=check_data)
            elif isinstance(check_data, dict):
                config.checks[check_id] = CheckConfig(
                    enabled=check_data.get("enabled", True),
                    severity=check_data.get("severity"),
                    params=check_data.get("params", {}),
                )
            else:
                config.checks[check_id] = CheckConfig()
        config.global_settings = data.get("settings", {})
        return config

    def is_check_enabled(self, check_id: str) -> bool:
        if check_id in self.checks:
            return self.checks[check_id].enabled
        return True

    def get_check_severity(self, check_id: str) -> Optional[str]:
        """Return the configured severity override, or None to keep the
        check's own default."""
        if check_id in self.checks:
            return self.checks[check_id].severity
        return None

    def get_check_params(self, check_id: str) -> dict:
        if check_id in self.checks:
            return self.checks[check_id].params
        return {}
