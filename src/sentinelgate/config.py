"""Configuration loading and safety validation."""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    token_env: str = "SENTINELGATE_ADMIN_TOKEN"

    @property
    def admin_token(self) -> str:
        return os.environ.get(self.token_env, "")


@dataclass(slots=True)
class FirewallConfig:
    mode: str = "dry-run"
    table_name: str = "sentinelgate"
    management_cidrs: list[str] = field(default_factory=lambda: ["192.168.56.0/24"])
    management_ports: list[int] = field(default_factory=lambda: [22, 8080])
    default_input_policy: str = "drop"
    default_forward_policy: str = "drop"
    default_output_policy: str = "accept"
    allow_icmp: bool = True
    log_rate: str = "10/second"
    nft_binary: str = "nft"
    auto_block: bool = True
    scan_threshold: int = 12
    scan_window_seconds: int = 30
    ban_seconds: int = 900


@dataclass(slots=True)
class StorageConfig:
    state_dir: str = "./data"
    database: str = "./data/sentinelgate.db"


@dataclass(slots=True)
class AppConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    source_path: Path | None = None

    @property
    def database_path(self) -> Path:
        value = Path(self.storage.database).expanduser()
        if not value.is_absolute() and self.source_path:
            value = self.source_path.parent / value
        return value.resolve()

    @property
    def state_path(self) -> Path:
        value = Path(self.storage.state_dir).expanduser()
        if not value.is_absolute() and self.source_path:
            value = self.source_path.parent / value
        return value.resolve()

    def validate(self) -> None:
        if self.firewall.mode not in {"dry-run", "apply"}:
            raise ValueError("firewall.mode must be 'dry-run' or 'apply'")
        if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]{0,31}", self.firewall.table_name):
            raise ValueError("Invalid nftables table name")
        if self.firewall.default_input_policy not in {"accept", "drop"}:
            raise ValueError("Invalid input policy")
        if self.firewall.default_forward_policy not in {"accept", "drop"}:
            raise ValueError("Invalid forward policy")
        if self.firewall.default_output_policy not in {"accept", "drop"}:
            raise ValueError("Invalid output policy")
        if not re.fullmatch(r"[1-9]\d{0,4}/(second|minute|hour)", self.firewall.log_rate):
            raise ValueError("log_rate must look like '10/second'")
        self.firewall.management_cidrs = [
            str(ip_network(value, strict=False)) for value in self.firewall.management_cidrs
        ]
        if any(not 1 <= int(port) <= 65535 for port in self.firewall.management_ports):
            raise ValueError("Invalid management port")
        if not 1 <= self.server.port <= 65535:
            raise ValueError("Invalid server port")
        try:
            address = ip_address(self.server.host)
            is_local = address.is_loopback
        except ValueError:
            is_local = self.server.host.lower() == "localhost"
        if not is_local and not self.server.admin_token:
            raise ValueError(
                f"Set {self.server.token_env} before binding the API to a non-loopback address"
            )
        if not 2 <= self.firewall.scan_threshold <= 10_000:
            raise ValueError("scan_threshold must be between 2 and 10000")
        if not 1 <= self.firewall.scan_window_seconds <= 3600:
            raise ValueError("scan_window_seconds must be between 1 and 3600")
        if not 30 <= self.firewall.ban_seconds <= 604_800:
            raise ValueError("ban_seconds must be between 30 and 604800")


def _section(cls: type, data: dict[str, Any], key: str):
    values = data.get(key, {})
    allowed = cls.__dataclass_fields__.keys()
    return cls(**{name: value for name, value in values.items() if name in allowed})


def load_config(path: str | Path | None = None) -> AppConfig:
    selected = Path(path or os.environ.get("SENTINELGATE_CONFIG", "sentinelgate.toml"))
    source_path: Path | None = selected.resolve() if selected.exists() else None
    data: dict[str, Any] = {}
    if selected.exists():
        with selected.open("rb") as handle:
            data = tomllib.load(handle)
    config = AppConfig(
        server=_section(ServerConfig, data, "server"),
        firewall=_section(FirewallConfig, data, "firewall"),
        storage=_section(StorageConfig, data, "storage"),
        source_path=source_path,
    )
    config.validate()
    return config

