from pathlib import Path

import pytest

from sentinelgate.config import AppConfig, FirewallConfig, ServerConfig, StorageConfig
from sentinelgate.service import FirewallService


@pytest.fixture
def app_config(tmp_path: Path) -> AppConfig:
    config = AppConfig(
        server=ServerConfig(host="127.0.0.1", port=8080),
        firewall=FirewallConfig(
            mode="dry-run",
            management_cidrs=["192.168.56.0/24"],
            management_ports=[22, 8080],
            scan_threshold=5,
            scan_window_seconds=30,
        ),
        storage=StorageConfig(
            state_dir=str(tmp_path / "state"),
            database=str(tmp_path / "sentinelgate.db"),
        ),
    )
    config.validate()
    return config


@pytest.fixture
def service(app_config: AppConfig) -> FirewallService:
    return FirewallService(app_config)

