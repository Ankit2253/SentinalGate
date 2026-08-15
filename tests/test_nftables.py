import subprocess
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from sentinelgate.config import FirewallConfig
from sentinelgate.models import Ban, Rule
from sentinelgate.nftables import NftablesBackend, RulesetRenderer


def test_renderer_builds_stateful_safe_order() -> None:
    config = FirewallConfig(
        management_cidrs=["192.168.56.0/24"],
        management_ports=[22, 8080],
    )
    rule = Rule(
        name='Block inbound SMB "test"; delete table',
        direction="input",
        action="block",
        protocol="tcp",
        source="0.0.0.0/0",
        destination_port=445,
        priority=50,
    )

    rendered = RulesetRenderer(config).render([rule])

    assert "table inet sentinelgate" in rendered
    assert "ct state established,related counter accept" in rendered
    assert "ip saddr 192.168.56.0/24 tcp dport { 22, 8080 }" in rendered
    assert "ip saddr 0.0.0.0/0 meta l4proto tcp tcp dport 445" in rendered
    assert 'comment "SG: Block inbound SMB test delete table"' in rendered
    assert rendered.index("Protected management path") < rendered.index("SG: Block inbound SMB")


def test_log_rate_limit_does_not_limit_verdict() -> None:
    rule = Rule(
        name="Block admin port",
        direction="input",
        action="block",
        protocol="tcp",
        destination_port=3389,
    )
    lines = RulesetRenderer(FirewallConfig()).render([rule]).splitlines()
    log_line = next(line for line in lines if "SG_RULE_" in line and "log prefix" in line)
    verdict_line = next(line for line in lines if "SG: Block admin port" in line)

    assert "limit rate" in log_line
    assert " drop " not in f" {log_line} "
    assert "counter drop" in verdict_line
    assert "limit rate" not in verdict_line


def test_unexpired_bans_are_rendered_into_timed_sets() -> None:
    ban = Ban(
        ip="203.0.113.20",
        reason="test",
        created_at=datetime.now(UTC).isoformat(),
        expires_at=(datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
    )
    rendered = RulesetRenderer(FirewallConfig()).render([], [ban])
    assert "elements = { 203.0.113.20 timeout" in rendered


class FakeRunner:
    def __init__(self):
        self.calls: list[tuple[list[str], str | None]] = []

    def run(self, args: list[str], input_text: str | None = None):
        self.calls.append((args, input_text))
        returncode = 1 if args[1:3] == ["list", "table"] else 0
        return subprocess.CompletedProcess(args, returncode, "", "")


def test_backend_uses_argument_arrays_and_checks_before_apply() -> None:
    config = FirewallConfig(mode="apply", nft_binary="/usr/sbin/nft")
    runner = FakeRunner()
    backend = NftablesBackend(config, runner)
    rendered = RulesetRenderer(config).render([])

    with patch.object(backend, "binary_path", return_value="/usr/sbin/nft"), patch(
        "sentinelgate.nftables.os.geteuid", return_value=0
    ):
        result = backend.apply(rendered)

    assert result.applied is True
    assert [call[0] for call in runner.calls] == [
        ["/usr/sbin/nft", "list", "table", "inet", "sentinelgate"],
        ["/usr/sbin/nft", "--check", "-f", "-"],
        ["/usr/sbin/nft", "-f", "-"],
    ]
    assert runner.calls[1][1] == rendered
    assert runner.calls[2][1] == rendered

