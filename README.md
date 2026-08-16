# SentinelGate

SentinelGate is a safe-by-default Linux stateful firewall and blue-team monitoring platform. It
turns validated policy into an atomic `nftables` ruleset, records every deployment, detects rapid
port scanning, maintains temporary IPv4/IPv6 blocklists, and presents the result in a local SOC
dashboard.

The project starts in **dry-run mode**: it can be fully demonstrated without root access and
without changing the host firewall.

## Capabilities

- Stateful input, forwarding, and output chains.
- Allow/block rules by IP or CIDR, direction, protocol, and port/range.
- Separate IPv4 and IPv6 dynamic blocklists with expiration.
- Management-path protection placed before custom policy.
- Atomic syntax-check and deployment through `nft --check` and `nft -f`.
- Full ruleset snapshots with safe rollback.
- Kernel-log parsing and unique-port scan detection.
- SQLite event, policy, ban, and snapshot history.
- FastAPI control plane with bearer authentication for non-local binding.
- Responsive dashboard, command-line interface, JSON evidence export, and deterministic demo data.
- No `shell=True`, no raw nftables fragments, and no automatic change in the default mode.

## Quick start: safe dashboard demo

Requirements: Python 3.11 or newer. `nftables` is not required for dry-run mode.

```bash
cd sentinelgate
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/sentinelgate init
.venv/bin/sentinelgate --config sentinelgate.toml demo
```

Open [http://127.0.0.1:8080](http://127.0.0.1:8080). The demo adds four sample rules and labelled
documentation-range telemetry. It never generates network traffic.

You can also run only the data seeding and inspect the CLI:

```bash
.venv/bin/sentinelgate --config sentinelgate.toml demo --no-server
.venv/bin/sentinelgate --config sentinelgate.toml status
.venv/bin/sentinelgate --config sentinelgate.toml rules list
.venv/bin/sentinelgate --config sentinelgate.toml events --limit 10
```

## Rule examples

Block inbound SMB:

```bash
.venv/bin/sentinelgate --config sentinelgate.toml rules add \
  --name "Block inbound SMB" \
  --direction input --action block --protocol tcp \
  --source 0.0.0.0/0 --destination-port 445 --priority 50
```

Allow an internal network to reach a local application:

```bash
.venv/bin/sentinelgate --config sentinelgate.toml rules add \
  --name "Allow internal application" \
  --direction input --action allow --protocol tcp \
  --source 10.10.0.0/16 --destination-port 8443 --priority 90
```

Render the exact policy:

```bash
.venv/bin/sentinelgate --config sentinelgate.toml render
.venv/bin/sentinelgate --config sentinelgate.toml apply --reason "Reviewed dry run"
```

In dry-run mode, `apply` means “validate the application model, render, save, and snapshot.” It
does not execute `nft`.

## Real enforcement in an isolated Linux VM

Read [docs/lab-guide.md](docs/lab-guide.md) before enabling enforcement. The short version is:

1. Install the Linux `nftables` package.
2. Use a VM with a separate console and management interface.
3. Set `management_cidrs` and `management_ports` correctly.
4. Inspect the rendered rules while `mode = "dry-run"`.
5. Change the mode to `apply` and use explicit confirmation from the VM console:

```bash
sudo .venv/bin/sentinelgate --config sentinelgate.toml apply --confirm APPLY
```

SentinelGate owns only `table inet sentinelgate`; it does not flush unrelated host rulesets.

## CLI reference

| Command | Purpose |
|---|---|
| `sentinelgate init` | Create a safe starter configuration |
| `sentinelgate status` | Show mode, policy, nft availability, counts, and active snapshot |
| `sentinelgate render` | Print the complete generated nftables table |
| `sentinelgate apply` | Snapshot a dry run or explicitly deploy in apply mode |
| `sentinelgate rules list/add/delete/toggle` | Manage validated policy rules |
| `sentinelgate events` | Query recent firewall events |
| `sentinelgate ban/unban` | Manage a timed IP block |
| `sentinelgate monitor` | Follow `SG_*` kernel logs and run scan detection |
| `sentinelgate snapshots/rollback` | Inspect or restore policy history |
| `sentinelgate report` | Export rules, statistics, events, bans, and snapshots to JSON |
| `sentinelgate demo` | Seed safe sample telemetry and run the dashboard |

Every command accepts `--config PATH` before the subcommand.

## API security

The default dashboard binds to loopback and needs no token. Binding to any non-loopback address
is rejected unless the configured token environment variable is present:

```bash
export SENTINELGATE_ADMIN_TOKEN="replace-with-a-long-random-value"
.venv/bin/sentinelgate --config sentinelgate.toml serve --host 192.168.56.10
```

The UI's **Access token** action keeps the token in browser session storage. Prefer an SSH tunnel
and loopback binding because the built-in server does not terminate TLS.

Interactive API documentation is at `http://127.0.0.1:8080/api/docs`.

## Detection logic

The monitor reads kernel records containing SentinelGate's `SG_*` prefixes. A scan requires both:

- at least `scan_threshold` blocked attempts inside `scan_window_seconds`; and
- attempts across at least five unique destination ports (or the threshold, if lower).

When `auto_block` is enabled, the source enters a timed nftables set. Loopback, multicast,
unspecified, and configured management addresses are never automatically banned. Slow and
distributed scans are known limitations, documented in [docs/threat-model.md](docs/threat-model.md).

## Tests

```bash
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/ruff check src tests
```

The suite covers validation, rendering, database operations, dry-run apply and rollback, dynamic
bans, log parsing, scan detection, authentication, and API rule management.

## Project map

```text
src/sentinelgate/
├── api.py          # authenticated API and dashboard delivery
├── cli.py          # command-line workflows
├── config.py       # TOML loading and startup safety checks
├── database.py     # SQLite rule/event/snapshot repository
├── demo.py         # deterministic sample telemetry
├── models.py       # strict domain validation
├── monitor.py      # kernel-log parser and scan detector
├── nftables.py     # atomic ruleset renderer and backend
├── service.py      # application orchestration and rollback
└── static/         # dependency-free SOC dashboard
```

Additional design detail is in [docs/architecture.md](docs/architecture.md). Recruiter-ready CV
bullets and a short demonstration script are in [docs/portfolio-notes.md](docs/portfolio-notes.md).

## Scope

This is an educational and portfolio project, not an independently audited or production-certified
firewall appliance. It does not perform deep-packet inspection, TLS interception, multi-user RBAC,
distributed synchronization, or high-availability failover. Review [SECURITY.md](SECURITY.md)
before using real enforcement.

## License

MIT License. See [LICENSE](LICENSE).
