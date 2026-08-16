# Isolated VM lab guide

Use an isolated hypervisor lab. Do not begin on the router that provides your normal internet
connection.

## Suggested topology

| VM | Interface | Address | Purpose |
|---|---|---:|---|
| Kali/test client | `sg-wan` | `172.16.10.20/24` | Generates test traffic |
| SentinelGate | `sg-wan` | `172.16.10.1/24` | External firewall interface |
| SentinelGate | `sg-lan` | `10.10.20.1/24` | Protected network gateway |
| SentinelGate | Host-only | `192.168.56.10/24` | Separate management path |
| Ubuntu/Windows target | `sg-lan` | `10.10.20.15/24` | Protected test host |

Set the protected target's default gateway to `10.10.20.1`. Keep the VM console open while
testing. If you are testing forwarding, enable IPv4 forwarding on the SentinelGate VM only after
the interfaces are correct:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

This setting is temporary. Persist it only after the lab works as expected.

## Install and start safely

```bash
sudo apt update
sudo apt install -y python3-venv nftables
./scripts/bootstrap.sh
.venv/bin/sentinelgate --config sentinelgate.toml demo
```

Open `http://127.0.0.1:8080` inside the VM, or use an SSH tunnel from the host:

```bash
ssh -L 8080:127.0.0.1:8080 user@192.168.56.10
```

Then open `http://127.0.0.1:8080` on the host.

## Validate before enforcement

1. Edit `management_cidrs` so it exactly contains your host-only network.
2. Leave `mode = "dry-run"`.
3. Add the required forward allow rules.
4. Render and inspect the result:

```bash
.venv/bin/sentinelgate --config sentinelgate.toml render
.venv/bin/sentinelgate --config sentinelgate.toml apply
```

The second command creates a dry-run snapshot and `data/last-rendered.nft`; it does not change
the firewall.

## Enable the lab firewall

Change only this line after checking the management rule:

```toml
mode = "apply"
```

From the VM console, apply the policy:

```bash
sudo .venv/bin/sentinelgate --config sentinelgate.toml apply --confirm APPLY \
  --reason "First isolated lab deployment"
```

Test SSH management before closing the console. If you need to restore a prior policy:

```bash
sudo .venv/bin/sentinelgate --config sentinelgate.toml snapshots
sudo .venv/bin/sentinelgate --config sentinelgate.toml rollback 1 --confirm ROLLBACK
```

## Generate and observe test traffic

Start event monitoring on SentinelGate:

```bash
sudo .venv/bin/sentinelgate --config sentinelgate.toml monitor
```

From the Kali/test VM, scan only the protected lab host you own:

```bash
nmap -sT -Pn -p 20-100,135,139,445,3389 10.10.20.15
```

Review events in the dashboard. When the configured count and unique-port threshold is reached,
the source is added to a timed nftables set unless it belongs to the protected management network.

## Stop the experiment

Use the hypervisor console. Do not delete the whole host ruleset; SentinelGate owns only its
named `inet sentinelgate` table. Switch the configuration back to dry-run before continuing
development.

