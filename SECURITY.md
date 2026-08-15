# Security policy

SentinelGate is an educational and portfolio firewall. It has not undergone an independent
security audit and must not be treated as a replacement for a supported production appliance.

## Safe operation

- Start with `mode = "dry-run"`. In this mode SentinelGate renders policy but never calls `nft`.
- Test from a VM console before using SSH. A wrong management network can lock you out.
- Bind the dashboard to `127.0.0.1` unless a strong bearer token is supplied through the
  configured environment variable.
- Never store the bearer token in the TOML file or commit it to Git.
- Keep a separate hypervisor console open during the first real policy deployment.
- Back up the VM before enabling forwarding or real enforcement.
- Review `data/last-rendered.nft` before changing `mode` to `apply`.

## Deliberate safeguards

- Real deployment and rollback require an explicit confirmation word.
- `subprocess` receives argument arrays; the project never uses `shell=True`.
- Networks, ports, table names, protocols, durations, and IP addresses are validated.
- Rulesets are syntax-checked and applied as one nftables transaction.
- Loopback and configured management networks cannot be dynamically banned.
- Every deployment creates a rollback snapshot and audit event.
- API access outside loopback is rejected at startup unless a token is configured.
- Browser responses include CSP, frame, MIME-sniffing, referrer, and permissions headers.

## Reporting a problem

Do not publish a working exploit or sensitive firewall configuration. Open a private security
report with the affected version, a minimal reproduction, impact, and suggested remediation.

