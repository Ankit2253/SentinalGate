# Portfolio presentation notes

## One-line description

Built a safe-by-default Linux stateful firewall with atomic nftables deployment, policy rollback,
scan detection, temporary blocking, a REST API, and a SOC operations dashboard.

## What to demonstrate in 90 seconds

1. Open the dashboard in dry-run mode and explain why safe simulation is the default.
2. Show the management-path rule generated before custom policy.
3. Add a TCP block rule and deploy it to a dry-run snapshot.
4. Load sample telemetry and identify the top scanning source.
5. Show the event stream, temporary block, and rollback snapshot.
6. Open the architecture and threat-model documents to discuss design limitations honestly.

## CV bullets

- Engineered a Python/FastAPI stateful firewall control plane that validates policy and generates
  atomic Linux nftables rulesets with management lockout protection and versioned rollback.
- Implemented kernel-log parsing and time-window port-scan detection with protected-network
  safeguards, temporary IPv4/IPv6 blocklists, SQLite audit history, and JSON evidence export.
- Built a responsive SOC dashboard and CLI, secured non-local API binding with bearer
  authentication, and verified rule, API, persistence, detection, and rollback behaviour with
  automated tests.

## Honest scope statement

SentinelGate is a portfolio and isolated-lab project, not a production-certified appliance. It
demonstrates firewall architecture, secure command execution, detection engineering, telemetry,
and safety controls. It intentionally does not claim deep-packet inspection, enterprise identity,
high availability, or independent security assurance.

