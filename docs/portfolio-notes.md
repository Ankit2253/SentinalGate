# Portfolio presentation notes

## One-line description

Built a safe-by-default Linux stateful firewall with atomic nftables deployment, policy rollback,
scan detection, temporary blocking, a REST API, a SOC operations dashboard, and a Yocto/OpenEmbedded
hardening layer for embedded-Linux deployment.

## What to demonstrate in 90 seconds

1. Open the dashboard in dry-run mode and explain why safe simulation is the default.
2. Show the management-path rule generated before custom policy.
3. Add a TCP block rule and deploy it to a dry-run snapshot.
4. Load sample telemetry and identify the top scanning source.
5. Show the event stream, temporary block, and rollback snapshot.
6. Show `yocto/meta-sentinelgate` and explain how the BitBake recipe hardens a future embedded-Linux
   deployment without changing the firewall engine.
7. Open the architecture and threat-model documents to discuss design limitations honestly.

## CV bullets

- Engineered a Python/FastAPI stateful firewall control plane that validates policy and generates
  atomic Linux nftables rulesets with management lockout protection and versioned rollback.
- Implemented kernel-log parsing and time-window port-scan detection with protected-network
  safeguards, temporary IPv4/IPv6 blocklists, SQLite audit history, and JSON evidence export.
- Built a responsive SOC dashboard and CLI, secured non-local API binding with bearer
  authentication, and verified rule, API, persistence, detection, and rollback behaviour with
  automated tests.
- Added a Yocto/OpenEmbedded `meta-sentinelgate` layer with a custom BitBake hardening recipe,
  systemd sandboxing, sysctl controls, restricted runtime directories, and a minimal image recipe;
  metadata is covered by automated tests, while a full BitBake image build remains a separate lab step.

## Honest scope statement

SentinelGate is a portfolio and isolated-lab project, not a production-certified appliance. It
demonstrates firewall architecture, secure command execution, detection engineering, telemetry,
security configuration, and safety controls. The included Yocto metadata is validated statically; a
full image build and hardware/ECU validation are not claimed. It intentionally does not claim
deep-packet inspection, enterprise identity, high availability, or independent security assurance.

