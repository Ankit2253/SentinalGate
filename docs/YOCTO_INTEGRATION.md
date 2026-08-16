# SentinelGate v1.0 — Yocto / Embedded Linux Security Integration

## Goal

Add a small, auditable Yocto component to SentinelGate v1.0 without changing the existing firewall engine. The component demonstrates how SentinelGate could be integrated into a controlled embedded-Linux/ECU image and how system configuration can be hardened at image-build time.

## Architecture

```text
Yocto / OpenEmbedded
        |
        +-- meta-sentinelgate
               |
               +-- sentinelgate-hardening_1.0.0.bb
               |      |
               |      +-- systemd service hardening
               |      +-- sysctl hardening
               |      +-- tmpfiles permissions
               |
               +-- sentinelgate-security-image.bb
                      |
                      +-- core-image-minimal
                      +-- sentinelgate-hardening
```

## Security decisions

### 1. systemd sandboxing

The drop-in uses controls such as `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, `ProtectKernelTunables`, and `CapabilityBoundingSet`.

SentinelGate is a firewall, so the policy deliberately retains `CAP_NET_ADMIN`, `CAP_NET_RAW`, and `AF_NETLINK`. Removing these blindly could prevent nftables/network operations.

### 2. Kernel/network sysctl policy

The layer disables ICMP redirects and reduces kernel information disclosure. It intentionally does **not** disable IP forwarding because a firewall/gateway deployment may require forwarding.

### 3. Restricted state directories

`systemd-tmpfiles` creates SentinelGate state, log, and runtime directories with mode `0750`.

## How to test in a real Yocto environment

```bash
source oe-init-build-env
bitbake-layers add-layer /path/to/sentinelgate/yocto/meta-sentinelgate
bitbake-layers show-layers
bitbake-layers show-recipes sentinelgate-hardening
bitbake sentinelgate-hardening
bitbake sentinelgate-security-image
```

After booting the image, inspect:

```bash
systemctl cat sentinelgate.service
systemd-analyze security sentinelgate.service
sysctl kernel.dmesg_restrict
sysctl net.ipv4.conf.all.accept_redirects
stat -c '%a %U %G %n' /var/lib/sentinelgate /var/log/sentinelgate /run/sentinelgate
```

## Interview explanation

> I added a custom Yocto layer to my SentinelGate Linux firewall project. The layer contains a BitBake recipe that applies embedded-Linux hardening at image-build time, including a systemd sandbox profile, conservative sysctl settings, and restricted runtime directories. I kept the policy aware of SentinelGate's firewall requirements by retaining the network capabilities and netlink access it needs, rather than applying security controls that would break the service.

## Limitation

The metadata is statically validated in this package, but a full BitBake image build requires an actual Yocto build environment with the selected release and its source downloads. That environment is not bundled here.
