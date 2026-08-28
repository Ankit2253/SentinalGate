# SentinelGate v1.1 — Yocto / Embedded Linux Integration

## Goal

SentinelGate v1.1 includes a custom Yocto/OpenEmbedded layer that packages the SentinelGate application together with Linux security hardening.

The integration preserves SentinelGate's safe-by-default architecture and keeps real firewall enforcement disabled by default.

## Architecture

```text
Yocto / OpenEmbedded
        |
        +-- meta-sentinelgate
               |
               +-- sentinelgate_1.1.0.bb
               |      |
               |      +-- SentinelGate Python application
               |      +-- C2 Guard
               |      +-- threat intelligence
               |      +-- trusted-destination controls
               |      +-- FastAPI control plane
               |      +-- SOC dashboard
               |      +-- analyst-response functionality
               |      +-- systemd service
               |      +-- safe default configuration
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
                      +-- sentinelgate
                      +-- sentinelgate-hardening
```

## SentinelGate Application Recipe

The v1.1 application is represented by:

```text
recipes-security/sentinelgate/sentinelgate_1.1.0.bb
```

The recipe packages the SentinelGate Python source and its runtime integration.

Runtime requirements include Python, FastAPI, Pydantic, Uvicorn, and nftables.

The package installs the SentinelGate systemd service and configuration into standard image locations rather than relying on the development virtual environment used on Parrot OS.

## Safe Configuration

The Yocto configuration keeps:

```toml
[firewall]
mode = "dry-run"
```

as the default.

C2 Guard configuration is also included, with support for:

- enable/disable control
- minimum-confidence threshold
- trusted destinations
- local threat-intelligence IP indicators

Runtime state is stored under `/var/lib/sentinelgate`.

## Security Hardening

The separate `sentinelgate-hardening` package provides additional Linux security controls.

### systemd sandboxing

Controls include:

- `NoNewPrivileges`
- `ProtectSystem`
- `ProtectHome`
- `ProtectKernelTunables`
- `ProtectKernelModules`
- `ProtectControlGroups`
- restricted address families
- controlled writable paths
- restricted capability sets

SentinelGate deliberately retains `CAP_NET_ADMIN`, `CAP_NET_RAW`, and `AF_NETLINK` because firewall/network operations require them.

### Kernel/network policy

The sysctl policy disables unsafe behaviors such as ICMP redirect acceptance and reduces kernel information exposure.

It intentionally does not globally disable IP forwarding because SentinelGate may be used in a gateway/firewall deployment.

### Runtime directories

`systemd-tmpfiles` provides restricted SentinelGate state, logging, and runtime directories.

## BitBake Validation

The custom `meta-sentinelgate` layer has been added successfully to a Scarthgap-based Yocto environment.

Metadata parsing completed successfully:

```text
2803 recipes parsed
4946 targets
0 errors
```

BitBake resolves the application metadata as:

```text
PN="sentinelgate"
PV="1.1.0"
```

The runtime dependency metadata includes:

- `python3-core`
- `python3-fastapi`
- `python3-pydantic`
- `python3-uvicorn`
- `nftables`

## Build Status

The complete `bitbake sentinelgate` package build and full image build are intentionally deferred to a later integration milestone.

Therefore, the current v1.1 claim is:

> SentinelGate includes a custom Yocto layer and v1.1 BitBake application recipe whose metadata has been successfully parsed and resolved.

It does not yet claim completion of a full Yocto image build.

## Future Validation

The later BitBake milestone should include:

```bash
source oe-init-build-env
bitbake-layers show-layers
bitbake -e sentinelgate
bitbake sentinelgate
bitbake sentinelgate-security-image
```

After booting a generated image, validation should include:

```bash
systemctl status sentinelgate.service
systemctl cat sentinelgate.service
systemd-analyze security sentinelgate.service
sentinelgate status
```

## Scope

Yocto is a deployment and integration path for SentinelGate.

The core security platform remains focused on general Linux, network, and SOC defensive-security functionality.
