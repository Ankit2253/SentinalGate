# meta-sentinelgate

`meta-sentinelgate` is the Yocto/OpenEmbedded security-hardening layer shipped with the full
SentinelGate v1.0 source project. It demonstrates image-build-time hardening for an embedded Linux
deployment while leaving the SentinelGate Python firewall engine and rule model unchanged.

## What it demonstrates

- Custom Yocto layer structure
- A BitBake recipe (`.bb`)
- Installing security configuration into an embedded Linux image
- systemd service sandboxing
- sysctl hardening
- systemd-tmpfiles runtime directory permissions
- A minimal custom image recipe

## Add the layer

From an initialized Yocto build environment:

```bash
bitbake-layers add-layer /path/to/SentinelGate/yocto/meta-sentinelgate
bitbake-layers show-layers
```

Make sure systemd is enabled by your distro configuration. Then either add the package to an existing image:

```conf
IMAGE_INSTALL:append = " sentinelgate-hardening"
```

or build the included demonstration image:

```bash
bitbake sentinelgate-security-image
```

## Validation

From the SentinelGate repository root, run the metadata tests without requiring BitBake:

```bash
python -m pytest tests/test_yocto_overlay.py -q
```

A complete image build requires a separate Yocto build environment. See
`docs/YOCTO_INTEGRATION.md` for the build and post-boot verification steps.

## Important scope

This layer hardens a SentinelGate deployment; it does not package or replace the SentinelGate v1.0
Python application by itself and does not silently change its firewall rules. The systemd drop-in
assumes the deployed service is named `sentinelgate.service`.
