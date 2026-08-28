import re
from pathlib import Path


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def layer_root() -> Path:
    return project_root() / "yocto" / "meta-sentinelgate"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_layer_has_expected_v11_structure():
    layer = layer_root()

    expected = [
        layer / "conf" / "layer.conf",
        layer
        / "recipes-security"
        / "sentinelgate"
        / "sentinelgate_1.1.0.bb",
        layer
        / "recipes-security"
        / "sentinelgate-hardening"
        / "sentinelgate-hardening_1.0.0.bb",
        layer
        / "recipes-core"
        / "images"
        / "sentinelgate-security-image.bb",
    ]

    for path in expected:
        assert path.is_file(), f"missing Yocto metadata: {path}"


def test_v11_application_recipe_contains_runtime_integration():
    recipe = read(
        layer_root()
        / "recipes-security"
        / "sentinelgate"
        / "sentinelgate_1.1.0.bb"
    )

    assert "python_setuptools_build_meta" in recipe
    assert "systemd" in recipe
    assert "sentinelgate.service" in recipe
    assert "sentinelgate.toml" in recipe
    assert "python3-fastapi" in recipe
    assert "python3-pydantic" in recipe
    assert "python3-uvicorn" in recipe
    assert "nftables" in recipe


def test_v11_packaged_config_is_safe_by_default():
    config = read(
        layer_root()
        / "recipes-security"
        / "sentinelgate"
        / "files"
        / "sentinelgate.toml"
    )

    assert 'mode = "dry-run"' in config
    assert "[c2_guard]" in config
    assert "enabled = true" in config
    assert "minimum_confidence" in config
    assert "trusted_destinations" in config
    assert "threat_intelligence_ips" in config


def test_hardening_recipe_requires_systemd_and_installs_controls():
    recipe = read(
        layer_root()
        / "recipes-security"
        / "sentinelgate-hardening"
        / "sentinelgate-hardening_1.0.0.bb"
    )

    assert 'REQUIRED_DISTRO_FEATURES = "systemd"' in recipe
    assert "10-hardening.conf" in recipe
    assert "90-sentinelgate-hardening.conf" in recipe
    assert "sentinelgate-tmpfiles.conf" in recipe
    assert "do_install()" in recipe


def test_systemd_policy_keeps_required_firewall_access_but_sandboxes_service():
    policy = read(
        layer_root()
        / "recipes-security"
        / "sentinelgate-hardening"
        / "files"
        / "10-hardening.conf"
    )

    for setting in [
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectControlGroups=yes",
    ]:
        assert setting in policy

    assert "CAP_NET_ADMIN" in policy
    assert "AF_NETLINK" in policy


def test_sysctl_policy_does_not_break_gateway_forwarding():
    sysctl = read(
        layer_root()
        / "recipes-security"
        / "sentinelgate-hardening"
        / "files"
        / "90-sentinelgate-hardening.conf"
    )

    assert "kernel.dmesg_restrict = 1" in sysctl
    assert "net.ipv4.conf.all.accept_redirects = 0" in sysctl

    active_lines = [
        line.strip()
        for line in sysctl.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    assert not any(
        re.match(r"net.ipv[46].conf..*.forwarding\s*=", line)
        for line in active_lines
    )
    assert not any(
        line.startswith("net.ipv4.ip_forward")
        for line in active_lines
    )


def test_custom_image_contains_application_and_hardening():
    image = read(
        layer_root()
        / "recipes-core"
        / "images"
        / "sentinelgate-security-image.bb"
    )

    assert "core-image-minimal.bb" in image
    assert 'IMAGE_INSTALL:append = " sentinelgate sentinelgate-hardening"' in image
