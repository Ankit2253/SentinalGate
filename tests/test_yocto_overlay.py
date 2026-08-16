from pathlib import Path
import re


def project_root() -> Path:
    # Works both in the standalone integration package and after copying into SentinelGate v1.0.
    return Path(__file__).resolve().parents[1]


def layer_root() -> Path:
    return project_root() / "yocto" / "meta-sentinelgate"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_layer_has_expected_structure():
    layer = layer_root()
    expected = [
        layer / "conf" / "layer.conf",
        layer / "recipes-security" / "sentinelgate-hardening" / "sentinelgate-hardening_1.0.0.bb",
        layer / "recipes-core" / "images" / "sentinelgate-security-image.bb",
    ]
    for path in expected:
        assert path.is_file(), f"missing Yocto metadata: {path}"


def test_recipe_requires_systemd_and_installs_three_controls():
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
    assert "ReadWritePaths=/var/lib/sentinelgate /var/log/sentinelgate /run/sentinelgate" in policy


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
    # The overlay must not force forwarding off; SentinelGate may be used as a gateway.
    active_lines = [
        line.strip()
        for line in sysctl.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert not any(re.match(r"net\.ipv[46]\.conf\..*\.forwarding\s*=", line) for line in active_lines)
    assert not any(line.startswith("net.ipv4.ip_forward") for line in active_lines)


def test_tmpfiles_are_restricted():
    tmpfiles = read(
        layer_root()
        / "recipes-security"
        / "sentinelgate-hardening"
        / "files"
        / "sentinelgate-tmpfiles.conf"
    )
    for path in ["/var/lib/sentinelgate", "/var/log/sentinelgate", "/run/sentinelgate"]:
        assert path in tmpfiles
    assert tmpfiles.count("0750") == 3


def test_custom_image_includes_hardening_package():
    image = read(layer_root() / "recipes-core" / "images" / "sentinelgate-security-image.bb")
    assert "core-image-minimal.bb" in image
    assert 'IMAGE_INSTALL:append = " sentinelgate-hardening"' in image
