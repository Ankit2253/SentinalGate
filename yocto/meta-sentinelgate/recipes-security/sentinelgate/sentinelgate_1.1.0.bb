SUMMARY = "SentinelGate Linux firewall and threat-monitoring platform"
DESCRIPTION = "Installs SentinelGate v1.1 with C2 Guard, threat-intelligence enrichment, allowlists, API/dashboard visibility, and analyst-controlled response."
HOMEPAGE = "https://github.com/Ankit2253/SentinalGate"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = " \
    file://pyproject.toml \
    file://README.md \
    file://src \
    file://sentinelgate.service \
    file://sentinelgate.toml \
"

S = "${WORKDIR}"

inherit python_setuptools_build_meta systemd useradd

REQUIRED_DISTRO_FEATURES = "systemd"

SYSTEMD_SERVICE:${PN} = "sentinelgate.service"
SYSTEMD_AUTO_ENABLE:${PN} = "enable"

USERADD_PACKAGES = "${PN}"
USERADD_PARAM:${PN} = "--system --home /var/lib/sentinelgate --no-create-home --shell /sbin/nologin sentinelgate"

RDEPENDS:${PN} += " \
    python3-core \
    python3-fastapi \
    python3-pydantic \
    python3-uvicorn \
    nftables \
"

do_install:append() {
    install -d ${D}${sysconfdir}/sentinelgate
    install -m 0644 ${WORKDIR}/sentinelgate.toml \
        ${D}${sysconfdir}/sentinelgate/sentinelgate.toml

    install -d ${D}${systemd_system_unitdir}
    install -m 0644 ${WORKDIR}/sentinelgate.service \
        ${D}${systemd_system_unitdir}/sentinelgate.service

    install -d ${D}${localstatedir}/lib/sentinelgate
    chown sentinelgate:sentinelgate \
        ${D}${localstatedir}/lib/sentinelgate
}

FILES:${PN} += " \
    ${sysconfdir}/sentinelgate/sentinelgate.toml \
    ${systemd_system_unitdir}/sentinelgate.service \
    ${localstatedir}/lib/sentinelgate \
"
