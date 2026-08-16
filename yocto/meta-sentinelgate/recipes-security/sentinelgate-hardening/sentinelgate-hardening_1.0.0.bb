SUMMARY = "Embedded Linux hardening policy for SentinelGate v1.0"
DESCRIPTION = "Installs a systemd hardening drop-in, conservative kernel/network sysctl settings, and restricted runtime directories for SentinelGate."
HOMEPAGE = "https://example.invalid/sentinelgate"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = "file://10-hardening.conf \
           file://90-sentinelgate-hardening.conf \
           file://sentinelgate-tmpfiles.conf"

inherit allarch features_check

REQUIRED_DISTRO_FEATURES = "systemd"

S = "${WORKDIR}"

do_install() {
    # systemd drop-in for the existing SentinelGate service.
    install -d ${D}${sysconfdir}/systemd/system/sentinelgate.service.d
    install -m 0644 ${WORKDIR}/10-hardening.conf \
        ${D}${sysconfdir}/systemd/system/sentinelgate.service.d/10-hardening.conf

    # Kernel/network hardening applied by systemd-sysctl at boot.
    install -d ${D}${nonarch_libdir}/sysctl.d
    install -m 0644 ${WORKDIR}/90-sentinelgate-hardening.conf \
        ${D}${nonarch_libdir}/sysctl.d/90-sentinelgate-hardening.conf

    # Persistent state/log directories with least-privilege permissions.
    install -d ${D}${nonarch_libdir}/tmpfiles.d
    install -m 0644 ${WORKDIR}/sentinelgate-tmpfiles.conf \
        ${D}${nonarch_libdir}/tmpfiles.d/sentinelgate.conf
}

FILES:${PN} += "${sysconfdir}/systemd/system/sentinelgate.service.d/10-hardening.conf \
                ${nonarch_libdir}/sysctl.d/90-sentinelgate-hardening.conf \
                ${nonarch_libdir}/tmpfiles.d/sentinelgate.conf"

RDEPENDS:${PN} += "systemd"
