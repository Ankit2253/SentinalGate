SUMMARY = "Minimal Linux image with SentinelGate v1.1 and security hardening"
DESCRIPTION = "Extends core-image-minimal with SentinelGate v1.1 and the SentinelGate hardening policy."
LICENSE = "MIT"

require recipes-core/images/core-image-minimal.bb

IMAGE_INSTALL:append = " sentinelgate sentinelgate-hardening"
