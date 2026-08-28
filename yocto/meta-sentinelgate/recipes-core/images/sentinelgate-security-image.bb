SUMMARY = "Minimal embedded Linux image with SentinelGate security hardening"
DESCRIPTION = "Extends core-image-minimal with the SentinelGate v1.0 hardening policy."
LICENSE = "MIT"

require recipes-core/images/core-image-minimal.bb

IMAGE_INSTALL:append = " sentinelgate-hardening"
