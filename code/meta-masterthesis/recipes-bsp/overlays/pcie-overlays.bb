SUMMARY = "Custom Device Tree Overlays"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://LICENSE;md5=477dfa54ede28e2f361e7db05941d7a7"

SRC_URI += "file://pcie-32bit-dma-pi5.dtbo \
            file://LICENSE \
"
S = "${WORKDIR}/sources"
UNPACKDIR = "${S}"

do_install() {
    install -d ${D}/boot/overlays
    install -m 0644 ${UNPACKDIR}/pcie-32bit-dma-pi5.dtbo ${D}/boot/overlays/
}

FILES:${PN} += "/boot/overlays/pcie-32bit-dma-pi5.dtbo"
