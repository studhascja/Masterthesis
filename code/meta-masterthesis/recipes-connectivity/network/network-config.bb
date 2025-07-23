SUMMARY = "Custom network interfaces config"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${THISDIR}/files/LICENSE;md5=477dfa54ede28e2f361e7db05941d7a7"

SRC_URI += "file://interface" 

do_install() {
    install -d ${D}${sysconfdir}/network
    install -m 0644 ${WORKDIR}/interface ${D}${sysconfdir}/network/interfaces
}

FILES:${PN} += "${sysconfdir}/network/interfaces"

