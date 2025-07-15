FILESEXTRAPATHS:append := "${THISDIR}/files:"

SRC_URI += " \
	file://dhcpcd.conf \
"

do_install:append() {
    install -m 0644 ${WORKDIR}/sources-unpack/dhcpcd.conf ${D}${sysconfdir}/dhcpcd.conf
}

FILES:${PN} += " \
    ${sysconfdir}/dhcpcd.conf \
"




