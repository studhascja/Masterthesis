FILESEXTRAPATHS:append := "${THISDIR}/files:"

SRC_URI += " \
    file://dnsmasq.conf \
"

do_install:append () {
    install -m 0644 ${WORKDIR}/sources-unpack/dnsmasq.conf ${D}${sysconfdir}/dnsmasq.conf
}

FILES:${PN} += " \
    ${sysconfdir}/dnsmasq.conf \
"
