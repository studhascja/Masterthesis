FILESEXTRAPATHS:append := "${THISDIR}/files:"

SRC_URI += " \
    file://wifi4 \
    file://wifi4_20 \
    file://wifi4_40 \
    file://wifi5_20 \
    file://wifi5_40 \
    file://wifi5_80 \
    file://wifi6 \
    file://wifi6_5_20 \
    file://wifi6_5_40 \
    file://wifi6_5_80 \
    file://wifi6_6_20 \
    file://wifi6_6_40 \
    file://wifi6_6_80 \
    file://wifi6_6_160 \
"

do_install:append () {
readonly WIFI_PWD_PLACEHOLDER="WIFI_PWD"
readonly WIFI_PWD="${@d.getVar('WIFI_PWD')}"
install -d ${D}${sysconfdir}/hostapd

for cfg in \
    wifi4 wifi4_20 wifi4_40 \
    wifi5_20 wifi5_40 wifi5_80 \
    wifi6 \
    wifi6_5_20 wifi6_5_40 wifi6_5_80 \
    wifi6_6_20 wifi6_6_40 wifi6_6_80 wifi6_6_160; do

    install -m 0644 ${WORKDIR}/sources-unpack/$cfg ${D}${sysconfdir}/hostapd/$cfg
    sed -i 's/${WIFI_PWD_PLACEHOLDER}/${WIFI_PWD}/' ${D}${sysconfdir}/hostapd/$cfg
done
}

FILES:${PN} += " \
    ${sysconfdir}/hostapd/wifi4 \
    ${sysconfdir}/hostapd/wifi4_20 \
    ${sysconfdir}/hostapd/wifi4_40 \
    ${sysconfdir}/hostapd/wifi5_20 \
    ${sysconfdir}/hostapd/wifi5_40 \
    ${sysconfdir}/hostapd/wifi5_80 \
    ${sysconfdir}/hostapd/wifi6 \
    ${sysconfdir}/hostapd/wifi6_5_20 \
    ${sysconfdir}/hostapd/wifi6_5_40 \
    ${sysconfdir}/hostapd/wifi6_5_80 \
    ${sysconfdir}/hostapd/wifi6_6_20 \
    ${sysconfdir}/hostapd/wifi6_6_40 \
    ${sysconfdir}/hostapd/wifi6_6_80 \
    ${sysconfdir}/hostapd/wifi6_6_160 \
"
