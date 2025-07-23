FILESEXTRAPATHS:append := "${THISDIR}/files:"

SRC_URI += " \
    file://defconfig \
"
SRC_URI += "git://github.com/studhascja/Masterthesis.git;protocol=https;nobranch=1;branch=main"
SRCREV = "${AUTOREV}"
K = "${WORKDIR}/git/code/hostapd"
HOMEPAGE = "https://github.com/studhascja/Masterthesis.git"

do_configure:prepend() {
    cp ${WORKDIR}/sources-unpack/defconfig ${S}/.config
}

do_install:append () {
readonly WIFI_PWD_PLACEHOLDER="WIFI_PWD"

install -d ${D}${sysconfdir}/hostapd
cp -r ${K} ${D}${sysconfdir}

for cfg in \
    wifi4 wifi4_20 wifi4_40 \
    wifi5_20 wifi5_40 wifi5_80 \
    wifi6 \
    wifi6_5_20 wifi6_5_40 wifi6_5_80 \
    wifi6_6_20 wifi6_6_40 wifi6_6_80 wifi6_6_160; do

    sed -i 's/WIFI_PWD/${WIFI_PWD}/' ${D}${sysconfdir}/hostapd/$cfg
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
