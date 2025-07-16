do_install:append() {
    bbwarn ">>> Mein .bbappend wurde ausgeführt!"
    install -d ${D}${sysconfdir}/profile.d
    echo 'export WIFI_PASSWORD="${WIFI_PWD}"' > ${D}${sysconfdir}/profile.d/myenv.sh
    echo 'iw reg set DE' >> ${D}${sysconfdir}/profile.d/myenv.sh
    echo 'wpa_passphrase "jh_test" "${WIFI_PWD} > /code/wpa2.conf"' >> ${D}${sysconfdir}/profile.d/myenv.sh
    echo 'mac_addr=0 >> /code/wpa2.conf' >> ${D}${sysconfdir}/profile.d/myenv.sh
    echo 'gas_rand_mac_addr=0 >> /code/wpa2.conf' >> ${D}${sysconfdir}/profile.d/myenv.sh
    echo 'preassoc_mac_addr=0 >> /code/wpa2.conf' >> ${D}${sysconfdir}/profile.d/myenv.sh
    chmod 0755 ${D}${sysconfdir}/profile.d/myenv.sh
}


