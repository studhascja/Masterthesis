do_install:append() {
    bbwarn ">>> Mein .bbappend wurde ausgeführt!"
    install -d ${D}${sysconfdir}/profile.d
    echo 'export WIFI_PASSWORD="${WIFI_PWD}"' > ${D}${sysconfdir}/profile.d/myenv.sh
    chmod 0755 ${D}${sysconfdir}/profile.d/myenv.sh
}


