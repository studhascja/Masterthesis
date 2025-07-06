SRC_URI += "git://github.com/studhascja/Masterthesis.git;protocol=https;nobranch=1;branch=main"
SRCREV = "${AUTOREV}"
S = "${WORKDIR}/git/code"

RDEPENDS:${PN} += "bash"

do_install() {
    install -d ${D}/code
    cp ${S}/clean-script.sh ${D}/code/
    cp ${S}/client_test_suite.py ${D}/code/
    cp ${S}/config-script.sh ${D}/code/
    cp ${S}/server_test_suite.py ${D}/code/
    cp ${S}/setup_qos.sh ${D}/code/
    cp ${S}/test_configurations.save ${D}/code/
}

FILES:${PN} += "/code \
                /code/* \
"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${THISDIR}/files/LICENSE;md5=477dfa54ede28e2f361e7db05941d7a7"
