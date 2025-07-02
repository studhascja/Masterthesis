FILESEXTRAPATHS:prepend := "${THISDIR}/file:"

DEPENDS += "pahole-native"

SRC_URI += " \
    file://patch-6.12.8-rt7.patch \
    file://config-preempt-rt.cfg \
    file://config-enable-bpf-btf.cfg \
    file://config-enable-mt7925e.cfg \
"


EXTRA_OEMAKE:append = " PAHOLE=${STAGING_BINDIR_NATIVE}/pahole"
