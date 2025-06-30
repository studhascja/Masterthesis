FILESEXTRAPATHS:prepend := "${THISDIR}/file:"

SRC_URI += " \
    file://patch-6.12.8-rt7.patch \
    file://config-preempt-rt.cfg \
    file://config-enable-bpf-btf.cfg \
"
