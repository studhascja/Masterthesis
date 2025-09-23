SUMMARY = "TCP Server in Rust mit libbpf-rs"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://LICENSE;md5=477dfa54ede28e2f361e7db05941d7a7"

SRC_URI = "file://server \
	   file://server/LICENSE \
	   file://server/vendor \
           file://.cargo/config.toml \
	  "

S = "${WORKDIR}/server"

inherit cargo

# Build dependencies (compile-time)
DEPENDS += "llvm bpftool libbpf"

# Runtime dependencies (target)
RDEPENDS:${PN} += "libbpf"

do_install() {
    install -d ${D}${bindir}
    install -m 0755 target/${RUST_TARGET_SYS}/release/server ${D}${bindir}/server
}
