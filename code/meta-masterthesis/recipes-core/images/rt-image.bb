SUMMARY = "RT-Linux für Raspberry Pi 5"
LICENSE = "MIT"
#IMAGE_INSTALL = ""

# Debug-Login + SSH
EXTRA_IMAGE_FEATURES ?= "debug-tweaks ssh-server-dropbear"

inherit core-image

#IMAGE_INSTALL:append = " linux-firmware raspberrypi-overlays"

# Zusätzliche Pakete
IMAGE_INSTALL += " \
  packagegroup-core-boot \
  kernel-modules \
  dropbear \
  tzdata \
  hostapd \
  dnsmasq \
  iperf3 \
  python3 \
  python3-pip \
  net-tools \
  iproute2 \
  pcie-overlays \
  nano \
  wpa-supplicant \
  iw \
  linux-firmware \
  networkmanager \
  pahole \
  rust-server \
  libbpf \
  clang \
  cargo \
  rust \
  libbpf-dev \
  elfutils \
  gcc \
  binutils \
  make \
  pkgconfig \
  libc-dev \
  packagegroup-core-buildessential \
  systemd \
  systemd-serialgetty \
  perf \
  rust-client \
  setup \
"

DISTRO_FEATURES:append = " wifi systemd"
VIRTUAL-RUNTIME_init_manager = "systemd"
VIRTUAL-RUNTIME_network_manager = "networkmanager"


