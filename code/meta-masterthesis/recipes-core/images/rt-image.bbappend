IMAGE_INSTALL:append = " chrony"

SYSTEMD_AUTO_ENABLE:chrony = " enable"
SYSTEMD_SERVICE:chrony = " chronyd.service"

