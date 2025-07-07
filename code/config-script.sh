#!/bin/bash

FILENAME="${1:-hostapd.conf}"
CONFIG_FILE="/etc/dnsmasq.conf"
INTERFACE="wlan1"
DHCP_RANGE="dhcp-range=192.168.1.10,192.168.1.100,12h"

# Configure DHCP-Server
grep -q "^interface=$INTERFACE" "$CONFIG_FILE" || echo "interface=$INTERFACE" | sudo tee -a "$CONFIG_FILE"
grep -q "^$DHCP_RANGE" "$CONFIG_FILE" || echo "$DHCP_RANGE" | sudo tee -a "$CONFIG_FILE"
echo "Configured DHCP-server"

# Configure network interface
ifconfig "$INTERFACE" 192.168.1.1 netmask 255.255.255.0 up
echo "Configure Interface"

# Stop systemd-resolved (if active), to clear port 53
if systemctl is-active --quiet systemd-resolved; then
    systemctl stop systemd-resolved
    echo "Stopped systemd-resolved."
fi

# start Dnsmasq 
systemctl restart dnsmasq
echo "started Dnsmasq."

# start Hostapd
sudo hostapd -dd /etc/hostapd/${FILENAME}

