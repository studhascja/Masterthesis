#!/bin/bash

CONFIG_FILE="/etc/dnsmasq.conf"
INTERFACE="wlp1s0"
DHCP_RANGE="dhcp-range=192.168.1.10,192.168.1.100,12h"

# Configure DHCP server
grep -q "^interface=$INTERFACE" "$CONFIG_FILE" || echo "interface=$INTERFACE" | sudo tee -a "$CONFIG_FILE"
grep -q "^$DHCP_RANGE" "$CONFIG_FILE" || echo "$DHCP_RANGE" | sudo tee -a "$CONFIG_FILE"

# Configure network-interface
sudo ifconfig "$INTERFACE" 192.168.1.1 netmask 255.255.255.0 up

# Check if sestemd-resolve is running and stop it, if so
if systemctl is-active --quiet systemd-resolved; then
    sudo systemctl stop systemd-resolved
fi

# start Dnsmasq
sudo systemctl restart dnsmasq

# start Hostapd 
sudo hostapd /etc/hostapd/hostapd.conf
