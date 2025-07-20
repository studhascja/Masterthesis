#!/bin/bash

FILENAME="${1:-hostapd.conf}"
CONFIG_FILE="/etc/dnsmasq.conf"
INTERFACE="wlan1"
DHCP_RANGE="dhcp-range=192.168.1.1,192.168.1.99,12h"
DHCP_HOST="dhcp-host=76:35:72:d4:9d:1b,192.168.1.43"

# Configure DHCP-Server
#grep -q "^interface=$INTERFACE" "$CONFIG_FILE" || echo "interface=$INTERFACE" | tee -a "$CONFIG_FILE"
#grep -q "^$DHCP_RANGE" "$CONFIG_FILE" || echo "$DHCP_RANGE" | tee -a "$CONFIG_FILE"
#grep -q "^$DHCP_HOST" "$CONFIG_FILE" || echo "$DHCP_HOST" | tee -a "$CONFIG_FILE"

#echo "Configured DHCP-server"

# Configure network interface
#ifconfig "$INTERFACE" 192.168.1.1 netmask 255.255.255.0 up
#echo "Configure Interface"
ip addr flush dev wlan1
ip addr add 192.168.1.1/24 dev wlan1
ip link set wlan1 up

# Stop systemd-resolved (if active), to clear port 53
if systemctl is-active --quiet systemd-resolved; then
    systemctl stop systemd-resolved
    echo "Stopped systemd-resolved."
fi

# start Dnsmasq 
#systemctl restart dnsmasq
echo "started Dnsmasq."

# start Hostapd
hostapd -dd /etc/hostapd/${FILENAME}

