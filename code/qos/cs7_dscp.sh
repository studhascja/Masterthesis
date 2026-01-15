#!/bin/bash

# ----------------------------------------
# Interface and traffic configuration
# ----------------------------------------

# Network interface to apply QoS rules to
IFACE="wlan1"

# Real-time port
RT_PORT="8080"

# Non-real-time port definition
Non_RT_PORT="5202"

# Source and destination IPs 
SRC_IP="192.168.1.1"
DST_IP="192.168.1.43"

echo "[+] Applying tc configuration to interface $IFACE..."

# ----------------------------------------
# Traffic Control (tc) setup
# ----------------------------------------

# Remove any existing qdisc configuration on the interface
tc qdisc del dev $IFACE root 2>/dev/null

# Add root HTB queue discipline with default class 30
tc qdisc add dev $IFACE root handle 1: htb default 30

# Root class with total available bandwidth (upper limit open)
tc class add dev $IFACE parent 1: classid 1:1 htb rate 500mbit

# High-priority class for real-time traffic (TCP/UDP port 8080)
tc class add dev $IFACE parent 1:1 classid 1:10 htb rate 470mbit ceil 500mbit prio 0

# Low-priority class for all remaining traffic
# (both TCP and UDP that is NOT on port 8080)
tc class add dev $IFACE parent 1:1 classid 1:30 htb rate 30mbit ceil 30mbit prio 5

# ----------------------------------------
# iptables packet marking
# ----------------------------------------

echo "[+] Setting iptables marks..."

# Flush all existing rules in the mangle table
iptables -t mangle -F

# ----------------------------------------
# Mark real-time (RT) traffic with mark = 1
# Applies to both incoming (PREROUTING)
# and outgoing (OUTPUT) traffic
# ----------------------------------------

# Incoming RT traffic
iptables -t mangle -A PREROUTING -i $IFACE -p tcp --dport $RT_PORT -j MARK --set-mark 1
iptables -t mangle -A PREROUTING -i $IFACE -p tcp --sport $RT_PORT -j MARK --set-mark 1
iptables -t mangle -A PREROUTING -i $IFACE -p udp --dport $RT_PORT -j MARK --set-mark 1
iptables -t mangle -A PREROUTING -i $IFACE -p udp --sport $RT_PORT -j MARK --set-mark 1

# Outgoing RT traffic
iptables -t mangle -A OUTPUT -o $IFACE -p tcp --dport $RT_PORT -j MARK --set-mark 1
iptables -t mangle -A OUTPUT -o $IFACE -p tcp --sport $RT_PORT -j MARK --set-mark 1
iptables -t mangle -A OUTPUT -o $IFACE -p udp --dport $RT_PORT -j MARK --set-mark 1
iptables -t mangle -A OUTPUT -o $IFACE -p udp --sport $RT_PORT -j MARK --set-mark 1

# ----------------------------------------
# Mark all unclassified traffic with mark = 3
# This applies to any packet still marked as 0
# ----------------------------------------

iptables -t mangle -A PREROUTING -i $IFACE -m mark --mark 0 -j MARK --set-mark 3
iptables -t mangle -A OUTPUT     -o $IFACE -m mark --mark 0 -j MARK --set-mark 3

# ----------------------------------------
# Set Type of Service (ToS) / DSCP value
# 0xE0 = CS7 (Router Communication)
# Used to hint QoS priority on the network
# ----------------------------------------

iptables -t mangle -A POSTROUTING -o $IFACE -j DSCP --set-dscp-class CS7
iptables -t mangle -A POSTROUTING -o $IFACE -j DSCP --set-dscp-class CS7
iptables -t mangle -A POSTROUTING -o $IFACE -j DSCP --set-dscp-class CS7
iptables -t mangle -A POSTROUTING -o $IFACE -j DSCP --set-dscp-class CS7

# ----------------------------------------
# tc filters: link packet marks to classes
# ----------------------------------------

# Mark 1 → high-priority class (1:10)
tc filter add dev $IFACE parent 1: protocol ip handle 1 fw flowid 1:10

# Mark 3 → low-priority class (1:30)
tc filter add dev $IFACE parent 1: protocol ip handle 3 fw flowid 1:30

echo "[+] QoS rules applied:"
echo "    - High priority: TCP/UDP traffic on port 8080"
echo "    - Low priority: All other traffic (longer queueing delay)"

# ----------------------------------------
# Optional: show traffic control statistics
# ----------------------------------------
tc -s qdisc show dev $IFACE
