#!/bin/bash

# ----------------------------------------
# Interface and traffic configuration
# ----------------------------------------

# Network interface to apply QoS rules to
IFACE="wlan1"

# Real-time application port
RT_PORT="8080"

# Non-real-time port definition
Non_RT_PORT="5202"

# Source and destination IPs 
SRC_IP="192.168.1.1"
DST_IP="192.168.1.43"

echo "[+] Applying tc configuration to interface $IFACE..."

# ----------------------------------------
# Traffic Control (tc) setup using PRIO
# ----------------------------------------

# Remove any existing qdisc configuration
tc qdisc del dev $IFACE root 2>/dev/null

# Add a PRIO qdisc with three priority bands
# Band 1 = highest priority
# Band 3 = lowest priority
tc qdisc add dev $IFACE root handle 1: prio bands 3

# ----------------------------------------
# Optional leaf queue disciplines
# fq_codel helps reduce bufferbloat
# ----------------------------------------

# Attach fq_codel to each priority band
tc qdisc add dev $IFACE parent 1:1 handle 10: fq_codel
tc qdisc add dev $IFACE parent 1:2 handle 20: fq_codel
tc qdisc add dev $IFACE parent 1:3 handle 30: fq_codel

# ----------------------------------------
# iptables packet marking
# ----------------------------------------

# Flush all existing rules in the mangle table
iptables -t mangle -F

# ----------------------------------------
# Mark real-time traffic (port 8080) with mark = 1
# Applies to both incoming and outgoing packets
# ----------------------------------------

# Incoming real-time traffic
iptables -t mangle -A PREROUTING -i $IFACE -p tcp --dport $RT_PORT -j MARK --set-mark 1
iptables -t mangle -A PREROUTING -i $IFACE -p tcp --sport $RT_PORT -j MARK --set-mark 1
iptables -t mangle -A PREROUTING -i $IFACE -p udp --dport $RT_PORT -j MARK --set-mark 1
iptables -t mangle -A PREROUTING -i $IFACE -p udp --sport $RT_PORT -j MARK --set-mark 1

# Outgoing real-time traffic
iptables -t mangle -A OUTPUT -o $IFACE -p tcp --dport $RT_PORT -j MARK --set-mark 1
iptables -t mangle -A OUTPUT -o $IFACE -p tcp --sport $RT_PORT -j MARK --set-mark 1
iptables -t mangle -A OUTPUT -o $IFACE -p udp --dport $RT_PORT -j MARK --set-mark 1
iptables -t mangle -A OUTPUT -o $IFACE -p udp --sport $RT_PORT -j MARK --set-mark 1

# ----------------------------------------
# Mark all remaining traffic with mark = 3
# ----------------------------------------

iptables -t mangle -A PREROUTING -i $IFACE -m mark --mark 0 -j MARK --set-mark 3
iptables -t mangle -A OUTPUT     -o $IFACE -m mark --mark 0 -j MARK --set-mark 3

# ----------------------------------------
# Set Type of Service (ToS) / DSCP to EF (0xB8)
# for real-time traffic
# ----------------------------------------

iptables -t mangle -A POSTROUTING -o $IFACE -p tcp --dport $RT_PORT -j TOS --set-tos 0xB8
iptables -t mangle -A POSTROUTING -o $IFACE -p tcp --sport $RT_PORT -j TOS --set-tos 0xB8
iptables -t mangle -A POSTROUTING -o $IFACE -p udp --dport $RT_PORT -j TOS --set-tos 0xB8
iptables -t mangle -A POSTROUTING -o $IFACE -p udp --sport $RT_PORT -j TOS --set-tos 0xB8

# ----------------------------------------
# tc filters: map traffic to PRIO bands
# ----------------------------------------

# Outgoing traffic: destination port 8080 → highest priority band (band 1)
tc filter add dev $IFACE protocol ip parent 1: prio 1 u32 \
    match ip dport 8080 0xffff flowid 1:1

# Incoming traffic: source port 8080 → highest priority band (band 1)
tc filter add dev $IFACE protocol ip parent 1: prio 1 u32 \
    match ip sport 8080 0xffff flowid 1:1

# Catch-all rule: all remaining traffic → lowest priority band (band 3)
tc filter add dev $IFACE protocol ip parent 1: prio 5 u32 \
    match ip protocol 0 0 flowid 1:3

echo "[+] QoS rules successfully applied"

# ----------------------------------------
# Optional: display tc statistics
# ----------------------------------------
tc -s qdisc show dev $IFACE
