#!/bin/bash

# Interface definieren
IFACE="wlan1"

echo "[+] Setze tc-Konfiguration für Interface $IFACE..."

# Vorherige Konfiguration entfernen
tc qdisc del dev $IFACE root 2>/dev/null

# Root QDisc: HTB
tc qdisc add dev $IFACE root handle 1: htb default 30

# Root-Klasse (Gesamtbandbreite nach oben offen)
tc class add dev $IFACE parent 1: classid 1:1 htb rate 10000mbit

# Hochpriorität: TCP Port 8080
tc class add dev $IFACE parent 1:1 classid 1:10 htb rate 500mbit ceil 1000mbit prio 0

# Niedrigpriorität: Alle anderen Verbindungen (UDP und TCP, die nicht auf 8080 laufen)

tc class add dev $IFACE parent 1:1 classid 1:30 htb rate 500mbit ceil 2500mbit prio 3

# -------------------------------
# iptables Markierungen setzen
# -------------------------------

echo "[+] Setze iptables-Markierungen..."

# Erst alles leeren
iptables -t mangle -F

# TCP Port 8080 → MARK 1 (Server + Client)
iptables -t mangle -A PREROUTING -i $IFACE -p tcp --dport 8080 -j MARK --set-mark 1
iptables -t mangle -A OUTPUT     -o $IFACE -p tcp --sport 8080 -j MARK --set-mark 1

# TOS-Bits für TCP Port 8080 setzen (minimale Verzögerung)
iptables -t mangle -A POSTROUTING -p tcp --dport 8080 -j TOS --set-tos 0xB8
iptables -t mangle -A POSTROUTING -p tcp --sport 8080 -j TOS --set-tos 0xB8

# UDP Verkehr markieren
iptables -t mangle -A PREROUTING -i $IFACE -p udp -j MARK --set-mark 3
iptables -t mangle -A OUTPUT     -o $IFACE -p udp -j MARK --set-mark 3

# -------------------------------
# Filter verbinden MARK → Klassen
# -------------------------------

# TCP 8080 → Klasse 1:10 (hohe Priorität)
tc filter add dev $IFACE parent 1: protocol ip handle 1 fw flowid 1:10

# Alle anderen (einschließlich UDP) → Klasse 1:30 (niedrigste Priorität)
tc filter add dev $IFACE parent 1: protocol ip handle 3 fw flowid 1:30

echo "[+] QoS-Regeln gesetzt. TCP: Prio hoch (Port 8080) | Alle anderen Verbindungen niedrigere Priorität und längere Wartezeit"

# Optional: Statistiken anzeigen
tc -s qdisc show dev $IFACE

