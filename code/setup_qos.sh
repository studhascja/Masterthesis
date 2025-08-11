#!/bin/bash

# Interface definieren
IFACE="wlan1"
RT_PORT="8080"
Non_RT_PORT="5202"
SRC_IP="192.168.1.1"
DST_IP="192.168.1.43"

echo "[+] Setze tc-Konfiguration für Interface $IFACE..."

# Vorherige Konfiguration entfernen
tc qdisc del dev $IFACE root 2>/dev/null

# Root QDisc: HTB
tc qdisc add dev $IFACE root handle 1: htb default 30

# Root-Klasse (Gesamtbandbreite nach oben offen)
tc class add dev $IFACE parent 1: classid 1:1 htb rate 10000mbit

# Hochpriorität: TCP Port 8080
tc class add dev $IFACE parent 1:1 classid 1:10 htb rate 995mbit ceil 1000mbit prio 0

# Niedrigpriorität: Alle anderen Verbindungen (UDP und TCP, die nicht auf 8080 laufen)

tc class add dev $IFACE parent 1:1 classid 1:30 htb rate 5mbit ceil 2500mbit prio 5

# -------------------------------
# iptables Markierungen setzen
# -------------------------------

echo "[+] Setze iptables-Markierungen..."

# Erst alles leeren
iptables -t mangle -F

# TCP Port 8080 → MARK 1 (Server + Client)
iptables -t mangle -A PREROUTING -i $IFACE -p tcp --dport $RT_PORT -j MARK --set-mark 1
iptables -t mangle -A PREROUTING -i $IFACE -p udp --dport $RT_PORT -j MARK --set-mark 1
iptables -t mangle -A OUTPUT     -o $IFACE -p tcp --sport $RT_PORT -j MARK --set-mark 1
iptables -t mangle -A OUTPUT     -o $IFACE -p udp --sport $RT_PORT -j MARK --set-mark 1
# Alles standardmäßig auf Mark 3 setzen
iptables -t mangle -A PREROUTING -i $IFACE -j MARK --set-mark 3
iptables -t mangle -A OUTPUT     -o $IFACE -j MARK --set-mark 3

# Dann den RT-Verkehr überschreiben
iptables -t mangle -A PREROUTING -i $IFACE -p tcp --dport $RT_PORT  -j MARK --set-mark 1
iptables -t mangle -A PREROUTING -i $IFACE -p tcp --sport $RT_PORT  -j MARK --set-mark 1
iptables -t mangle -A PREROUTING -i $IFACE -p udp --dport $RT_PORT  -j MARK --set-mark 1
iptables -t mangle -A PREROUTING -i $IFACE -p udp --sport $RT_PORT  -j MARK --set-mark 1

iptables -t mangle -A OUTPUT -o $IFACE -p tcp --dport $RT_PORT  -j MARK --set-mark 1
iptables -t mangle -A OUTPUT -o $IFACE -p tcp --sport $RT_PORT  -j MARK --set-mark 1
iptables -t mangle -A OUTPUT -o $IFACE -p udp --dport $RT_PORT  -j MARK --set-mark 1
iptables -t mangle -A OUTPUT -o $IFACE -p udp --sport $RT_PORT  -j MARK --set-mark 1

iptables -t mangle -A POSTROUTING --dport 8080 -j TOS --set-tos 0xB8
iptables -t mangle -A POSTROUTING --sport 8080 -j TOS --set-tos 0xB8
# -------------------------------
# Filter verbinden MARK → Klassen
# -------------------------------

# TCP 8080 → Klasse 1:10 (hohe Priorität)
#tc filter add dev $IFACE parent 1: protocol ip handle 1 fw flowid 1:10

# Alle anderen (einschließlich UDP) → Klasse 1:30 (niedrigste Priorität)
#tc filter add dev $IFACE parent 1: protocol ip handle 3 fw flowid 1:30

echo "[+] QoS-Regeln gesetzt. TCP: Prio hoch (Port 8080) | Alle anderen Verbindungen niedrigere Priorität und längere Wartezeit"

# Optional: Statistiken anzeigen
tc -s qdisc show dev $IFACE

