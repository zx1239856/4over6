#!/bin/bash

NET_TUN=$(route | grep '^default' | grep -o '[^ ]*$')
echo "Using default interface: ${NET_TUN}"
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -A FORWARD -i tun0 -o "${NET_TUN}" -j ACCEPT
sudo iptables -A FORWARD -i "${NET_TUN}" -o tun0 -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -t nat -A POSTROUTING -o "${NET_TUN}" -j MASQUERADE
