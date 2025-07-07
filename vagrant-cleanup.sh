#!/bin/bash

echo "Disabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=0

echo "Removing iptables rules..."
sudo iptables -D FORWARD -i virbr1 -o wlan0 -j ACCEPT
sudo iptables -D FORWARD -i wlan0 -o virbr1 -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -t nat -D POSTROUTING -s 192.168.121.0/24 -o wlan0 -j MASQUERADE
echo "Network routing rules cleanup completed"
