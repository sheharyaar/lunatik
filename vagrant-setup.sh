#!/bin/bash

set -e

echo "Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1

echo "Adding iptables FORWARD rules..."
sudo iptables -A FORWARD -i virbr1 -o wlan0 -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o virbr1 -m state --state ESTABLISHED,RELATED -j ACCEPT

echo "Adding NAT rule..."
sudo iptables -t nat -A POSTROUTING -s 192.168.121.0/24 -o wlan0 -j MASQUERADE

echo "Network routing rules setup completed successfully"
