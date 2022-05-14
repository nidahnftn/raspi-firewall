#!/bin/bash

echo "Create ipset blacklist"
sudo bash ipset.sh
echo "Create iptables rule"
sudo python3 iptables.py

sudo sh -c "iptables-save > /etc/iptables.ipv4.nat"
sudo netfilter-persistent save