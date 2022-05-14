#!/bin/bash

echo 'Enable SSH'
sudo systemctl start ssh
sudo systemctl enable ssh

echo 'Installing WAP package'
sudo apt install hostapd -y
sudo systemctl unmask hostapd
sudo systemctl enable hostapd
# sudo apt install dnsmasq -y
# sudo systemctl enable dnsmasq
sudo DEBIAN_FRONTEND=noninteractive apt install -y netfilter-persistent iptables-persistent
sudo apt install dhcpcd5 -y

echo 'Ensuring WiFi radio is not blocked on Raspi'
sudo rfkill unblock wlan

echo 'Assign static IP address to Raspberry Pi and prevent dhcpcd from configuring wlan0'
echo \ '
denyinterfaces wlan0

interface enxb827eb8879e7
static ip_address=192.168.1.100/24
static routers=192.168.1.1
static domain_name_servers=192.168.1.1

noipv6rs
noipv6
' | sudo tee -a /etc/dhcpcd.conf

echo \ '
allow-hotplug wlan0
iface wlan0 inet static
    address 10.10.10.1
    netmask 255.255.255.240
    network 10.10.10.0
    broadcast 10.10.10.15
    dns-nameservers 8.8.8.8
' | sudo tee -a /etc/network/interfaces

echo 'country_code=ID
interface=wlan0
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
ssid=raspi
wpa_passphrase=raspi12345
' | sudo tee -a /etc/hostapd/hostapd.conf

echo "DAEMON_CONF='/etc/hostapd/hostapd.conf'" | sudo tee -a /etc/default/hostapd

# sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig
# echo 'interface=wlan0
# listen-address=10.10.10.1
# bind-interfaces
# server=8.8.8.8
# bogus-priv
# dhcp-range=10.10.10.2,10.10.10.14,255.255.240.0,24h
# ' | sudo tee -a /etc/dnsmasq.conf

echo 'Enable IPv4 routing'
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

echo "Disable ipv6"
echo \ '
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
' | sudo tee -a /etc/sysctl.conf

echo "Restarting networking..."
sudo systemctl restart networking
sudo systemctl restart dhcpcd
sudo systemctl restart systemd-sysctl.service
# sudo systemctl restart dnsmasq

# to allow this new network to access internet
sudo iptables -F
sudo iptables -t nat -A POSTROUTING -o enxb827eb8879e7 -j MASQUERADE
sudo iptables -A FORWARD -i enxb827eb8879e7 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o enxb827eb8879e7 -j ACCEPT
sudo sh -c "iptables-save > /etc/iptables.ipv4.nat"
sudo netfilter-persistent save

#echo 'MaxAuthTries 1' | sudo tee -a /etc/ssh/sshd_config
# enxb827eb8879e7

echo 'Setup WPA is done'
echo 'Continue to next step. Please reboot first.'