#!/bin/bash

echo 'Enable SSH'
sudo systemctl start ssh
sudo systemctl enable ssh

echo 'Installing WAP package'
sudo apt install hostapd -y
sudo systemctl unmask hostapd
sudo systemctl enable hostapd
sudo apt install dnsmasq -y
sudo DEBIAN_FRONTEND=noninteractive apt install -y netfilter-persistent iptables-persistent
sudo apt install dhcpcd5 -y

echo 'Ensuring WiFi radio is not blocked on Raspi'
sudo rfkill unblock wlan

echo 'denyinterfaces wlan0' | sudo tee -a /etc/dhcpcd.conf

echo \ '
allow-hotplug wlan0
iface wlan0 inet static
    address 10.10.10.1
    netmask 255.255.255.240
    network 10.10.10.0
    broadcast 10.10.10.15
    dns-nameservers 8.8.8.8
' | sudo tee -a /etc/network/interfaces

echo \ 
'country_code=ID
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
wpa_passphrase=thisispassword123
' | sudo tee -a /etc/hostapd/hostapd.conf

echo "DAEMON_CONF='/etc/hostapd/hostapd.conf'" | sudo tee -a /etc/default/hostapd

sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig
echo \ '
interface=wlan0
listen-address=10.10.10.1
bind-interfaces
server=8.8.8.8
bogus-priv
dhcp-range=10.10.10.2,10.10.10.14,255.255.240.0,24h
' | sudo tee -a /etc/dnsmasq.conf

echo 'Enable IPv4 routing'
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

# to allow this new network to access internet
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
sudo sh -c "iptables-save > /etc/iptables.ipv4.nat"
sudo netfilter-persistent save

echo 'Setup WPA is done'
echo 'Continue to next step'

echo 'Installing python-iptables'
sudo apt install python3-pip -y
pip install --upgrade python-iptables

# next: https://github.com/ldx/python-iptables#:~:text=Introduction-,About%20python%2Diptables,rules%20in%20the%20Linux%20kernel.
