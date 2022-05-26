#!/bin/bash

tables=("filter" "mangle" "raw")
chains=("PREROUTING" "POSTROUTING" "INPUT" "OUTPUT" "FORWARD")
filter_chains=("SSHATTACK" "UNRECOGDVC" "PINGATTACK")
raw_chains=("SYNFLOOD")
whitelist=( "192.168.1.1/32" "192.168.1.100/32" "192.168.1.15/32" "192.168.1.16/32" "10.10.10.1/32"
             "10.10.10.7/32" "10.10.10.11/32" "10.10.10.13/32" "127.0.0.1/32" "127.0.1.1/32" "8.8.8.8")
allowed_ping=("192.168.1.100/32" "10.10.10.1/32")
allowed_ssh=("192.168.1.15/32" "10.10.10.7/32")

echo "Flush all chains..."
for table in ${tables[@]}; do
    for chain in ${chains[@]}; do
        iptables -t $table -F $chain
        echo "Successfully flushed chain " $table:$chain
    done
done
for filter_chain in ${filter_chains[@]}; do
    iptables -F $filter_chain
    echo "Successfully flushed chain filter:" $filter_chain
done
for raw_chain in ${raw_chains[@]}; do
    iptables -t raw -F $raw_chain
    echo "Successfully flushed chain raw:" $raw_chain
done

echo "Flush ipset..."
ipset flush

echo "Add new chains..."
echo "Add chains in filter table..."
for filter_chain in ${filter_chains[@]}; do
    iptables -N $filter_chain
    echo "Successfully added chain filter:" $filter_chain
done
echo "Add chains in raw table..."
for raw_chain in ${raw_chains[@]}; do
    iptables -t raw -N $raw_chain
    echo "Successfully added chain raw:" $raw_chain
done

echo "Add forward rules..."
sudo iptables -A FORWARD -i enxb827eb8879e7 -o wlan0 -s 192.168.1.100/32 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o enxb827eb8879e7 -d 192.168.1.100/32 -j ACCEPT

echo "Add rules to block undesired connection attempt..."
iptables -A UNRECOGDVC -m limit --limit 1/h --limit-burst 5 -j LOG --log-prefix "Connection attempt is detected!" --log-level 7
iptables -A UNRECOGDVC -j DROP
ipset -N WHITELIST iphash
for addr in ${whitelist[@]}; do
    ipset -A WHITELIST $addr
    echo "Successfully added IP address" $addr "to WHITELIST set"
done
iptables -A INPUT -m set ! --match-set WHITELIST src -j UNRECOGDVC

echo "Add ssh rules..."
iptables -A SSHATTACK -j LOG --log-prefix "Possible SSH attack!" --log-level 7
iptables -A SSHATTACK -j DROP
ipset -N ALLOWED_SSH iphash
for addr in ${allowed_ssh[@]}; do
    ipset -A ALLOWED_SSH $addr
    echo "Successfully added IP address" $addr "to ALLOWED_SSH set"
done
iptables -A INPUT -m set ! --match-set ALLOWED_SSH src -p tcp -m tcp --dport 22 -j SSHATTACK
iptables -A INPUT -p tcp -m tcp --dport 22 -m recent --seconds 60 --hitcount 4 --update -m state --state NEW -j SSHATTACK
iptables -A INPUT -m state --state NEW -p tcp -m tcp --dport 22 -j SSHATTACK

echo "Add block-icmp rules..."
iptables -A PINGATTACK -j LOG --log-prefix "PING attempt is detected!" --log-level 7
iptables -A PINGATTACK -j DROP
ipset -N ALLOWED_PING iphash
for addr in ${allowed_ping[@]}; do
    ipset -A ALLOWED_PING $addr
    echo "Successfully added IP address" $addr "to ALLOWED_PING set"
done
iptables -A INPUT -p icmp --icmp-type 8 -m set ! --match-set ALLOWED_PING src -j PINGATTACK

echo "Add rules to minimize SYN FLOOD effect..."
iptables -t raw -A SYNFLOOD -m limit --limit 1/h --limit-burst 1 -m comment --comment "Limit TCP SYN rate" -j RETURN
iptables -t raw -A SYNFLOOD -m limit --limit 1/h --limit-burst 1 -j LOG --log-prefix "Possible SYN Flood attack!" --log-level 7
iptables -t raw -A SYNFLOOD -j DROP
iptables -t raw -A PREROUTING -m set ! --match-set WHITELIST src -p tcp -m tcp --syn -j SYNFLOOD