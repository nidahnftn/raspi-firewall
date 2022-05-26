#!/bin/bash

echo "Flush ipset..."
sudo ipset flush

echo "Added whitelist with ipset"
sudo ipset -N whitelist iphash

file='whitelist.txt'

while read line; do
sudo ipset -A whitelist $line
done < $file

#sudo sh -c "ipset save > /etc/ipset.conf"