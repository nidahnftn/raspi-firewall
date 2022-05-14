#!/bin/bash

echo "Flush ipset..."
sudo ipset flush

echo "Added blacklist with ipset"
sudo ipset -N blacklist iphash

file='blacklist.txt'

while read line; do
sudo ipset -A blacklist $line
done < $file

sudo sh -c "ipset save > /etc/ipset.conf"