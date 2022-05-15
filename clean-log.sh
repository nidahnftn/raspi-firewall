#!/bin/bash

sudo sh -c 'cat /dev/null > /var/log/syslog'
sudo sh -c 'cat /dev/null > /var/log/auth.log'
sudo sh -c 'cat /dev/null > /var/log/user.log'
sudo sh -c 'cat /dev/null > /var/log/kern.log'
sudo sh -c 'cat /dev/null > /var/log/daemon.log'