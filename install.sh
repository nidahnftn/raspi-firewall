#!/bin/bash

echo 'Installing python-iptables..'
sudo apt install python3-pip -y
sudo apt-get install python3-venv -y
pip install --upgrade python-iptables

echo "Installing git.."
sudo apt install git -y
git clone https://github.com/ldx/python-iptables.git

echo "Setting up virtual environment.."
cd python-iptables
sudo python3 setup.py build
sudo python3 -m venv venv
source venv/bin/activate
sudo python3 setup.py install
deactivate
sudo PATH=$PATH python3 setup.py test
# Type 'import iptc' to test whether the module has successfully installed
# Then type 'exit()' to continue to next step
sudo PATH=$PATH python3

echo "Installing ipset.."
sudo apt install ipset -y