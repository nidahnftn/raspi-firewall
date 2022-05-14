#!/bin/bash

echo "Download and install Filebeat package"
sudo mkdir -p /downloads/filebeat
cd /downloads/filebeat
wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.15.0-amd64.deb
sudo dpkg -i filebeat-7.15.0-amd64.deb

echo "Enable Filebeat module"
sudo filebeat modules enable system

sudo cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.orig

echo 'filebeat.inputs:
- type: log
  enabled: false
  paths:
    - /var/log/syslog
filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false
setup.template.settings:
  index.number_of_shards: 1
setup.kibana:
  host: "192.168.1.13:5601"
output.elasticsearch:
  hosts: ["192.168.1.13:9200"]
processors:
  - add_host_metadata: ~
  - add_cloud_metadata: ~
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~
' | sudo tee -a /etc/filebeat/filebeat.yml

sudo filebeat setup
sudo service filebeat start
sudo systemctl enable filebeat

# openssl s_client -showcerts -connect https://docker.elastic.co:443 < /dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > /etc/docker/certs.d/https://docker.elastic.co/ca.crt
# openssl s_client -showcerts -connect docker.elastic.co:443 < /dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > ca.crt
# ex +'/BEGIN CERTIFICATE/,/END CERTIFICATE/p' <(echo | openssl s_client -showcerts -connect docker.elastic.co:443) -scq > /etc/docker/certs.d/docker.elastic.co/docker_registry.crt
