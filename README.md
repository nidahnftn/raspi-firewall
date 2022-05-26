Prerequities:
    1. Ubuntu 20.0.4 as ELK and rsyslog server
    2. Ubuntu Mate 16.04 armv7 as Raspberry Pi OS

Steps:
1. Activate SSH in Raspberry Pi
2. Run start.sh in Raspberry Pi
3. Install docker in Ubuntu Server
4. Install docker-compose in Ubuntu Server
5. On Raspberry Pi, go to /etc/rsyslog.conf and uncomment:
    <!-- module(load="imtcp")
    input(type="imtcp" port="514") -->
    then add comment to: module(load="imklog" permitnonkernelfacility="on")
6. On Raspberry Pi, go to /etc/rsyslog.d/50-default.conf and add one line before Log by facility.
    *.*                         @@192.168.1.13:514
    # @@ indicate tcp port, 192.168.1.13 is rsyslog server address, 514 is syslog port.
7. Restart rsyslog by: sudo systemctl restart rsyslog.service or sudo service rsyslog restart
8. Check if port 514 is listening by: netstat plntu | grep "LISTEN "
9. On Ubuntu Server, do the same as step #5
10. Restart rsyslog by: sudo systemctl restart rsyslog.service or sudo service rsyslog restart
<!-- 11. On Ubuntu Server, create new file: /etc/rsyslog.d/01-json-template.conf and fill it with 01-json-template.conf -->
<!-- 12. On Ubuntu Server, create new file: /etc/rsyslog.d/60-output.conf and fill it with 60-output.conf -->
13. Restart rsyslog by: sudo systemctl restart rsyslog.service or sudo service rsyslog restart
14. On Ubuntu Server, Create new directory: elk-stack and go in.
15. On Ubuntu Server, Add docker-compose.yml there.
16. On Ubuntu Server, Add logstash.conf
17. On Ubuntu Server, Run docker-compose up -d
18. To see the status of the containers, type docker-compose ps
19. To see logs, docker-compose logs -f. For seeing specific logs, e.g. logstash: docker-compose logs -f logstash
20. Wait until the resources are successfully built.
21. After that, it's time to install Filebeat on Ubuntu Server. Use the same version as ELK.
    1) wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.15.0-amd64.deb
    2) sudo dpkg -i filebeat-7.15.0-amd64.deb
21. Enable filebeat module named System: sudo filebeat modules enable system
22. Save the original file in another file: sudo cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.orig
23. Go to /etc/filebeat/filebeat.yml and add the configuration.
24. Create the Filebeat dashboards on the Kibana server: sudo filebeat setup
25. Start the Filebeat service: sudo service filebeat start
26. Configure the Filebeat service to start during boot time: sudo systemctl enable filebeat
27. Now, go to 192.168.1.13:5601 => Analytics => Dashboard. Search Syslog. Your dashboard is ready!
28. Before applying iptables rule, make sure all main devices are already connected to raspi so we can get their IP address to exclude from blacklist.
29. Apply the iptables rule and monitor through Kibana server.


source:
1. Setup filebeat: https://techexpert.tips/elasticsearch/filebeat-sending-syslog-messages-elasticsearch/
2. Configuring rsyslog server-client: https://www.digitalocean.com/community/tutorials/how-to-centralize-logs-with-rsyslog-logstash-and-elasticsearch-on-ubuntu-14-04
