service rsyslog start
iptables -I INPUT 1 -j LOG --log-prefix 'emblem_server_event: ' --log-level 7
