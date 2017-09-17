#!/bin/bash

iptables -I FORWARD -j DROP -p udp --dport 389 -d 202.38.64.93

#first delete all
/sbin/iptables -F FORWARD_blackhole
/sbin/iptables -F blackhole_log_drop
/sbin/iptables -X blackhole_log_drop

#create ipset
/usr/sbin/ipset create bl_all hash:ip
/usr/sbin/ipset create bl_tcp hash:ip,port
/usr/sbin/ipset create bl_udp hash:ip,port

#create iptables
/sbin/iptables -N blackhole_log_drop
/sbin/iptables -A blackhole_log_drop -j LOG -m limit --limit 10/sec
/sbin/iptables -A blackhole_log_drop -j DROP

/sbin/iptables -A FORWARD_blackhole -j blackhole_log_drop -m set --match-set bl_tcp dst,dst -p tcp --syn
/sbin/iptables -A FORWARD_blackhole -j blackhole_log_drop -m set --match-set bl_udp dst,dst -p udp
/sbin/iptables -A FORWARD_blackhole -j blackhole_log_drop -m set --match-set bl_all dst 

