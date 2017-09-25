<?php

include "top.php";

?>

<h2>相关软件</h2>
1. bgp程序<p>
<a href=http://blackip.ustc.edu.cn/intro.php>简介</a><p>
<a href=https://github.com/bg6cq/blackhole>程序</a><p>

2. masscan<p>
<a href=https://github.com/robertdavidgraham/masscan>程序</a><p>

3. http_info<p>
<a href=https://github.com/bg6cq/http_info>程序</a>
<p>

<img src=blackhole.png>
<pre>
#iptables -L -nv

Chain FORWARD (policy ACCEPT 1095K packets, 1278M bytes)
 pkts bytes target     prot opt in     out     source               destination
3148K 3270M FORWARD_blackhole  all  --  *      *       0.0.0.0/0            0.0.0.0/0

Chain OUTPUT (policy ACCEPT 971K packets, 155M bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain FORWARD_blackhole (1 references)
 pkts bytes target     prot opt in     out     source               destination
  487 23740 blackhole_log_drop  tcp  --  *      *       0.0.0.0/0            0.0.0.0/0           match-set bl_tcp dst,dst tcp flags:0x17/0x02
 188K   15M blackhole_log_drop  udp  --  *      *       0.0.0.0/0            0.0.0.0/0           match-set bl_udp dst,dst
   14  1214 blackhole_log_drop  all  --  *      *       0.0.0.0/0            0.0.0.0/0           match-set bl_all dst

Chain blackhole_log_drop (3 references)
 pkts bytes target     prot opt in     out     source               destination
15165 1226K LOG        all  --  *      *       0.0.0.0/0            0.0.0.0/0           limit: avg 10/sec burst 5 LOG flags 0 level 4
 188K   15M DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0

#ipset list
Name: bl_all
Type: hash:ip
Header: family inet hashsize 1024 maxelem 65536 
Size in memory: 16520
References: 1
Members:
210.45.64.2

Name: bl_tcp
Type: hash:ip,port
Header: family inet hashsize 1024 maxelem 65536 
Size in memory: 19632
References: 1
Members:
222.195.70.8,tcp:3306
222.195.70.60,tcp:3306
202.38.64.93,tcp:3389
222.195.70.38,tcp:3306
222.195.70.144,tcp:3306
222.195.70.134,tcp:3306
202.38.74.214,tcp:1433
202.38.64.66,tcp:3306

Name: bl_udp
Type: hash:ip,port
Header: family inet hashsize 1024 maxelem 65536 
Size in memory: 16560
References: 1
Members:
202.38.64.93,udp:389
</pre>
