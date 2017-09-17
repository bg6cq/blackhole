#!/bin/bash

cd /usr/src/blackhole

> ip.txt

curl http://222.195.81.240/scan/`date +%F`.sql.txt | grep -e "202.38.64" -e "210.45.64" -e "202.38.95" -e "222.195.70" -e "202.38.74" -e "202.38.93" >> ip.txt
curl http://222.195.81.240/scan/`date +%F`.3389.txt | grep -e "202.38.64" -e "210.45.64"  >> ip.txt

cut -f3,4 -d' ' ip.txt | while read port ip; do 
	echo $ip $port
	./addblackhole $ip 1 tcp $port "masscan"
done 

./changeiptables.sh
