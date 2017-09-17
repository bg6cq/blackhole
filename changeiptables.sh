#!/bin/bash

cd /usr/src/blackhole

/bin/mv ip_prot_port.txt ip_prot_port.txt.last

echo "select prefix, prot, port from blackip where status='added'" | mysql -N blackip |sort | uniq > ip_prot_port.txt

cmp ip_prot_port.txt.last  ip_prot_port.txt  > /dev/null

if [ $? == 0 ] ; then
#	echo no changes
	exit
fi

#update ipset
>tmp.tcp.new.2
>tmp.udp.new.2
>tmp.all.new.2
cat ip_prot_port.txt | while read ip prot port; do 
#	echo $ip $prot $port;
	if [ $prot == "tcp" ]; then
		echo $ip,tcp:$port >> tmp.tcp.new.2
	elif [ $prot == "udp" ]; then
		echo $ip,udp:$port  >> tmp.udp.new.2
	elif [ $prot == "all" ]; then
		echo $ip >> tmp.all.new.2
	fi
done

sort tmp.tcp.new.2 > tmp.tcp.new
sort tmp.udp.new.2 > tmp.udp.new
sort tmp.all.new.2 > tmp.all.new

/usr/sbin/ipset list bl_tcp | tail -n +7 | sort > tmp.tcp.old
/usr/sbin/ipset list bl_udp | tail -n +7 | sort > tmp.udp.old
/usr/sbin/ipset list bl_all | tail -n +7 | sort > tmp.all.old

diff -u tmp.tcp.old tmp.tcp.new |grep "^-[0-9]"|cut -c2-| while read ip; do
	echo del $ip
  	/usr/sbin/ipset del bl_tcp $ip
done
diff -u tmp.tcp.old tmp.tcp.new |grep "^+[0-9]"|cut -c2-| while read ip; do
	echo add $ip
  	/usr/sbin/ipset add bl_tcp $ip
done

diff -u tmp.udp.old tmp.udp.new |grep "^-[0-9]"|cut -c2-| while read ip; do
	echo del $ip
  	/usr/sbin/ipset del bl_udp $ip
done
diff -u tmp.udp.old tmp.udp.new |grep "^+[0-9]"|cut -c2-| while read ip; do
	echo add $ip
  	/usr/sbin/ipset add bl_udp $ip
done

diff -u tmp.all.old tmp.all.new |grep "^-[0-9]"|cut -c2-| while read ip; do
	echo del $ip
  	/usr/sbin/ipset del bl_all $ip
done
diff -u tmp.all.old tmp.all.new |grep "^+[0-9]"|cut -c2-| while read ip; do
	echo add $ip
  	/usr/sbin/ipset add bl_all $ip
done

/bin/cp ip_prot_port.txt /usr/src/ip_port
cd /usr/src/ip_port
git add ip_prot_port.txt
git commit -m `date +%F%H%M`
