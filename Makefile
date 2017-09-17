#使用方式

CFLAGS=-I/usr/include/mysql -L/usr/lib64/mysql -Wall

all: bgpipv6c fromhpfeed addblackhole delblackhole

bgpipv6c: bgpipv6c.c db.c sock.h
	gcc -g -o bgpipv6c $(CFLAGS) bgpipv6c.c -lmysqlclient 
fromhpfeed: fromhpfeed.c db.c sock.h
	gcc -g -o fromhpfeed $(CFLAGS) fromhpfeed.c -lmysqlclient 
addblackhole: addblackhole.c db.c sock.h
	gcc -g -o addblackhole $(CFLAGS) addblackhole.c -lmysqlclient 
delblackhole: delblackhole.c db.c sock.h
	gcc -g -o delblackhole $(CFLAGS) delblackhole.c -lmysqlclient 

dbdump:
	mysqldump blackip > blackip.sql

clean:
	rm -rf  bgpipv6c

indent: bgpipv6c.c addblackhole.c delblackhole.c fromhpfeed.c
	indent  bgpipv6c.c addblackhole.c delblackhole.c fromhpfeed.c -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4  \
-cli0 -d0 -di1 -nfc1 -i8 -ip0 -l160 -lp -npcs -nprs -npsl -sai \
-saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1

