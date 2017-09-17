#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <time.h>
#include <endian.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define MAXLEN 16384

int debug = 1;

#include "sock.h"

int myasn = 65500;
char peerip[MAXLEN] = "210.45.230.118";
char routerid[MAXLEN] = "210.45.224.10";
//char peerip[MAXLEN]="202.38.95.241";
//char peerip[MAXLEN]="202.38.64.17";
unsigned short holdtime = 180;

int peerfd = 0;

/* 当前的时间 */
char *nowctime(void)
{
	time_t t;
	static char tbuf[MAXLEN];
	t = time(NULL);
	strcpy(tbuf, ctime(&t));
	if (tbuf[strlen(tbuf) - 1] == '\n')
		tbuf[strlen(tbuf) - 1] = 0;
	return tbuf;
}

static void Debug(const char *format, ...)
{
	if (debug) {
		va_list ap;
		fprintf(stderr, "%s ", nowctime());
		va_start(ap, format);
		vfprintf(stderr, format, ap);
		va_end(ap);
	}
}

void Error(const char *format, ...)
{
	va_list ap;
	fprintf(stderr, "%s ERROR:", nowctime());
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	exit(0);
}

#include <mysql.h>
#define DDBHOST 		"localhost"
#define DDBPORT 		3306
#define DDBSOCKET 	"/var/lib/mysql/mysql.sock"
#define DDBUSER 		"root"
#define DDBPASSWD 	""
#define DDBNAME     		"blackip"

char DBHOST[MAXLEN] = DDBHOST;
int DBPORT = DDBPORT;
char DBSOCKET[MAXLEN] = DDBSOCKET;
char DBUSER[MAXLEN] = DDBUSER;
char DBPASSWD[MAXLEN] = DDBPASSWD;
char DBNAME[MAXLEN] = DDBNAME;

MYSQL *mysql;
char sqlbuf[MAXLEN];

/* 连接mysql数据库 */
MYSQL *ConnectDB(void)
{
	if ((mysql = mysql_init(NULL)) == NULL)
		Error("%s\n", "内部错误：mysql_init error");
	if (mysql_real_connect(mysql, DBHOST, DBUSER, DBPASSWD, DBNAME, DBPORT, DBSOCKET, 0) == NULL)
		Error("内部错误：mysql_connect error, host:%s port:%d socket:%s user:%s pass:%s db:%s\n", DBHOST, DBPORT, DBSOCKET, DBUSER, DBPASSWD,
		      DBNAME);
	return mysql;
}

/* 执行sql语句 */
MYSQL_RES *ExecSQL(char *sql, int haveresult)
{
	MYSQL_RES *mysql_res;
	Debug("sql: %s\n", sql);
	if (mysql_query(mysql, sql))
		Error("内部错误：mysql_querying %s error\n", sql);
	if (haveresult) {
		if ((mysql_res = mysql_store_result(mysql)) == NULL)
			Error("内部错误：mysql_store_result %s error\n", sql);
		return mysql_res;
	}
	return NULL;
}

char *INET_NTOA(unsigned long int ip)
{
	static char buf[100];
	sprintf(buf, "%d.%d.%d.%d",
		(unsigned int)((ip >> 24) & 0xff), (unsigned int)((ip >> 16) & 0xff), (unsigned int)((ip >> 8) & 0xff), (unsigned int)((ip) & 0xff));
	return buf;
}

void alarm_handler()
{
	Error("holdtime expired, exit\n");
}

void DumpWithdraw(unsigned char *pkt, int pktlen)
{
	int prefixlen, psize;
	unsigned long prefix = 0L;
	if (debug == 0)
		return;
	Debug("Withdraw route:\n");
	while (pktlen > 0) {
		prefix = 0;
		prefixlen = *(pkt);
		pkt++;
		pktlen--;
		psize = (prefixlen + 7) / 8;
		if (pktlen < psize)
			Error("pktlen<psize???\n");
		if (psize > 0)
			prefix += (*pkt) << 24;
		if (psize > 1)
			prefix += (*(pkt + 1)) << 16;
		if (psize > 2)
			prefix += (*(pkt + 2)) << 8;
		if (psize > 3)
			prefix += (*(pkt + 3));
		pkt += psize;
		pktlen -= psize;
		fprintf(stderr, "%s/%d\n", INET_NTOA(prefix), prefixlen);
	}
}

void DumpNLRI(unsigned char *pkt, int pktlen)
{
	int prefixlen, psize;
	unsigned long prefix = 0L;
	if (debug == 0)
		return;
	Debug("NLRI route: pktlen=%d\n", pktlen);
	while (pktlen > 0) {
		prefix = 0;
		prefixlen = *(pkt);
		pkt++;
		pktlen--;
		psize = (prefixlen + 7) / 8;
		if (pktlen < psize)
			Error("pktlen<psize???\n");
		if (psize > 0)
			prefix += (*pkt) << 24;
		if (psize > 1)
			prefix += (*(pkt + 1)) << 16;
		if (psize > 2)
			prefix += (*(pkt + 2)) << 8;
		if (psize > 3)
			prefix += (*(pkt + 3));
		pkt += psize;
		pktlen -= psize;
		fprintf(stderr, "%s/%d\n", INET_NTOA(prefix), prefixlen);
	}
}

void DumpASPATH(unsigned char *pkt, int pktlen)
{
	unsigned char ptype, plen;
	int i;
	if (debug == 0)
		return;
	while (pktlen > 0) {
		ptype = *pkt;
		pkt++;
		pktlen--;
		if (pktlen == 0)
			Error("pktlen==0???\n");
		plen = *pkt;
		pkt++;
		pktlen--;
		if (pktlen == 0)
			Error("pktlen==0???\n");
		if (ptype == 1)
			fprintf(stderr, "AS_SET ");
		else if (ptype == 2)
			fprintf(stderr, "AS_SEQENCE ");
		else
			fprintf(stderr, "unknow ");
		for (i = 0; i < plen; i++) {
			fprintf(stderr, "%d ", (*pkt << 8) + *(pkt + 1));
			pkt += 2;
			pktlen -= 2;
		}
	}
	fprintf(stderr, "\n");
}

void DumpPathattr(unsigned char *pkt, int pktlen)
{
	int attrlen, attrflag, attrtype;
	if (debug == 0)
		return;
	Debug("Path Attr: len=%d\n", pktlen);
	while (pktlen > 0) {
		attrflag = *pkt;
		pkt++;
		pktlen--;
		if (pktlen == 0)
			Error("pktlen==0???\n");
		fprintf(stderr, "Attr flag: %02X ", attrflag);
		if (attrflag & 0x80)
			fprintf(stderr, "optional ");
		else
			fprintf(stderr, "well-know ");
		if (attrflag & 0x40)
			fprintf(stderr, "transitive ");
		else
			fprintf(stderr, "non-transitive ");
		if (attrflag & 0x20)
			fprintf(stderr, "partial ");
		else
			fprintf(stderr, "complete ");
		if (attrflag & 0x10)
			fprintf(stderr, "extend_len ");
		else
			fprintf(stderr, "one_octet_len ");

		fprintf(stderr, "\n");
		attrtype = *pkt;
		pkt++;
		pktlen--;
		if (pktlen == 0)
			Error("pktlen==0???\n");
		fprintf(stderr, "Attr Type: %02X ", attrtype);

		if (attrflag & 0x10) {
			attrlen = ((*pkt) << 8) + *(pkt + 1);
			pkt += 2;
			pktlen -= 2;
		} else {
			attrlen = (*pkt);
			pkt++;
			pktlen--;
		}
		fprintf(stderr, "Attr len: %d\n", attrlen);

		if (pktlen == 0)
			Error("pktlen==0???\n");
		switch (attrtype) {
		case 1:	// ORIGIN
			fprintf(stderr, "ORIGIN: ");
			if (attrlen != 1) {
				fprintf(stderr, "bad len %d, should be 1\n", attrlen);
			}
			fprintf(stderr, " %d ", *pkt);
			switch (*pkt) {
			case 0:
				fprintf(stderr, "IGP\n");
				break;
			case 1:
				fprintf(stderr, "EGP\n");
				break;
			case 2:
				fprintf(stderr, "INCOMPLETE\n");
				break;
			default:
				fprintf(stderr, "unknow\n");
			}
			break;
		case 2:	// AS_PATH
			fprintf(stderr, "ASPATH: ");
			DumpASPATH(pkt, attrlen);
			break;
		case 3:	// NEXT_HOP
			fprintf(stderr, "NEXT_HOP: %d.%d.%d.%d\n", *(pkt), *(pkt + 1), *(pkt + 2), *(pkt + 3));
			break;
		case 4:	// MED
			{
				unsigned long *med;
				med = (unsigned long *)pkt;
				fprintf(stderr, "MED: %lu\n", (unsigned long)ntohl(*med));
			}
			break;
		case 5:	// Local_pref 
			{
				unsigned long *lp;
				lp = (unsigned long *)pkt;
				fprintf(stderr, "Local_Pref: %lu\n", (unsigned long)ntohl(*lp));
			}
			break;
		case 8:	// community
			fprintf(stderr, "Community %d:%d\n", ntohs(*(unsigned short *)(pkt)), ntohs(*(unsigned short *)(pkt + 2)));
			break;
		case 14:	// MP_REACH_NLRI
			{
				int i;
				int l;
				unsigned char *p;
				fprintf(stderr, "MP_REACH_NLRI: ");
				fprintf(stderr, "AFI/SAFI=%d/%d next_hop: ", ntohs(*(unsigned short *)(pkt)), *(pkt + 2));
				for (i = 0; i < *(pkt + 3); i++)
					fprintf(stderr, "%02X ", *(pkt + 4 + i));

				i = *(pkt + *(pkt + 3) + 4);	// num of SNPAs
				if (i == 0) {	// num of SNPAs is 0, for ipv6 should be 0
					l = attrlen - 5 - *(pkt + 3);
					p = pkt + *(pkt + 3) + 5;	// p point to first NLRI
					fprintf(stderr, "\n");
					while (l > 0) {
						fprintf(stderr, "NLRI: ");
						if (*p > 0) {
							for (i = 0; i < (*p + 7) / 8; i++) {
								fprintf(stderr, "%02X ", *(p + 1 + i));
								l--;
							}
						}
						fprintf(stderr, "::/%d\n", *p);
						l--;
						p += (*p + 7) / 8 + 1;
					}
				}
			}
			break;
		case 15:	// MP_UNREACH_NLRI
			{
				int l, i;
				unsigned char *p;
				fprintf(stderr, "MP_UNREACH_NLRI: ");
				fprintf(stderr, "AFI/SAFI=%d/%d\n", ntohs(*(unsigned short *)(pkt)), *(pkt + 2));
				l = attrlen - 3;
				p = pkt + 3;	// p point to first NLRI
				while (l > 0) {
					fprintf(stderr, "NLRI: ");
					if (*p > 0) {
						for (i = 0; i < (*p + 7) / 8; i++) {
							fprintf(stderr, "%02X ", *(p + 1 + i));
							l--;
						}
					}
					fprintf(stderr, "::/%d\n", *p);
					l--;
					p += (*p + 7) / 8 + 1;
				}
			}
			break;
		default:
			{
				int i;
				for (i = 0; i < attrlen; i++)
					fprintf(stderr, "%02X ", *(pkt + i));
			}
			fprintf(stderr, "\n");
		}		// end switch
		pkt += attrlen;
		pktlen -= attrlen;
	}
}

void DumpPKT(unsigned char *pkt, int pktlen)
{
	int i;
	unsigned char *type;
	time_t tm;
	unsigned short int *len;
	if (debug == 0)
		return;
	time(&tm);
	fprintf(stderr, "BGP PKT len=%d at %s", pktlen, ctime(&tm));

	if (pktlen < 19) {
		fprintf(stderr, "PKT len is %d, too small. ERROR\n", pktlen);
		return;
	}
	fprintf(stderr, "Marker: ");
	for (i = 0; i < 16; i++) {
		fprintf(stderr, "%02X ", pkt[i]);
	}
	fprintf(stderr, "\n");
	len = (unsigned short int *)(pkt + 16);
	if (pktlen != ntohs(*len)) {
		fprintf(stderr, "PKT len is %d, but BGP Length is %d. ERROR\n", pktlen, ntohs(*len));
		return;
	}
	type = pkt + 18;
	pkt = pkt + 19;
	pktlen = pktlen - 19;
	switch (*type) {
	case 1:		/* open msg */
		if (pktlen < 10) {
			fprintf(stderr, "Incomplete OPEN MSG, len=%d\n", pktlen);
			break;
		}
		fprintf(stderr, "OPEN MSG: ver=%d asn=%d holdtime=%d id=%d.%d.%d.%d\n",
			*(pkt), (*(pkt + 1) << 8) + *(pkt + 2), (*(pkt + 3) << 8) + *(pkt + 4), *(pkt + 5), *(pkt + 6), *(pkt + 7), *(pkt + 8));
		fprintf(stderr, "          opt param len=%d\n", *(pkt + 9));
		if (*(pkt + 9) > 0) {
			int plen = *(pkt + 9);
			pkt += 10;
			while (plen > 0) {
				fprintf(stderr, "parm_type:%d parm_len:%d ", *pkt, *(pkt + 1));
				if (*pkt == 2) {	// capability code 
					unsigned char *p;
					int caplen = *(pkt + 1);
					p = pkt + 2;
					if (caplen > 0)
						fprintf(stderr, " Capability :\n");
					while (caplen > 0) {
						fprintf(stderr, "cap_code:%d cap_len:%d ", *p, *(p + 1));
						if (*p == 1) {
							fprintf(stderr, "MPBGP afi/safi=%d/%d\n", ntohs(*(unsigned short *)(p + 2)), *(p + 5));
						} else if (*p == 2) {
							fprintf(stderr, "Route Refresh Cap\n");
						} else
							fprintf(stderr, "\n");

						caplen = caplen - 2 - *(p + 1);
						p = p + *(p + 1) + 2;
					}
				} else
					fprintf(stderr, "\n");
				plen = plen - 2 - *(pkt + 1);
				pkt = pkt + *(pkt + 1) + 2;
			}
		}
		break;
	case 2:		/* update msg */  {
			unsigned short int *withdrawlen, *pathattrlen;
			fprintf(stderr, "UPDATE MSG: len=%d\n", pktlen);
			withdrawlen = (unsigned short int *)pkt;
			fprintf(stderr, "Withdraw len=%d\n", ntohs(*withdrawlen));
			DumpWithdraw(pkt + 2, ntohs(*withdrawlen));
			pkt += ntohs(*withdrawlen) + 2;
			pktlen -= (ntohs(*withdrawlen) + 2);
			pathattrlen = (unsigned short int *)pkt;
			fprintf(stderr, "Path attr len=%d\n", ntohs(*pathattrlen));
			if (ntohs(*pathattrlen) == 0)
				break;
			DumpPathattr(pkt + 2, ntohs(*pathattrlen));
			pkt += ntohs(*pathattrlen) + 2;
			pktlen -= ntohs(*pathattrlen) + 2;
			DumpNLRI(pkt, pktlen);
		}

		break;
	case 3:		/* notification msg */
		fprintf(stderr, "NOTIFICATION MSG: code=%d(", *(pkt));
		switch (*pkt) {
		case 1:
			fprintf(stderr, "Message Header Error),subode=%d(", *(pkt + 1));
			switch (*(pkt + 1)) {
			case 1:
				fprintf(stderr, "Connection Not Synchronized)\n");
				break;
			case 2:
				fprintf(stderr, "Bad Message Length)\n");
				break;
			case 3:
				fprintf(stderr, "Bad Message Type)\n");
				break;
			default:
				fprintf(stderr, "unknow)\n");
			}
			break;
		case 2:
			fprintf(stderr, "OPEN Message Error");
			switch (*(pkt + 1)) {
			case 1:
				fprintf(stderr, "Unsupported Version Number)\n");
				break;
			case 2:
				fprintf(stderr, "Bad Peer AS)\n");
				break;
			case 3:
				fprintf(stderr, "Bad BGP Identifier)\n");
				break;
			case 4:
				fprintf(stderr, "Unsupported Optional Parameter)\n");
				break;
			case 5:
				fprintf(stderr, "Authentication Failure)\n");
				break;
			case 6:
				fprintf(stderr, "Unacceptable Hold Time)\n");
				break;
			default:
				fprintf(stderr, "unknow)\n");
			}
			break;
		case 3:
			fprintf(stderr, "UPDATE Message Error");
			switch (*(pkt + 1)) {
			case 1:
				fprintf(stderr, "Malformed Attribute List)\n");
				break;
			case 2:
				fprintf(stderr, "Unrecognized Well-known Attribute)\n");
				break;
			case 3:
				fprintf(stderr, "Missing Well-known Attribute)\n");
				break;
			case 4:
				fprintf(stderr, "Attribute Flags Error)\n");
				break;
			case 5:
				fprintf(stderr, "Attribute Length Error)\n");
				break;
			case 6:
				fprintf(stderr, "Invalid ORIGIN Attribute)\n");
				break;
			case 7:
				fprintf(stderr, "AS Routing Loop)\n");
				break;
			case 8:
				fprintf(stderr, "Invalid NEXT_HOP Attribute)\n");
				break;
			case 9:
				fprintf(stderr, "Optional Attribute Error)\n");
				break;
			case 10:
				fprintf(stderr, "Invalid Network Field)\n");
				break;
			case 11:
				fprintf(stderr, "Malformed AS_PATH)\n");
				break;
			default:
				fprintf(stderr, "unknow)\n");
			}
		case 4:
			fprintf(stderr, "Hold Time Expired");
			break;
		case 5:
			fprintf(stderr, "Finite State Machine Error");
			break;
		case 6:
			fprintf(stderr, "Cease, subcode:%d", *(pkt + 1));
			break;
		default:
			fprintf(stderr, "unknow)\n");
		}
		break;

	case 4:		/* keepalive msg */
		fprintf(stderr, "KEEPALIVE MSG: ");
		if (pktlen != 0)
			fprintf(stderr, "len!=0\n");
		else
			fprintf(stderr, "\n");
		break;
	default:		/* unknow */
		fprintf(stderr, "unknow)\n");

	}
}

#define PEEK 0
#define WAIT 1
int recvpkt(unsigned char *buf, int buflen, int mode)
{
	int len = 0;
	unsigned short *plen;
	int n;
	if (buflen < 4096)
		Error("buflen %d is too small\n", buflen);
	if (mode == PEEK) {
		Fcntl(peerfd, F_SETFL, O_NONBLOCK);
		n = recv(peerfd, buf, 1, MSG_PEEK);
		if ((n == -1) && (errno == EAGAIN)) {	/* no pkt */
			Fcntl(peerfd, F_SETFL, 0);
			return 0;
		}
		Fcntl(peerfd, F_SETFL, 0);
	}
	n = recv(peerfd, buf, 19, MSG_WAITALL);
	if (n != 19)
		Error("recv 19 got %d\n", n);
	len = 19;
	plen = (unsigned short *)(buf + 16);
	if (ntohs(*plen) > 4096)
		Error("msg len %d too long\n", ntohs(*plen));
	if (ntohs(*plen) != 19) {
		n = recv(peerfd, buf + len, ntohs(*plen) - len, MSG_WAITALL);
		if (n != ntohs(*plen) - len)
			Error("recv %d got %d\n", ntohs(*plen) - len, n);
		len += n;
	}
	Debug("Recv from peer, len=%d\n", len);
	return len;
}

void setmarker(unsigned char *p)
{
	int i;
	for (i = 0; i < 16; i++)
		*(p + i) = 0xff;
}

/* open msg 

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      +                                                               +
      |                                                               |
      +                                                               +
      |                           Marker                              |
      +                                                               +
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |          Length               |      Type     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+
       |    Version    |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |     My Autonomous System      |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           Hold Time           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         BGP Identifier                        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Opt Parm Len  |   14 
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

         0                   1
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
         |  Parm. Type   | Parm. Length  |  Parameter Value (variable)
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
                2            12

       +------------------------------+
       | Capability Code (1 octet)    | 1, MPBGP 
       +------------------------------+
       | Capability Length (1 octet)  | 4, len
       +------------------------------+
       0       7      15      23      31
       +-------+-------+-------+-------+
       |      AFI      | Res.  | SAFI  |
       +-------+-------+-------+-------+
               1                   1    IPv6 unicast

       +------------------------------+
       | Capability Code (1 octet)    | 1, MPBGP 
       +------------------------------+
       | Capability Length (1 octet)  | 4, len
       +------------------------------+
       0       7      15      23      31
       +-------+-------+-------+-------+
       |      AFI      | Res.  | SAFI  |
       +-------+-------+-------+-------+
               2                   1    IPv6 unicast

*/

void sendopen(int myasn, char *routerid)
{
	unsigned char buf[MAXLEN];
	unsigned short int *si;
	Debug("try send open msg\n");

	setmarker(buf);
	si = (unsigned short *)(buf + 16);
	*si = htons(43);
	*(buf + 18) = 1;	// type = 1, open msg
	*(buf + 19) = 4;	// ver =4, bgpv4
	si = (unsigned short *)(buf + 20);
	*si = htons(myasn);	// myasn      
	si = (unsigned short *)(buf + 22);
	*si = htons(holdtime);	// holdtime        
	*((unsigned long int *)(buf + 24)) = inet_addr(routerid);	// my router id

	*(buf + 28) = 14;	// opt len = 14

	*(buf + 29) = 2;	// param type: cap 
	*(buf + 30) = 12;

	*(buf + 31) = 1;	// MPBGP
	*(buf + 32) = 4;	// caplen=4
	si = (unsigned short *)(buf + 33);
	*si = htons(1);		// afi = 1
	*(buf + 35) = 0;
	*(buf + 36) = 1;	// safi = 1

	*(buf + 37) = 1;	// MPBGP
	*(buf + 38) = 4;	// caplen=4
	si = (unsigned short *)(buf + 39);
	*si = htons(2);		// afi = 2
	*(buf + 41) = 0;
	*(buf + 42) = 1;	// safi = 1

	DumpPKT(buf, 43);
	Send(peerfd, buf, 43, 0);
}

void sendkeepalive(void)
{
	static time_t lastsend = 0;
	time_t tm;
	unsigned char buf[MAXLEN];
	unsigned short int *si;
	time(&tm);
	if ((tm - lastsend) < holdtime / 3)
		return;		/* no need to send */
	lastsend = tm;
	Debug("try send keepalive msg\n");

	setmarker(buf);
	si = (unsigned short *)(buf + 16);
	*si = ntohs(19);
	*(buf + 18) = 4;
	DumpPKT(buf, 19);
	Send(peerfd, buf, 19, 0);
}

void connectpeer(void)
{
	unsigned char buf[MAXLEN];
	int len;
	Debug("try connect to peer\n");
	peerfd = Tcp_connect(peerip, "179");
	Debug("connected, fd is  %d\n", peerfd);
	sendopen(myasn, routerid);
	len = recvpkt(buf, MAXLEN, WAIT);	/* open */
	DumpPKT(buf, len);
	fprintf(stderr, "connect to peer\n");
}

void usage(void)
{
	fprintf(stderr, "Usage: bgpc [options] \n");
	fprintf(stderr, "   -d            print debug information\n");
	fprintf(stderr, "   -p peerip     default is %s\n", peerip);
	fprintf(stderr, "   -a myasn      default is %d\n", myasn);
	fprintf(stderr, "   -i routerid   default is %s\n", routerid);
	exit(0);
}

int packprefixv4(unsigned char *buf, char *pref, char *preflen)
{
	unsigned long int prefix;
	unsigned short int prefixlen;
	prefix = inet_addr(pref);
	if (prefix == (in_addr_t) (-1)) {
		fprintf(stderr, "prefix %s error\n", pref);
		return -1;
	}
	prefix = ntohl(prefix);
	prefixlen = atoi(preflen);
	if (prefixlen > 32) {
		fprintf(stderr, "preflen %s error\n", preflen);
		return -1;
	}
	if (prefix != (prefix & (0xffffffffL << (32 - prefixlen)))) {
		fprintf(stderr, "%s/%d is not a valid prefix\n", pref, prefixlen);
		return -1;
	}
	*(buf) = prefixlen;
	buf++;
	if (prefixlen > 24) {
		*(buf) = (prefix >> 24) & 0xff;
		*(buf + 1) = (prefix >> 16) & 0xff;
		*(buf + 2) = (prefix >> 8) & 0xff;
		*(buf + 3) = (prefix) & 0xff;
		return 5;
	} else if (prefixlen > 16) {
		*(buf) = (prefix >> 24) & 0xff;
		*(buf + 1) = (prefix >> 16) & 0xff;
		*(buf + 2) = (prefix >> 8) & 0xff;
		return 4;
	} else if (prefixlen > 8) {
		*(buf) = (prefix >> 24) & 0xff;
		*(buf + 1) = (prefix >> 16) & 0xff;
		return 3;
	} else if (prefixlen > 0) {
		*(buf) = (prefix >> 24) & 0xff;
		return 2;
	} else
		return 1;
}

int packprefixv6(unsigned char *buf, const char *pref, char *preflen)
{
	unsigned short int prefixlen;
	if (inet_pton(AF_INET6, pref, buf + 1) != 1)
		return -1;
	prefixlen = atoi(preflen);
	if (prefixlen > 128) {
		fprintf(stderr, "preflen %s error\n", preflen);
		return -1;
	}
	*buf = prefixlen;
	return (prefixlen + 7) / 8 + 1;
}

int sendupdatev4(char *prefix, char *prefixlen, char *next_hop, char *community)
{
	unsigned char buf[MAXLEN], *p;
	int packlen = 0;
	int len = 0, palen = 0;
	unsigned short int *wp;

	setmarker(buf);
	len = 16;
	*(buf + 18) = 2;	// type=update message
	len += 3;
	wp = (unsigned short *)(buf + 19);
	*wp = htons(0);		// Withdrawn Routes Length = 0
	len += 2;
	wp = (unsigned short *)(buf + 21);	// Total Path Attribute Length
	len += 2;
	p = buf + 23;		// p is Path Attr begin
	*p = 0x40;
	*(p + 1) = 1;
	*(p + 2) = 1;
	*(p + 3) = 0;		// ORIGIN IGP
	palen += 4;
	p += 4;
	*p = 0x40;
	*(p + 1) = 2;
	*(p + 2) = 4;		// ASPATH, blank
	palen += 3;
	p += 3;

	/* AS_PATH */
	*p = 2;			// type as_seqence
	*(p + 1) = 1;		// len
	*(p + 2) = myasn >> 8;
	*(p + 3) = myasn & 0xff;
	palen += 4;
	p += 4;

	*p = 0x40;
	*(p + 1) = 3;
	*(p + 2) = 4;		// NEXT_HOP
	palen += 3;
	p += 3;
	*((unsigned long int *)(p)) = inet_addr(next_hop);
	palen += 4;
	p += 4;

	*p = 0x80;
	*(p + 1) = 4;
	*(p + 2) = 4;		// MED
	palen += 3;
	p += 3;
	*p = 0;
	*(p + 1) = 0;
	*(p + 2) = 0;
	*(p + 3) = 20;		// MED 20
	palen += 4;
	p += 4;
	*p = 0x40;
	*(p + 1) = 5;
	*(p + 2) = 4;		// Local_Pref
	palen += 3;
	p += 3;
	*p = 0;
	*(p + 1) = 0;
	*(p + 2) = 0;
	*(p + 3) = 100;		// Local_Pref 100
	palen += 4;
	p += 4;

	if (community && community[0] != 0) {	// set community, fomat is XXXX:XXXX
		unsigned short int c1, c2;
		if (sscanf(community, "%hu:%hu", &c1, &c2) == 2) {
			*p = 0xC0;
			*(p + 1) = 8;
			*(p + 2) = 4;
			palen += 3;
			p += 3;
			*((unsigned short *)(p)) = htons(c1);
			*((unsigned short *)(p + 2)) = htons(c1);
			palen += 4;
			p += 4;
		}
	}
	*wp = htons(palen);
	len += palen;

	packlen = packprefixv4((unsigned char *)(p), prefix, prefixlen);
	if (packlen == -1)
		return 0;
	len += packlen;
	p += packlen;

	wp = (unsigned short *)(buf + 16);
	*wp = htons(len);
	DumpPKT(buf, len);
	Send(peerfd, buf, len, 0);
	len = recvpkt(buf, MAXLEN, PEEK);
	if (len > 0)
		DumpPKT(buf, len);
	return 1;
}

int sendupdatev6(char *prefix, char *prefixlen, char *next_hop, char *community)
{
	unsigned char buf[MAXLEN], *p;
	int packlen = 0;
	int len = 0, palen = 0;
	unsigned short int *wp;

	setmarker(buf);
	len = 16;
	*(buf + 18) = 2;	// type=update message
	len += 3;
	wp = (unsigned short *)(buf + 19);
	*wp = htons(0);		// Withdrawn Routes Length = 0
	len += 2;
	wp = (unsigned short *)(buf + 21);	// Total Path Attribute Length
	len += 2;
	p = buf + 23;		// p is Path Attr begin
	*p = 0x40;
	*(p + 1) = 1;
	*(p + 2) = 1;
	*(p + 3) = 0;		// ORIGIN IGP
	palen += 4;
	p += 4;
	*p = 0x40;
	*(p + 1) = 2;
	*(p + 2) = 0;		// ASPATH, blank
	palen += 3;
	p += 3;
/*	*p=0x40;	*(p+1)=3;  *(p+2)=4;  // NEXT_HOP
	palen+=3; p+=3;
	*p=192; *(p+1)=0; *(p+2)=2; *(p+3)=1; // 192.0.2.1
//	*p=202; *(p+1)=38; *(p+2)=64; *(p+3)=1; // 192.0.2.1
	palen+=4; p+=4;
*/
	*p = 0x80;
	*(p + 1) = 4;
	*(p + 2) = 4;		// MED
	palen += 3;
	p += 3;
	*p = 0;
	*(p + 1) = 0;
	*(p + 2) = 0;
	*(p + 3) = 20;		// MED 20
	palen += 4;
	p += 4;
	*p = 0x40;
	*(p + 1) = 5;
	*(p + 2) = 4;		// Local_Pref
	palen += 3;
	p += 3;
	*p = 0;
	*(p + 1) = 0;
	*(p + 2) = 0;
	*(p + 3) = 100;		// Local_Pref 100
	palen += 4;
	p += 4;

	if (community && community[0] != 0) {	// set community, fomat is XXXX:XXXX
		unsigned short int c1, c2;
		if (sscanf(community, "%hu:%hu", &c1, &c2) == 2) {
			*p = 0xC0;
			*(p + 1) = 8;
			*(p + 2) = 4;
			palen += 3;
			p += 3;
			*((unsigned short *)(p)) = htons(c1);
			*((unsigned short *)(p + 2)) = htons(c1);
			palen += 4;
			p += 4;
		}
	}

	*p = 0x80;
	*(p + 1) = 14;		// *(p+2) = len ;  MP_REACH_NLRI 
	*(p + 3) = 0;
	*(p + 4) = 2;
	*(p + 5) = 1;		// AFI/SFI = 2/1 ipv4 unicast
	*(p + 6) = 16;		// next_hop len = 16
	inet_pton(AF_INET6, next_hop, p + 7);
	*(p + 23) = 0;		// number of SNAPs = 0

	packlen = packprefixv6((unsigned char *)(p + 24), prefix, prefixlen);
	if (packlen == -1)
		return 0;
	*(p + 2) = packlen + 21;
	palen += packlen + 24;
	p += packlen + 24;

	*wp = htons(palen);
	len += palen;

	wp = (unsigned short *)(buf + 16);
	*wp = htons(len);
	DumpPKT(buf, len);
	Send(peerfd, buf, len, 0);
	len = recvpkt(buf, MAXLEN, PEEK);
	if (len > 0)
		DumpPKT(buf, len);
	return 1;
}

// if mode==0, it's first run, send state=='added'
// if mode==1, it's running, send state=='adding' and change state to 'added'
int sendupdate(int mode)
{
	MYSQL_RES *mysql_res;
	MYSQL_ROW row;

	if (mode == 0)
		snprintf(sqlbuf, MAXLEN, "select id,prefix,len from blackip where status='added'");
	else
		snprintf(sqlbuf, MAXLEN, "select id,prefix,len from blackip where status='adding'");

	mysql_res = ExecSQL(sqlbuf, 1);
	if (mysql_num_rows(mysql_res) == 0) {
		mysql_free_result(mysql_res);
		Debug("nothing to send\n");
		return 0;
	}

	while ((row = mysql_fetch_row(mysql_res))) {
		int sendresult;
		Debug("update prefix %s/%s\n", row[1], row[2]);
		if (strchr(row[1], ':'))
			sendresult = sendupdatev6(row[1], row[2], "2001:db8::1", "400:400");
		else
			sendresult = sendupdatev4(row[1], row[2], "210.45.230.117", "400:400");
		if (sendresult == 1 && mode == 1) {
			snprintf(sqlbuf, MAXLEN, "update blackip set status='added' where id=%s", row[0]);
			ExecSQL(sqlbuf, 0);
		}
	}
	mysql_free_result(mysql_res);
	return 0;
}

int sendwithdrawv4(char *prefix, char *prefixlen)
{
	unsigned char buf[MAXLEN], *p;
	int len = 0, packlen;
	unsigned short int *wp;
	setmarker(buf);
	len = 16;
	*(buf + 18) = 2;	// type=update message
	len += 3;
	wp = (unsigned short *)(buf + 19);
	*wp = 0;		// Unfeasible Routes Length = 0, I will use it 
	len += 2;
	p = buf + len;

	packlen = packprefixv4(p, prefix, prefixlen);
	if (packlen == -1)
		return -1;
	*wp = htons(packlen);
	len += packlen;
	p += packlen;
	wp = (unsigned short *)(p);	// Total Path Attribute Length
	*wp = 0;
	len += 2;
	wp = (unsigned short *)(buf + 16);
	*wp = htons(len);
	DumpPKT(buf, len);
	Send(peerfd, buf, len, 0);
	len = recvpkt(buf, MAXLEN, PEEK);
	if (len > 0)
		DumpPKT(buf, len);
	return 1;
}

int sendwithdrawv6(char *prefix, char *prefixlen)
{
	unsigned char buf[MAXLEN], *p;
	int len = 0, packlen;
	unsigned short int *wp;
	setmarker(buf);
	len = 16;
	*(buf + 18) = 2;	// type=update message
	len += 3;
	wp = (unsigned short *)(buf + 19);
	*wp = 0;		// Unfeasible Routes Length = 0, I will use it 
	len += 2;
	p = buf + len;		// p point to Total Path Attribute Length

	*(p + 2) = 0x80;
	*(p + 3) = 15;		// *(p+4) = mp_unreach_nlri len
	*(p + 5) = 0;
	*(p + 6) = 2;
	*(p + 7) = 1;		// AFI/SFI = 2/1 ipv6 unicast
	packlen = packprefixv6((unsigned char *)(p + 8), prefix, prefixlen);
	if (packlen == -1)
		return 0;
	*(p + 4) = packlen + 3;
	len += (packlen + 8);

	*((unsigned short *)(p)) = htons(packlen + 6);
	wp = (unsigned short *)(buf + 16);
	*wp = htons(len);

	DumpPKT(buf, len);
	Send(peerfd, buf, len, 0);
	len = recvpkt(buf, MAXLEN, PEEK);
	if (len > 0)
		DumpPKT(buf, len);
	return 1;
}

int sendwithdraw(void)
{
	MYSQL_RES *mysql_res;
	MYSQL_ROW row;
	int prefixsend = 0;
	Debug("try send withdraw msg\n");

	snprintf(sqlbuf, MAXLEN, "update blackip set status='deleting' where status='added' and end<now()");
	ExecSQL(sqlbuf, 0);

	snprintf(sqlbuf, MAXLEN, "select id,prefix,len from blackip where status='deleting'");
	mysql_res = ExecSQL(sqlbuf, 1);
	if (mysql_num_rows(mysql_res) == 0) {
		mysql_free_result(mysql_res);
		Debug("nothing to send\n");
		return 0;
	}

	while ((row = mysql_fetch_row(mysql_res))) {
		MYSQL_RES *mysql_res2;
		// If the same prefix exist and status is added, do not sendwithdraw
		snprintf(sqlbuf, MAXLEN, "select id,prefix,len from blackip where status='added' and id<>%s and prefix='%s' and len=%s", row[0], row[1],
			 row[2]);
		mysql_res2 = ExecSQL(sqlbuf, 1);
		if (mysql_num_rows(mysql_res2) == 0) {
			int sendresult;
			mysql_free_result(mysql_res2);
			Debug("withdraw prefix %s/%s\n", row[1], row[2]);
			if (strchr(row[1], ':'))
				sendresult = sendwithdrawv6(row[1], row[2]);
			else
				sendresult = sendwithdrawv4(row[1], row[2]);
			if (sendresult == 1) {
				snprintf(sqlbuf, MAXLEN, "update blackip set status='deleted' where id=%s", row[0]);
				ExecSQL(sqlbuf, 0);
				prefixsend++;
			}
		} else {
			mysql_free_result(mysql_res2);
			snprintf(sqlbuf, MAXLEN, "update blackip set status='deleted' where id=%s", row[0]);
			ExecSQL(sqlbuf, 0);
		}
	}
	mysql_free_result(mysql_res);
	return prefixsend;
}

void setdata(void)
{
/*
	int i;
	for(i=5;i<2000;i++) {
		snprintf(sqlbuf,MAXLEN,"insert into blackip values(%d,'adding','192.168.%d.%d',32,now(),now(),'')",i,100+i/256,i%256);
			ExecSQL(sqlbuf,0);
		
	}
*/
}

int do_bgp()
{
	unsigned char buf[MAXLEN];
	int len;
	connectpeer();
	sendkeepalive();	// send first keepalive
	len = recvpkt(buf, MAXLEN, WAIT);	// wait keepalive 
	if (len > 0)
		DumpPKT(buf, len);
	sendupdate(0);
	while (1) {
		sendkeepalive();
		while (1) {
			len = recvpkt(buf, MAXLEN, PEEK);
			if (len > 0)
				DumpPKT(buf, len);
			if ((len == 19) && (*(buf + 18) == 4))	// KEEPALIVE MSG, reset alarm
				alarm(holdtime);
			if (len <= 0)
				break;
		}
		sendwithdraw();
		sendupdate(1);
		sleep(1);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int c;
	while ((c = getopt(argc, argv, "hdp:a:")) != EOF)
		switch (c) {
		case 'h':
			usage();
			exit(0);
		case 'd':
			debug = 1;
			break;
		case 'p':
			strncpy(peerip, optarg, MAXLEN);
			break;
		case 'i':
			strncpy(routerid, optarg, MAXLEN);
			break;
		case 'a':
			myasn = atoi(optarg);
			break;
		}

	if (debug) {
		fprintf(stderr, "db host: %s\n", DBHOST);
		fprintf(stderr, "db port: %d\n", DBPORT);
		fprintf(stderr, "db socket: %s\n", DBSOCKET);
		fprintf(stderr, "db user: %s\n", DBUSER);
		fprintf(stderr, "db pass: %s\n", DBPASSWD);
		fprintf(stderr, "db name: %s\n", DBNAME);
	}
	fprintf(stderr, "myasn=%d peerip=%s\n", myasn, peerip);
	signal(SIGALRM, alarm_handler);
	mysql = ConnectDB();
	setdata();
	if (debug)
		return do_bgp();
	while (1) {
		int pid;
		pid = fork();
		if (pid == 0)	// child 
			return do_bgp();
		else if (pid == -1)	// error
			exit(0);
		else
			wait(NULL);
		sleep(10);
	}
}
