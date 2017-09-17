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

int debug = 0;

#include "sock.h"

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

int main(void)
{
	char buf[MAXLEN];
	char *p;
	MYSQL_RES *mysql_res;

	ConnectDB();

	while (fgets(buf, MAXLEN, stdin)) {
		int prefixlen = 255;
		int timespan;
		char *msg;
		if (strlen(buf) < 3)
			continue;
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = 0;
		fprintf(stderr, "got %s\n", buf);

// x.x.x.x/y timespan msg 
		p = buf;
		while (*p && (isxdigit(*p) || (*p == ':') || (*p == '.')))
			p++;
		if (*p == '/') {
			*p = 0;
			p++;
			prefixlen = atoi(p);
			while (*p && isdigit(*p))
				p++;
		} else {
			if (strchr(buf, ':'))
				prefixlen = 128;
			else
				prefixlen = 32;
		}
		if (*p != ' ')
			continue;
		p++;
		timespan = atoi(p);
		while (*p && isdigit(*p))
			p++;
		if (*p != ' ')
			continue;
		p++;
		msg = p;

		// check whitelist
		if (strchr(buf, '.')) {	// only ipv4 check whitelist
			snprintf(sqlbuf, MAXLEN, "select * from whitelist where inet_aton(\"%s\") & inet_aton(mask) =  inet_aton(ip)", buf);
			mysql_res = ExecSQL(sqlbuf, 1);
			if (mysql_num_rows(mysql_res) != 0) {
				mysql_free_result(mysql_res);
				fprintf(stderr, "%s whitelist %s/%d %s\n", nowctime(), buf, prefixlen, msg);
				snprintf(sqlbuf, MAXLEN, "insert into whiteiplog (tm,prefix,len,msg) values (now(),'%s',%d,'%s')", buf, prefixlen, msg);
				ExecSQL(sqlbuf, 0);
				continue;
			}
		}
		snprintf(sqlbuf, MAXLEN, "select id from blackip where prefix='%s' and len=%d "
			 "and (status='adding' or status='added') and msg='%s'", buf, prefixlen, msg);
		mysql_res = ExecSQL(sqlbuf, 1);
		if (mysql_num_rows(mysql_res) != 0) {
			MYSQL_ROW row;
			row = mysql_fetch_row(mysql_res);
			snprintf(sqlbuf, MAXLEN, "update blackip set end=FROM_UNIXTIME(UNIX_TIMESTAMP()+%d) where id='%s'", timespan, row[0]);
			ExecSQL(sqlbuf, 0);
			mysql_free_result(mysql_res);
			Debug("in table\n");
			fprintf(stderr, "%s update %s/%d %d %s\n", nowctime(), buf, prefixlen, timespan, msg);
			continue;
		}
		mysql_free_result(mysql_res);
		fprintf(stderr, "%s add %s/%d %d %s\n", nowctime(), buf, prefixlen, timespan, msg);
		snprintf(sqlbuf, MAXLEN,
			 "insert into blackip (status,prefix,len,start,end,msg) values('adding','%s',%d,now(),FROM_UNIXTIME( UNIX_TIMESTAMP()+%d),'%s')", buf,
			 prefixlen, timespan, msg);
		ExecSQL(sqlbuf, 0);
	}
	return 0;
}
