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

#define MAXLEN 16384 

int debug=0;

#include "sock.h"

int  myasn=24362;
//char peerip[]="202.38.96.175";
char peerip[MAXLEN]="202.38.64.17";
unsigned short holdtime=180;

int peerfd=0;

/* 当前的时间 */
char * nowctime(void)
{	time_t t;
 	static char tbuf[MAXLEN];
 	t=time(NULL);
 	strcpy(tbuf,ctime(&t));
 	if(tbuf[strlen(tbuf)-1]=='\n') tbuf[strlen(tbuf)-1]=0;
        return tbuf;
}

static void Debug(const char *format, ... )
{
        if(debug) {
                va_list ap;
                fprintf(stderr, "%s ", nowctime());
                va_start (ap, format );
                vfprintf(stderr, format, ap);
                va_end(ap);
        }
}

void Error(const char *format, ... )
{
                va_list ap;
                fprintf(stderr, "%s ERROR:", nowctime());
                va_start (ap, format );
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


char DBHOST[MAXLEN]=DDBHOST;
int  DBPORT=DDBPORT;
char DBSOCKET[MAXLEN]=DDBSOCKET;
char DBUSER[MAXLEN]=DDBUSER;
char DBPASSWD[MAXLEN]=DDBPASSWD;
char DBNAME[MAXLEN]=DDBNAME;

MYSQL *mysql;
char sqlbuf[MAXLEN];


/* 连接mysql数据库 */
MYSQL * ConnectDB(void)
{
	if ((mysql=mysql_init(NULL))==NULL)  {
     	fprintf(stderr,"内部错误：mysql_init error\n");
		exit(0);
	}
	if( mysql_real_connect(mysql, DBHOST, DBUSER, DBPASSWD,
		DBNAME, DBPORT, DBSOCKET, 0)== NULL) {
       	fprintf(stderr,"内部错误：mysql_connect error, host:%s port:%d socket:%s user:%s pass:%s db:%s\n",DBHOST,DBPORT,DBSOCKET,DBUSER,DBPASSWD,DBNAME);
		exit(0);
	}
    return mysql;
}

/* 执行sql语句 */
MYSQL_RES * ExecSQL(char *sql, int haveresult)
{
	MYSQL_RES *mysql_res;
	Debug("sql: %s\n",sql);
	if(mysql_query(mysql,sql)) {
 		fprintf(stderr,"内部错误：mysql_querying %s error\n",sql);
		exit(0);
	}
	if(haveresult) {
 		if((mysql_res=mysql_store_result(mysql))==NULL) {
 			fprintf(stderr,"内部错误：mysql_store_result %s error\n",sql);
			exit(0);
		}
		return mysql_res; 
	}
	return NULL;
}
char * INET_NTOA(unsigned long int ip)
{ 	static char buf[100];
 	sprintf(buf,"%d.%d.%d.%d",
 	(unsigned int)((ip>>24)&0xff), (unsigned int)((ip>>16)&0xff), (unsigned int)((ip>>8)&0xff), (unsigned int)((ip)&0xff));
 	return buf;
}

char * INET_NTOA2(unsigned long int ip)
{ 	static char buf[100];
 	sprintf(buf,"%d.%d.%d.%d",
 	(unsigned int)((ip>>24)&0xff), (unsigned int)((ip>>16)&0xff), (unsigned int)((ip>>8)&0xff), (unsigned int)((ip)&0xff));
 	return buf;
}

void alarm_handler() {
	fprintf(stderr,"holdtime expired, exit\n");
	exit(0);
}


int dumpprefix(void)
{
	MYSQL_RES *mysql_res;
    MYSQL_ROW row;
	FILE *fp;

	// delete prefix before 30 days

	snprintf(sqlbuf,MAXLEN,"update blackip set status='deleting' where status='added' and end< now()");
	ExecSQL(sqlbuf,0);

	sleep(2);	
	fp=fopen("/var/www/html/blackip/bytime.html","w");
	fprintf(fp,"%s\n","<html> <head> <meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\" /> <title>by time</title> </head> <body>");
	fprintf(fp,"Last update: %s<p>\n",nowctime());
	
	
	snprintf(sqlbuf,MAXLEN,"select start,prefix,len,type,msg,end from blackip where status='added' order by start desc");
	mysql_res=ExecSQL(sqlbuf,1);
	if(mysql_num_rows(mysql_res) == 0) {
		mysql_free_result(mysql_res);
		Debug("nothing to dump\n");
		return 0;
	}
	fprintf(fp,"%s","<table border=1>\n<tr><th width=\"100\">封锁时间</th><th>失效时间</th><th width=\"100\">原因</th><th width=\"100\">IP</th><th width=\"600\">相关信息</th></tr>\n");
	
	while ((row= mysql_fetch_row(mysql_res))) {
		int i;
		fprintf(fp,"%s","<tr><td>");
		fprintf(fp,"%s",row[0]);
		fprintf(fp,"%s","</td><td>");
		fprintf(fp,"%s",row[5]);
		fprintf(fp,"%s","</td><td>");
		switch (atoi(row[3])) {
			case 0: fprintf(fp,"%s","恶意网站"); break;
			case 1: fprintf(fp,"%s","黄色网站"); break;
			case 2: fprintf(fp,"%s","病毒下载"); break;
			case 3: fprintf(fp,"%s","钓鱼网站"); break;
			case 4: fprintf(fp,"%s","瑞星恶意网站监测网"); break;
			case 100: fprintf(fp,"%s","neu黑名单"); break;
			default: fprintf(fp,"%s","unknow"); break;
		}
		fprintf(fp,"%s","</td><td>");
		fprintf(fp,"%s",row[1]);
		if(atoi(row[2])!=32) 
			fprintf(fp,"/%d ",atoi(row[2]));
		
		fprintf(fp,"</td><td>%s</td></tr>\n",row[4]);

	}
	mysql_free_result(mysql_res);

	fclose(fp);

	fp=fopen("/var/www/html/blackip/byip.html","w");
	fprintf(fp,"%s\n","<html> <head> <meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\" /> <title>by ip</title> </head> <body>");
	fprintf(fp,"Last update: %s<p>\n",nowctime());
	snprintf(sqlbuf,MAXLEN,"select start,prefix,len,type,msg from blackip where status='added' group by prefix order by INET_ATON(prefix)");
	
	mysql_res=ExecSQL(sqlbuf,1);
	if(mysql_num_rows(mysql_res) == 0) {
		mysql_free_result(mysql_res);
		Debug("nothing to dump\n");
		return 0;
	}
	fprintf(fp,"%s","<table border=1><tr><th>封锁时间</th><th>原因</th><th>IP</th><th>相关信息</th></tr>\n");
	
	while ((row= mysql_fetch_row(mysql_res))) {
		int i;
		fprintf(fp,"%s","<tr><td>");
		for(i=0;i<10;i++) 
			fprintf(fp,"%c",row[0][i]);
		fprintf(fp,"%s","</td><td>");
		switch (atoi(row[3])) {
			case 0: fprintf(fp,"%s","恶意网站"); break;
			case 1: fprintf(fp,"%s","黄色网站"); break;
			case 2: fprintf(fp,"%s","病毒下载"); break;
			case 3: fprintf(fp,"%s","钓鱼网站"); break;
			case 4: fprintf(fp,"%s","瑞星恶意网站监测网"); break;
			case 100: fprintf(fp,"%s","neu黑名单"); break;
			default: fprintf(fp,"%s","unknow"); break;
		}
		fprintf(fp,"%s","</td><td>");
		fprintf(fp,"%s",row[1]);
		if(atoi(row[2])!=32) 
			fprintf(fp,"/%d ",atoi(row[2]));
		
		fprintf(fp,"</td><td>%s</td></tr>\n",row[4]);

	}
	mysql_free_result(mysql_res);
	fclose(fp);

return 0;

	fp=fopen("/var/www/html/blackip/byip.txt","w");
	fprintf(fp,"%s\n","#\n# ip black list by USTC");
	{ time_t c;
	  struct tm * ptm;
	     c=time(NULL);
	  ptm=localtime(&c);
	  fprintf(fp,"# time : %04d-%02d-%02dT%02d:%02d:%02d.%06d\n#\n",
		ptm->tm_year+1900, ptm->tm_mon+1, ptm->tm_mday,
		ptm->tm_hour, ptm->tm_min, ptm->tm_sec, 0);
	}
	snprintf(sqlbuf,MAXLEN,"select prefix,len,type,url from blackip where status='added' order by INET_ATON(prefix)");
	
	mysql_res=ExecSQL(sqlbuf,1);
	if(mysql_num_rows(mysql_res) == 0) {
		mysql_free_result(mysql_res);
		Debug("nothing to dump\n");
		return 0;
	}
	while ((row= mysql_fetch_row(mysql_res))) {
		fprintf(fp,"%s|ustc",row[0]);
if(0) {
		switch (atoi(row[2])) {
			case 0: fprintf(fp,"%s","Malicious"); break;
			case 1: fprintf(fp,"%s","Adult"); break;
			case 2: fprintf(fp,"%s","Virus"); break;
			case 3: fprintf(fp,"%s","Phishing"); break;
			case 4: fprintf(fp,"%s","Rsing"); break;
			case 100: fprintf(fp,"%s","neu"); break;
			default: fprintf(fp,"%s","unknow"); break;
		}
}
		fprintf(fp,"|%s\n",row[3]);

	}
	mysql_free_result(mysql_res);
	fclose(fp);
	return 0;
}
int main(int argc, char*argv[])
{	int c;
	while ((c = getopt(argc, argv, "d")) != EOF) switch(c) {
		case 'd':
			debug=1;
			break;
	}

	if(debug) {
		fprintf(stderr,"db host: %s\n",DBHOST);
		fprintf(stderr,"db port: %d\n",DBPORT);
		fprintf(stderr,"db socket: %s\n",DBSOCKET);
		fprintf(stderr,"db user: %s\n",DBUSER);
		fprintf(stderr,"db pass: %s\n",DBPASSWD);
		fprintf(stderr,"db name: %s\n",DBNAME);
	}
	fprintf(stderr,"myasn=%d peerip=%s\n",myasn,peerip);
	signal(SIGALRM,alarm_handler);
	mysql = ConnectDB();
	dumpprefix();
	return 0;
}
