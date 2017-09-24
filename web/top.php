<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"" />
<title>USTC IP Blackhole</title>
</head>

<body bgcolor=#dddddd>
<a href=index.php>接口流量</a>   
<a href=list.php>黑洞IP</a> 
<a href=exp.php>失效黑洞</a> 
<a href=policy.php>防护策略</a>
<a href=stats.php>数量统计</a>
<a href=httpinfo.php>HTTPinfo</a>
<a href=intro.php>简介</a> 

<?php

$db_host = "localhost";
$db_user = "root";
$db_passwd = "";
$db_dbname = "blackip";

$mysqli = new mysqli($db_host, $db_user, $db_passwd, $db_dbname);
if(mysqli_connect_error()){
	echo mysqli_connect_error();
}
session_start();

if ( isset($_SESSION["isadmin"]) && $_SESSION["isadmin"]) {
	echo "<a href=whiteip.php>白名单</a> ";
	echo "<a href=logout.php>logout</a> ";
}

?>

发往以下IP相关端口的数据包被丢入黑洞，如需解封请发信:james@ustc.edu.cn  

<?php 

echo "您的IP地址:";
echo  $_SERVER["REMOTE_ADDR"];

?>
<hr>
