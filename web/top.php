<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"" />
<title>USTC IP Blackhole</title>
</head>

<body bgcolor=#dddddd>

<a href=index.php>流量</a>   
<a href=list.php>黑洞IP</a> 
<a href=stats.php>统计</a>
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
以下IP被加入黑洞(禁止1433/1521/3306/3389等端口流量)，如需解封请发信:james@ustc.edu.cn  
<?php 
echo "您的IP地址:";
echo  $_SERVER["REMOTE_ADDR"];
?>
<hr>
