<?php
$db_host = "localhost";
$db_user = "root";
$db_passwd = "";
$db_dbname = "blackip";

$mysqli = new mysqli($db_host, $db_user, $db_passwd, $db_dbname);
if(mysqli_connect_error()){
        echo mysqli_connect_error();
}

$q="select count(distinct(prefix)) from blackip where status='added'";
$result = $mysqli->query($q);
$r=$result->fetch_array();
echo "N:".$r[0];
$q="select count(*) from blackip where status='added'";
$result = $mysqli->query($q);
$r=$result->fetch_array();
echo ":".$r[0];
?>

