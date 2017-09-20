<?php

include "top.php";

$q="select count(distinct(prefix)) from blackip where status='deleted'";
$result = $mysqli->query($q);
$r=$result->fetch_array();
echo "已失效黑洞 ".$r[0]." IP, ";
$q="select count(*) from blackip where status='deleted'";
$result = $mysqli->query($q);
$r=$result->fetch_array();
echo $r[0]." 端口<p>";

@$s=$_REQUEST["s"];
$q="select id,prefix,start,end,prot,port,msg from blackip where status='deleted' order by inet_aton(prefix)";
if($s=="s")
	$q="select id,prefix,start,end,prot,port,msg from blackip where status='deleted' order by start";
else if($s=="e")
	$q="select id,prefix,start,end,prot,port,msg from blackip where status='deleted' order by end";
$result = $mysqli->query($q);
echo "<table border=1 cellspacing=0>";
echo "<tr><th>序号</th><th><a href=exp.php>IP</a></th><th><a href=exp.php?s=s>start</a></th><th><a href=exp.php?s=e>end</a></th>";
echo "<th>协议</th><th>端口</th><th>MSG</th>";
echo "</tr>\n";
$count=0;
while($r=$result->fetch_array()) {
	$count++;
	echo "<tr><td align=center>";
	echo $count;
	echo "</td><td>";
	echo $r[1];
	echo "</td><td>";
	echo $r[2];
	echo "</td><td>";
	echo $r[3];
	echo "</td><td>";
	echo $r[4];
	echo "</td><td>";
	echo $r[5];
	echo "</td><td>";
	echo $r[6];
	echo "</td>";
	echo "</tr>\n";
}
echo "</table>";

?>
