<?php

include "top.php";


echo "<p>黑洞路由管理的网段<p>";
$q="select ip,mask from mylist order by inet_aton(ip)";
$result = $mysqli->query($q);
echo "<table border=1 cellspacing=0>";
echo "<tr><th>序号</th><th>IP</th><th>MASK</th>";
echo "</tr>\n";
$count=0;
while($r=$result->fetch_array()) {
	$count++;
	echo "<tr><td align=center>";
	echo $count;
	echo "</td><td>";
	echo $r[0];
	echo "</td><td>";
	echo $r[1];
	echo "</td>";
	echo "</tr>\n";
}
echo "</table>";
?>
<p>
针对IP地址段和端口的防护策略<p>
<table border cellpadding=2 cellspacing=0>
<tr>
<th>端口</th><th>IP地址段</th><th>检测方式</th><th>防护策略</th>
</tr>
<tr><td align=center>
1433/1521/3306<br>
(MSSQL/Oracle/MySQL)
</td><td>
<pre>
202.38.64
210.45.64
202.38.95
222.195.70
202.38.74
202.38.93
</pre>
</td><td align=center>
端口开放
</td><td align=center>
封端口
</td>
</tr>

<tr><td align=center>
3389(RDP)
</td><td>
<pre>
202.38.64
210.45.64
</pre>
</td><td align=center>
端口开放
</td><td align=center>
封端口
</td></tr>

<tr><td align=center>
9100（HP打印机）
</td><td align=center>
所有
</td><td align=center>
端口开放<br>
并且80端口开放
</td><td align=center>
封IP
</td></tr>
</table>
</pre>

<p>

