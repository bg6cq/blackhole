<?php

include "top.php";

if( isset($_SESSION["isadmin"]) && ($_SESSION["isadmin"]==1))  {
        if(isset($_REQUEST["delistip"]))  {   //delistip
                $delistip = intval($_REQUEST["delistip"]);
                if($delistip!=0) {
                        $q="update blackip set end=now(),status='deleting' where id=?";
                        $stmt=$mysqli->prepare($q);
                        $stmt->bind_param("i",$delistip);
                        $stmt->execute();
                }
        }
        if(isset($_REQUEST["prefix"])) {  //add new
                $prefix = $_REQUEST["prefix"];
                $len = 32;
                $day = intval($_REQUEST["day"]);
                $prot = $_REQUEST["prot"];
                $port = $_REQUEST["port"];
                $msg = $_REQUEST["msg"];
		$q="select count(*) from mylist where inet_aton(ip) = (inet_aton(?) & inet_aton(mask))";
		$stmt=$mysqli->prepare($q);
                $stmt->bind_param("s",$prefix);
                $stmt->execute();
		$stmt->bind_result($count);
		$stmt->fetch();
		$stmt->close();
		if($count==0)  
			echo "Error: IP ".$prefix." not in mylist, check your input<p>";
		else {
                        $q = "insert into blackip (status,prefix,len,start,end,prot,port,msg) values ('adding',?,?,now(),date_add(now(),interval ? day),?,?,?)";
                        $stmt=$mysqli->prepare($q);
                       	$stmt->bind_param("siisis",$prefix,$len,$day,$prot,$port,$msg);
                       	$stmt->execute();
			sleep(1);
                }
        }
?>

<form action=list.php>
增加IP黑洞: IP:<input name=prefix>, 协议:<input type=radio name=prot value="tcp" checked>TCP</input>
<input type=radio name=prot value="udp">UDP</input><input type=radio name=prot value="all">ALL</input>,
端口:<input name=port size=5 value=3306>, 封锁天数: <input name=day value=10 size=2>, 消息: <input name=msg>
<input type=submit value=add>
</form>

<?php

}

$q="select count(distinct(prefix)) from blackip where status='added'";
$result = $mysqli->query($q);
$r=$result->fetch_array();
echo "正在保护 ".$r[0]." IP, ";
$q="select count(*) from blackip where status='added'";
$result = $mysqli->query($q);
$r=$result->fetch_array();
echo $r[0]." 端口<p>";

@$s=$_REQUEST["s"];
$q="select id,prefix,start,end,prot,port,msg from blackip where status='added' order by inet_aton(prefix)";
if($s=="s")
	$q="select id,prefix,start,end,prot,port,msg from blackip where status='added' order by start";
else if($s=="e")
	$q="select id,prefix,start,end,prot,port,msg from blackip where status='added' order by end";
else if($s=="p")
	$q="select id,prefix,start,end,prot,port,msg from blackip where status='added' order by prot, port";
else if($s=="m")
	$q="select id,prefix,start,end,prot,port,msg from blackip where status='added' order by msg";
$result = $mysqli->query($q);
echo "<table border=1 cellspacing=0>";
echo "<tr><th>序号</th><th><a href=list.php>IP</a></th><th><a href=list.php?s=s>start</a></th><th><a href=list.php?s=e>end</a></th>";
echo "<th><a href=list.php?s=p>协议</a></th><th>端口</th><th><a href=list.php?s=m>MSG</a></th>";
if( isset($_SESSION["isadmin"]) && ($_SESSION["isadmin"]==1))
        echo "<th>cmd</th>";
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
        if( isset($_SESSION["isadmin"]) && ($_SESSION["isadmin"]==1)) {
                echo "<td><a href=list.php?delistip=$r[0]  onclick=\"return confirm('删除 $r[1]/$r[4]/$r[5] ?');\">删除</a></td>";
        };
	echo "</tr>\n";
}
echo "</table>";

?>

