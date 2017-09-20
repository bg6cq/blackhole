<?php

include "top.php";

if( isset($_SESSION["isadmin"]) && ($_SESSION["isadmin"]==1))  {
	if(isset($_REQUEST["delip"]))  {   //deip
        	$delip = $_REQUEST["delip"];
        	if($delip!=0) {
			$delmask=$_REQUEST["delmask"];
                	$q="delete from whitelist where ip=? and mask=?";
			$stmt=$mysqli->prepare($q);
    			$stmt->bind_param("ss",$delip,$delmask);
    			$stmt->execute();   
        	}
	}	
	if(isset($_REQUEST["ip"])) {  //add new
		$ip= $_REQUEST["ip"];
		$mask = $_REQUEST["mask"];
		$msg = $_REQUEST["msg"];
		$q = "insert into whitelist (ip,mask,msg) values (?,?,?)";
			$stmt=$mysqli->prepare($q);
    			$stmt->bind_param("sss",$ip,$mask,$msg);
    			$stmt->execute();   
		}
	}
?>

<form action=whiteip.php>
增加白名单IP<input name=ip>/<input name=mask size=20 value="255.255.255.255"> msg<input name=msg size=30>
<input type=submit value=add>
</form>
自动程序不会处理与以下白名单IP有关的端口，但web界面可以添加：<p>

<?php

$q="select ip,mask,msg from whitelist order by inet_aton(ip)";

$result = $mysqli->query($q);
echo "<table border=1 cellspacing=0><tr><th>IP</th><th>MASK</th><th>MSG</th>";
if( isset($_SESSION["isadmin"]) && ($_SESSION["isadmin"]==1)) 
	echo "<th>command</th>";
echo "</tr>\n";
while($r=$result->fetch_array()) {
	echo "<tr><td>";
	echo $r[0];
	echo "</td><td>";
	echo $r[1];
	echo "</td><td>";
	echo $r[2];
	echo "</td>";
	if( isset($_SESSION["isadmin"]) && ($_SESSION["isadmin"]==1)) {
		echo "<td><a href=whiteip.php?delip=$r[0]&delmask=$r[1]  onclick=\"return confirm('删除 $r[0]/$r[1] ?');\">删除</a></td>";
	}
	echo "</tr>\n";
}

echo "</table>";

?>
