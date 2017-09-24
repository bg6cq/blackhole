<?php

include "top.php";

if( isset($_SESSION["isadmin"]) && ($_SESSION["isadmin"]==1))  {
        if(isset($_REQUEST["del"]))  {   //delistip
                $del= $_REQUEST["del"];
                if($del!="") {
                        $q="delete from http_info where url=?";
                        $stmt=$mysqli->prepare($q);
                        $stmt->bind_param("s",$del);
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
}

@$s=$_REQUEST["s"];
$q="select url,substr(server,1,40), substr(soft,1,40),tag,lastcheck from http_info order by url";
if($s=="s")
	$q="select url,substr(server,1,40),substr(soft,1,40),tag,lastcheck from http_info order by server desc";
else if($s=="o")
	$q="select url,substr(server,1,40),substr(soft,1,40),tag,lastcheck from http_info order by soft ddesc";
else if($s=="t")
	$q="select url,substr(server,1,40),substr(soft,1,40),tag,lastcheck from http_info order by tag desc";
else if($s=="l")
	$q="select url,substr(server,1,40),substr(soft,1,40),tag,lastcheck from http_info order by lastcheck desc";
$result = $mysqli->query($q);
echo "<table border=1 cellspacing=0>";
echo "<tr><th>序号</th><th><a href=httpinfo.php>URL</a></th><th><a href=httpinfo.php?s=s>Server</a></th><th><a href=httpinfo.php?s=o>soft</a></th>";
echo "<th><a href=httpinfo.php?s=t>tag</a></th><th><a href=httpinfo.php?s=l>LastCheck</a></th>";
if( isset($_SESSION["isadmin"]) && ($_SESSION["isadmin"]==1))
        echo "<th>cmd</th>";
echo "</tr>\n";
$count=0;
while($r=$result->fetch_array()) {
	$count++;
	echo "<tr><td align=center>";
	echo $count;
	echo "</td><td>";
	echo "<a href=".$r[0]." target=_blank>".$r[0]."</a>";
	echo "</td><td>";
	echo $r[1];
	echo "</td><td>";
	echo $r[2];
	echo "</td><td>";
	echo $r[3];
	echo "</td><td>";
	echo $r[4];
	echo "</td>";
        if( isset($_SESSION["isadmin"]) && ($_SESSION["isadmin"]==1)) {
                echo "<td><a href=httpinfo.php?del=$r[0]  onclick=\"return confirm('删除 $r[0]/$r[4]/$r[5] ?');\">删除</a></td>";
        };
	echo "</tr>\n";
}
echo "</table>";

?>

