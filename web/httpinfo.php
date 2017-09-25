<?php

include "top.php";

if(! isset($_SESSION["isadmin"]))
	exit(0);

if($_SESSION["isadmin"]!=1)
	exit(0);

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
}

if(isset($_REQUEST["tag"])) {
	$q = "select count(*), tag from http_info group by tag";
$result = $mysqli->query($q);
echo "<table border=1 cellspacing=0>";
echo "<tr><th>序号</th><th>tag</th><th>数量</th></tr>";
$count=0;
$total=0;
while($r=$result->fetch_array()) {
	$count++;
	echo "<tr><td align=center>";
	echo $count;
	echo "</td><td>";
	echo $r[1];
	echo "</td><td>";
	echo $r[0];
	echo "</tr>";
	$total += $r[0];
}
echo "<tr><td colspan=2>ALL</td><td>";
echo $total;
echo "</td></tr>";
echo "</table>";
	exit(0);
}

@$str=$_REQUEST["str"];

?>

<form action=httpinfo.php>Filter:<input name=str value="<?php echo $str;?>"><input type=submit name=filter> <input type=submit name=tag value="按tag统计"></form>

<?php
@$s=$_REQUEST["s"];
if($str<>"") {
	$str2 = '%'.$str.'%';
	$filter = " where url like '".$str2."' or server like '".$str2."' or soft like '".$str2."' or tag like '".$str2."'";
} else $filter = "";

$q="select url,substr(server,1,40), substr(soft,1,40),tag,lastcheck from http_info ".$filter." order by url";
if($s=="s")
	$q="select url,substr(server,1,40),substr(soft,1,40),tag,lastcheck from http_info ".$filter." order by server desc";
else if($s=="o")
	$q="select url,substr(server,1,40),substr(soft,1,40),tag,lastcheck from http_info ".$filter." order by soft desc";
else if($s=="t")
	$q="select url,substr(server,1,40),substr(soft,1,40),tag,lastcheck from http_info ".$filter." order by tag desc";
else if($s=="l")
	$q="select url,substr(server,1,40),substr(soft,1,40),tag,lastcheck from http_info ".$filter." order by lastcheck desc";
$result = $mysqli->query($q);
echo "<table border=1 cellspacing=0>";
echo "<tr><th>序号</th><th><a href=httpinfo.php?str=$str>URL</a></th><th><a href=httpinfo.php?s=s&str=$str>Server</a></th><th><a href=httpinfo.php?s=o&str=$str>soft</a></th>";
echo "<th><a href=httpinfo.php?s=t&str=$str>tag</a></th><th><a href=httpinfo.php?s=l&str=$str>LastCheck</a></th>";
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
                echo "<td><a href=httpinfo.php?del=$r[0]  onclick=\"return confirm('删除 $r[0] ?');\">删除</a></td>";
        };
	echo "</tr>\n";
}
echo "</table>";

?>

