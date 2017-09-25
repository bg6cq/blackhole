<?php

include "top.php";

function addblackholeip($ip, $day, $prot, $port, $msg)
{
	global $mysqli;
	$q="select count(*) from mylist where inet_aton(ip) = (inet_aton(?) & inet_aton(mask))";
	$stmt=$mysqli->prepare($q);
        $stmt->bind_param("s",$ip);
        $stmt->execute();
	$stmt->bind_result($count);
	$stmt->fetch();
	$stmt->close();
	if($count==0)  {
		echo "Error: IP ".$ip." not in mylist, check your input\n";
		return;
	}
	$q="select count(*) from whitelist where inet_aton(ip) = (inet_aton(?) & inet_aton(mask))";
	$stmt=$mysqli->prepare($q);
        $stmt->bind_param("s",$ip);
        $stmt->execute();
	$stmt->bind_result($count);
	$stmt->fetch();
	$stmt->close();
	if($count>0)   {
		echo "Error: IP ".$ip." in whitelist\n";
		return;
	}
	$q="select count(*) from blackip where prefix = ? and len=32 and prot=? and port=? and status='added'";
	$stmt=$mysqli->prepare($q);
        $stmt->bind_param("ssi",$ip,$prot,$port);
        $stmt->execute();
	$stmt->bind_result($count);
	$stmt->fetch();
	$stmt->close();
	if($count>0)   {
		echo "IP ".$ip." in blacklist, skip\n";
		return;
	}
	echo "Adding ".$ip; echo "\n";
        $q = "insert into blackip (status,prefix,len,start,end,prot,port,msg) values ('adding',?,32,now(),date_add(now(),interval ? day),?,?,?)";
        $stmt=$mysqli->prepare($q);
        $stmt->bind_param("sisis",$ip,$day,$prot,$port,$msg);
        $stmt->execute();
}

echo "auto blockip<p>";
echo "<pre>";
$count = 0;
$q="select url, tag from http_info where lastcheck > date_sub(now(), interval 1 hour) and (tag ='ipmi' or tag ='hpprinter' or tag like '%ipcam' or tag = 'lenovo' )";
$result = $mysqli->query($q);
while($r=$result->fetch_array()) {
	if(strstr($r[0],"http://"))
		$ip = substr($r[0],7,30);
	else if(strstr($r[0],"https://"))
		$ip = substr($r[0],8,30);
	
	echo "block ip ".$ip; echo "\n";
	if(strpos($ip,":")>0)  {
		echo "port ip ";
		$ip=substr($ip,0,strpos($ip,":"));
		echo $ip; echo "\n";
	}

	addblackholeip($ip, 1, "all", 0, $r[1]);
	$count++;
}

?>

