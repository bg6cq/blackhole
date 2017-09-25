<?php

require_once('USTC_CAS.php');

session_start();

if(isset($_SESSION['isadmin']));
	 $_SESSION['isadmin']=0;
	 
$isadmin = $_SESSION['isadmin'];

if (!$isadmin) {
    $cas = ustc_cas_login();
    $user = $cas->user();
    $gid = $cas->gid();
}

echo "hello $user/$gid<p>";

if ( $gid == '3199700722') // james
	$_SESSION['isadmin']=1;
else if ( $gid == '1199305084')  // xyl
	$_SESSION['isadmin']=1;
else if ( $gid == '1200990253')  // chenlei2
	$_SESSION['isadmin']=1;

$isadmin = $_SESSION['isadmin'];

if(!$isadmin) {
	echo "you not allowed to login, contact james@ustc.edu.cn";	
} else {
	echo "you are logged in, please go <a href=/> here</a>.";
}
?>
