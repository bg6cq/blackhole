<?php

include "top.php";

?>

<H3>科大黑洞流量统计图</H3>
<BODY bgColor=#ffffff>
<table bgcolor=#cccccc border cellpadding=2 cellspacing=0>
<tr><th>图形含义</th><th>eth0(内部)</th><th>eth1(外部)</th></tr>
<tr><td nowrap>3分钟</td>
<td><img src="/cgi-bin/traffic?dev=eth0&type=1"></td>
<td><img src="/cgi-bin/traffic?dev=eth1&type=1"></td>
</tr><tr><td nowrap>3小时</td>
<td><img src="/cgi-bin/traffic?dev=eth0&type=2"></td>
<td><img src="/cgi-bin/traffic?dev=eth1&type=2"></td>
</tr><tr><td nowrap>1.5天</td>
<td><img src="/cgi-bin/traffic?dev=eth0&type=3"></td>
<td><img src="/cgi-bin/traffic?dev=eth1&type=3"></td>
</tr><tr><td nowrap>15天</td>
<td><img src="/cgi-bin/traffic?dev=eth0&type=4"></td>
<td><img src="/cgi-bin/traffic?dev=eth1&type=4"></td>
</tr></table><p>
图形含义：<p>
3分钟的图中，每个点分别表示1秒钟的间隔内收、发数据包的个数以及比特。<br>
3小时的图中，每个点分别表示1分钟的间隔内，每秒钟平均收、发数据包的个数以及比特。<br>
1.5天的图中，每个点分别表示12分钟的间隔内，每秒钟平均收、发数据包的个数以及比特。<br>
15天的图中，每个点分别表示2小时的间隔内，每秒钟平均收、发数据包的个数以及比特。<br>


