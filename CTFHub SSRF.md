---
title: CTFHub SSRF
categories: ctf题目
---


![](https://img-blog.csdnimg.cn/20210404114641950.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)

<!--more-->
---
# 内网访问
- 尝试访问位于127.0.0.1的flag.php吧

![](https://img-blog.csdnimg.cn/20210404114757832.png#pic_center)
Payload：
```
?url=127.0.0.1/flag.php
```


---
# 伪协议读取文件
- 尝试去读取一下Web目录下的flag.php

根据题目的意思我们需要使用URL的伪协议去读取文件，那么我们首先要了解`URL的伪协议`
URL伪协议有如下这些：[SSRF中的URL伪协议](https://www.cnblogs.com/-mo-/p/11673190.html)
```
file:///
dict://
sftp://
ldap://
tftp://
gopher://
```

用file读取 , Payload：
```
?url=file:///var/www/html/flag.php
```

---
# 端口扫描
题目提示端口在8000-9000，因此直接扫就可以了。这里我们需要使用`dict伪协议`来扫描，因为dict协议可以用来探测开放的端口。

```
?url=dict://127.0.0.1:8922   
```
![](https://img-blog.csdnimg.cn/20210404115651941.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
```
?url=127.0.0.1:8922
```
![](https://img-blog.csdnimg.cn/20210404115710581.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# URL Bypass
url解析问题
url跳转bypass：
```
1.利用问好绕过限制url=https://www.baidu.com?www.xxxx.me
2.利用@绕过限制url=https://www.baidu.com@www.xxxx.me
3.利用斜杠反斜杠绕过限制
4.利用#绕过限制url=https://www.baidu.com#www.xxxx.me
5.利用子域名绕过
6.利用畸形url绕过
7.利用跳转ip绕过
```

![](https://img-blog.csdnimg.cn/20210404115932888.png#pic_center)

Payload：
```
?url=http://notfound.ctfhub.com@127.0.0.1/flag.php
```

---
# IP Bypass
- Ip进制转换

![](https://img-blog.csdnimg.cn/20210404120022591.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
payload:
```
127.0.0.1可以替换为:
十六进制：0x7F000001
十进制:  2130706433
或 localhost
```

php脚本：

```php
<?php
$ip = '127.0.0.1';
$ip = explode('.',$ip);
$r = ($ip[0] << 24) | ($ip[1] << 16) | ($ip[2] << 8) | $ip[3] ;
if($r < 0) {
$r += 4294967296;
}
echo "十进制:";
echo $r;
echo "八进制:";
echo decoct($r);
echo "十六进制:";
echo dechex($r);
?>
```


---
# 302跳转bypass


访问http://127.0.0.1/flag.php
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021040412194198.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)

在网络上存在一个很神奇的服务，网址为 `http://xip.io`，当访问这个服务的任意子域名的时候，都会重定向到这个子域名，举个例子：

>当我们访问 http://127.0.0.1.xip.io/flag.php，那么实际上我们访问的是就 http://127.0.0.1/flag.php。

试了一下失败

还有一个302跳转的方法，即利用短地址跳转绕过，这里也给出一个网址: [https://4m.cn/](https://4m.cn/)

![](https://img-blog.csdnimg.cn/20210404122421202.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)

访问得到flag
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210404122442913.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


---
# DNS重绑定DNS Rebinding攻击

>在网页浏览过程中，用户在地址栏中输入包含域名的网址。浏览器通过DNS服务器将域名解析为IP地址，然后向对应的IP地址请求资源，最后展现给用户。而对于域名所有者，他可以设置域名所对应的IP地址。当用户第一次访问，解析域名获取一个IP地址；然后，域名持有者修改对应的IP地址；用户再次请求该域名，就会获取一个新的IP地址。对于浏览器来说，整个过程访问的都是同一域名，所以认为是安全的。这就造成了DNS Rebinding攻击。

基于这个攻击原理，Kali Linux提供了对应的工具Rebind。该工具可以实现对用户所在网络路由器进行攻击。当用户访问Rebind监听域名，Rebind会自动实施DNS Rebinding攻击，通过用户的浏览器执行js脚本，建立socket连接。这样，Rebind可以像局域网内部用户一样，访问路由器，从而控制路由器。

1.攻击者控制恶意的DNS服务器来回复域的查询,如rebind.network

2.攻击者通过一些方式诱导受害者加载http://rebind.network

3.用户打开链接,浏览器就会发出DNS请求查找rebind.network的IP地址

4.恶意DNS服务器收到受害者的请求,并使用真实IP地址进行响应,并将TTL值设置为1秒,让受害者的机器缓存很快失效

5.从http://rebind.network加载的网页包含恶意的js代码,构造恶意的请求到http://rebind.network/index,而受害者的浏览器便在执行恶意请求

6.一开始的恶意请求当然是发到了攻击者的服务器上,但是随着TTL时间结束,攻击者就可以让http://rebind.network绑定到别的IP,如果能捕获受害者的一些放在内网的应用IP地址,就可以针对这个内网应用构造出对应的恶意请求,然后浏览器执行的恶意请求就发送到了内网应用,达到了攻击的效果


dns解析

![](https://img-blog.csdnimg.cn/20210404125704543.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

这是一个测试dns重绑定漏洞的网站,可以让一个域名随机的绑定两个IP 

[https://lock.cmpxchg8b.com/rebinder.html](https://lock.cmpxchg8b.com/rebinder.html)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210404125802745.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)

访问过程中会不断出现以下报错，这是因为这个域名是不断的在127.0.0.1与xxx.xxx.xxx.xxx之间跳动的，所以要不断访问数次

[浅谈DNS重绑定漏洞](https://zhuanlan.zhihu.com/p/89426041)

---
# Redis协议和FastCGI协议
这两道按着wp没弄出来，先去刷ctfshow，再回来试试吧

[Redis在SSRF中的应用](https://sec.thief.one/article_content?a_id=3c0250e0cbc5180cf95bba5002385533)


[浅析Redis中SSRF的利用](https://xz.aliyun.com/t/5665)

工具：Gopherus
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210404143514135.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


---
# 参考
[我在CTFHub学习SSRF](https://www.freebuf.com/articles/web/258365.html)

[CTFHub-SSRF部分（已完结）](https://blog.csdn.net/rfrder/article/details/108589988)

