---
title: BeesCMS v4.0
categories: PHP代码审计
---
# 前言
前一段比赛，来审计一下

# 后台登录框sql注入
两个函数进行处理

![](https://img-blog.csdnimg.cn/9390d57f40ad4902a5be9ee36b3e232b.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

<!--more-->
跟进fl_value:

![](https://img-blog.csdnimg.cn/6e2cf7eac31e4271a0cb9b49353688e5.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
将特定字符过滤为空并返回，这里可以 `双写` 绕过呀，又跟着一个 `htmlspecialchars()` 函数进行处理

重点来了：

![](https://img-blog.csdnimg.cn/62f1468a478b4312b2b0d876ad6d2943.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/a038faf0e566431294a5647aaff7eedf.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
这里代码默认是不处理单引号的


接着进行函数处理：

![](https://img-blog.csdnimg.cn/982644abf4c24f3db601fb18103ee5da.png#pic_center)

跟进：这里构造了sql语句

![](https://img-blog.csdnimg.cn/460c1f502fb54cbdbc1f8a84ec6d72cd.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

接着跟进函数：

![](https://img-blog.csdnimg.cn/aea1a3445b334a65b0bcb26fc710d279.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

返回错误sql语句

![](https://img-blog.csdnimg.cn/71b86975f3504446bd2505bf7ddbaee5.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
利用：sql写webshell


修复：加上参数

![](https://img-blog.csdnimg.cn/0567afc33ac24db3ad11047a4103ced2.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

# 后台任意文件上传getshell
admin/upload.php

![](https://img-blog.csdnimg.cn/3aa0f320c5d14db689c7e3059a076619.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

跟进函数：

![](https://img-blog.csdnimg.cn/1f97e5e6c89e4f498666c2b17465e4d2.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/25e33b17909e4e97ab9258bb2e6deec8.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

# 前台登录绕过
upload.php中

![](https://img-blog.csdnimg.cn/f623dbebfeb64b43a76e13085837fdd3.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
看`admin/init.php`:检查登录

![](https://img-blog.csdnimg.cn/643d8389c139439e8f2d31ca812e039a.png#pic_center)
跟进：

![](https://img-blog.csdnimg.cn/93aca6a2c7094a34a0aba5bd55100924.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
这里并没有对用户信息做检查，只是单纯的判断了是否存在login_in admin这两个session标识位和是否超时而已

如果能覆盖(添加)这几个$_SESSION值 就能绕过这个检查

寻找可利用的文件：

`$_SESSION` 覆盖有个必须前提，session_start()必须出现在覆盖之前，不然就算覆盖了 `$_SESSION`变量，一旦session_start()  变量就会被初始化掉。

发现一处可利用地址：include/init.php

![](https://img-blog.csdnimg.cn/5c92916645da46c8987f6f75a0e23ed0.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
一个全局过滤的代码，最后用 `extract` 来初始化变量 由于没有使用 `EXTR_SKIP` 参数导致任意变量覆盖，又由于执行的时候已经 `session_start()` 了,所以可以覆盖（添加）任意 `$_SESSION` 值。

在`index.php`下可以进行利用:

![](https://img-blog.csdnimg.cn/d908202e37b847b8b67096af27e18948.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
断点看一下：

![](https://img-blog.csdnimg.cn/bd497da3c8464f8f9e32e3e0aa573a96.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
include/init.php:

![](https://img-blog.csdnimg.cn/1e26300bca7842b59f99f53041bd2edd.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
直接访问后台admin/admin.php:

![](https://img-blog.csdnimg.cn/aaf4424587554a92bcaa6c4d4b798d32.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
`admin/init.php` 进行检查登录

![](https://img-blog.csdnimg.cn/08c750d3da294d368ae19fad502bb19c.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
成功利用：

![](https://img-blog.csdnimg.cn/b8cb8521d0ed486cacb7242138fb11a9.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
这样我们可以前台登录绕过配合文件上传getshell
