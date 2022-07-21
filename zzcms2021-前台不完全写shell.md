---
title: zzcms2021-前台不完全写shell
categories: 漏洞复现
---
﻿# 前言
zzcms 前台不完全写shell分析，先知社区看到的，跟一下漏洞
先知社区:[代码审计-zzcms2021前台写shell?](https://xz.aliyun.com/t/10432)

# 分析
漏洞发生处：
/3/ucenter_api/api/uc.php

![](https://img-blog.csdnimg.cn/2c8ac3ec3d9d458c8f7f450e359e7b0f.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

<!--more-->
以get方式传入一个code参数

然后执行_authcode方法 传入DECODE 再存入$get数组中

跟进_authcode方法

![](https://img-blog.csdnimg.cn/8a68706a21094b4fbda0620dd74be39e.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

是一个加密方法，这里传入的是UC_KEY

搜索一下：定值为123456

![](https://img-blog.csdnimg.cn/28452f2bd19d4a4fbf3e40bf8a2d61a9.png#pic_center)

根据下面的参数知道$get数组中有time 和action，且有一个超时判断

![](https://img-blog.csdnimg.cn/04221b02bfbd4925841fe93acf4906a5.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

接着往下：
无过滤的利用php://input伪协议读取post过去的内容存到$post参数中

然后执行xml_unserialize

![](https://img-blog.csdnimg.cn/fb213d87e06d4873868d28ba08ea1041.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

如果action在特定的数组中，实例化uc_note，然后以$get $post为参数执行action方法

看一下uc_note中有什么可利用的方法，在uppdateapps方法中：

![](https://img-blog.csdnimg.cn/6d8d2876d54342fdba75855a5497aa35.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

第一处限制$post中有UC_API

然后执行一个正则
```php
preg_replace("/define\('UC_API',\s*'.*?'\);/i", "define('UC_API', '$UC_API');", $configfile);
```

将传入的API参数去覆盖掉原来写好的代码

![](https://img-blog.csdnimg.cn/7a1bc7ec4776412d9f351739b94ee540.png#pic_center)

也就是覆盖掉这一处 但是这里存在一个问题，正则的时候，最后的一个 `;` 与括号是挨着的，但是原文件里是存在一个空格的，这就导致了正则无法匹配，所以无法写入

不过这里试一试 `修改正则或者原文件的 ; 都可以`

![](https://img-blog.csdnimg.cn/ceb607edb06b4c4dae843d0e408fd7fe.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

利用方法，传入参数，得到code加密

传入payload
```
<?xml version="1.0" encoding="ISO-8859-1"?>
<root>
	<item id="UC_API">')echo phpinfo();//</item>
</root>
```

![](https://img-blog.csdnimg.cn/9ec9f759233f42df8a8421eb6fe31a50.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

写入成功

![](https://img-blog.csdnimg.cn/23c0d2d1008c46629a42682187297022.png#pic_center)
![](https://img-blog.csdnimg.cn/05750cbad33248d987112423f091ac55.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

