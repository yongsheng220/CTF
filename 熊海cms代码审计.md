---
title: 熊海cms代码审计
categories: PHP代码审计
---
# 前言
很多天没看代码了，作为菜鸡的我当然要继续练习审计，very easy

# SQL1
![](https://img-blog.csdnimg.cn/8281df16dff046c1960051055e32ee35.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

<!--more-->
r接受参数
在files/content.php  files/software.php

![](https://img-blog.csdnimg.cn/bb7154e0e72942e79546912f8c5ab040.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
虽然有addslashes 但是浏览计数这里没有单引号闭合，报错注入
?r=content&cid=1 or updatexml(1,concat(0x7e,(select database()),0x7e),1)


# SQL2
files/submit.php mail参数没有过滤
![](https://img-blog.csdnimg.cn/8761230f55ed48edbcb08733c19a7044.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
![](https://img-blog.csdnimg.cn/70ea4e4fb1c74a2e8a6a23a7c385dd2e.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
admin/files/editlink.php

![](https://img-blog.csdnimg.cn/ce433b53f1094f1aa55174c78dec0229.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
# SQL3
![](https://img-blog.csdnimg.cn/3e09f08207a84bc8bc20c7c02b40ce59.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
传入的参数没有进行过滤

这点就是利用union select 出来一个虚拟的一行参数，然后导致password处md5可控
![](https://img-blog.csdnimg.cn/8cc156139bf443fd8c726f258115ddd0.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
# 越权
checkadmin.php 这是什么？？裸奔了

![](https://img-blog.csdnimg.cn/2165d736eeff4e0a809fca043fe34e77.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_16,color_FFFFFF,t_70,g_se,x_16#pic_center)
加一个cookie头，直接进后台了
![](https://img-blog.csdnimg.cn/69e6f278f0ba4376970a3494acab0858.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_15,color_FFFFFF,t_70,g_se,x_16#pic_center)
# XSS
files/list.php  files/download.php
![](https://img-blog.csdnimg.cn/a6a7cefcf57240558d187df92f3996e3.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
可控，直接输出
![](https://img-blog.csdnimg.cn/e72b2cbe6e0b43f4beeb150d22f05be6.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
提交评论时：
![](https://img-blog.csdnimg.cn/cfd4e31df8db46f2ac53acb1c088bc1c.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
很多参数没有进行过滤
![](https://img-blog.csdnimg.cn/03a283c5fcb7449e9d96ac10e42f3402.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
然后进行一个insert

在展示评论的时候：
![](https://img-blog.csdnimg.cn/eb4720026b84409488ea8dfc2a3e1e23.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
从sql取出结果存入$pinglun中，然后就name进行了输出
直接name整个xss

