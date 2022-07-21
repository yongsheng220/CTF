---
title: 9CCMS 辣椒CMS 代码审计
categories: PHP代码审计
---

# 前言
颜色网站，无数据交互，所以无sql注入，js和php配合写的网站，漏洞较多，比较简单，毕竟新人刚开始，加油

# XSS
## 前台反射型XSS
/Static/Home/VideoJS/index.php

![](https://img-blog.csdnimg.cn/20210711202756411.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
<!--more-->
跟进函数

![](https://img-blog.csdnimg.cn/20210711202912196.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
`stripslashes  删除反斜线`

`htmlspecialchars  把预定义的字符  "<" （小于）和 ">" （大于）转换为 HTML 实体`

而参数 play 本身就在 script 标签中，所以就不需要 < 和 >，只要将前后闭合即可触发XSS

Payload:  `1';alert(1);' `

这里说一下自己的测试来解释payload：

新建 1.php 这里为 php 文件！

![](https://img-blog.csdnimg.cn/20210711203325139.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
运行发现自动添加单引号

![](https://img-blog.csdnimg.cn/20210711203346265.png#pic_center)
这也就解释为什么payload有单引号了：

![](https://img-blog.csdnimg.cn/20210711203403759.png#pic_center)

---

# Getshell
## 后端直接写马
/Php/Admin/Home/Ad/Adjs.php
/Php/Admin/Home/Basic/Statistics.php

![](https://img-blog.csdnimg.cn/20210711203506819.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210711203518306.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

## 修改密码写马
php/admin/home/security/userpass.php

![](https://img-blog.csdnimg.cn/2021071120361241.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
这里直接拼接

Payload: `');eval($_POST[shell]);//`


---
# 辣椒CMS
添加广告处有变化

![](https://img-blog.csdnimg.cn/20210711203746804.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
提交的广告以 `lmjs` 参数提交，include了`class_txttest_js.php`

跟踪一下：

![](https://img-blog.csdnimg.cn/2021071120382289.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
New 触发__construct()，将 `$ad_top_json_url` 带进 TxtDB 类，跟踪一下 `$ad_top_json_url` 发现 `$ad_top_json_url=JCCMS_ROOT."ad/ad_js/ad.json";` 再通过`alter` 方法写入到 json 文件

![](https://img-blog.csdnimg.cn/20210711203958882.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
这里很多include函数，比如在主界面

![](https://img-blog.csdnimg.cn/20210711204023647.png#pic_center)
跟踪cllass_ad_js.php

![](https://img-blog.csdnimg.cn/20210711204037764.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
发现都是通过include来调用



