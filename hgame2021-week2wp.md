---
title: hgame2021 -week 2
categories: 赛题wp
---
## web1-LazyDogR4U 
- 代码审计 变量覆盖

扫完目录www.zip 之后就被ban了，拿到源代码
<!--more-->
```bash
<?php

    if($_SESSION['username'] === 'admin'){
        echo "<h3 style='color: white'>admin将于今日获取自己忠实的flag</h3>";
        echo "<h3 style='color: white'>$flag</h3>";
    }else{
        if($submit == "getflag"){
            echo "<h3 style='color: white'>{$_SESSION['username']}接近了问题的终点</h3>";
        }else{
            echo "<h3 style='color: white'>篡位者占领了神圣的页面</h3>";
        }
    }
        ?>

```
$_SESSION['username'] === 'admin'  才能拿到flag

但是在 lazy.php 中会将 _GET 、 _POST 传⼊的变量全部注册为普通变量，造成了变量覆盖

```bash
<?php
$filter = ["SESSION", "SEVER", "COOKIE", "GLOBALS"];

// 直接注册所有变量，这样我就能少打字力，芜湖~

foreach(array('_GET','_POST') as $_request){
    foreach ($$_request as $_k => $_v){
        foreach ($filter as $youBadBad){
            $_k = str_replace($youBadBad, '', $_k);
        }
        ${$_k} = $_v;
    }
}

```
因为过滤替换为空
```
 Payload：flag.php?_SESSESSIONSION[username]=admin
```

---
## web2-Post to zuckonit
- xss的基本过滤与绕过

---
## web3-200ok！
- 基础sql语句以及基本过滤

![](https://img-blog.csdnimg.cn/20210215171152987.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
根据hint  bp抓包后发现修改status数值，返回值不一样，可能是sql注入且猜测返回字段数为1

查询数据库 发现返回为空

![](https://img-blog.csdnimg.cn/20210215171214339.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
猜测过滤空格等 /**/代替空格且大小写绕过 成功发现库

![](https://img-blog.csdnimg.cn/2021021517130187.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

查表名

![](https://img-blog.csdnimg.cn/20210215171309237.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

查列名

![](https://img-blog.csdnimg.cn/20210215171315196.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

查数据

![](https://img-blog.csdnimg.cn/20210215171320814.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## Misc1-tools
- 了解了四款图片隐写工具 F5、Steghide、Outguess、JPHS

F5隐写

![](https://img-blog.csdnimg.cn/20210215171454639.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

Steghide隐写

![](https://img-blog.csdnimg.cn/20210215171513253.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

Outguess

![](https://img-blog.csdnimg.cn/20210215171520261.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## Misc2-Telegraph
- 音频隐写

拖进au听一遍 选中莫斯密码部分导出 在线网站识别 稍微修改一下flag即可

[在线音频莫斯解密](https://morsecode.world/international/decoder/audio-decoder-adaptive.html)

![](https://img-blog.csdnimg.cn/2021021517170121.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## Misc-3 Hallucigenia
- base64转⼆进制、字节翻转

Stegsolve

![](https://img-blog.csdnimg.cn/2021021517211811.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

微信扫码


![](https://img-blog.csdnimg.cn/20210215172227520.png#pic_center)
![](https://img-blog.csdnimg.cn/20210215172241824.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## Misc4 DNS
- DNS流量分析、TXT记录

题目是DNS我们去找dns 

![](https://img-blog.csdnimg.cn/20210215172410339.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
看流量是访问了http://flag.hgame2021.cf 后面给了提示SPF

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210215172417365.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210215172433563.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210215172441456.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## wp
[hgame2021-week2 ](https://share.weiyun.com/bJg2FE11)
