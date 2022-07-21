---
title: CTFHub 文件上传
categories: ctf题目
---
![](https://img-blog.csdnimg.cn/20210311225714341.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

<!--more-->
---
## 无验证
![](https://img-blog.csdnimg.cn/20210311225734667.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## 前端验证
上传png 抓包修改为php修改成功

---
## 文件头检测
添加GIF89A即可上传抓包改后缀

---
## .htaccess
有两个版本

一、
```
AddType application/x-httpd-php .jpg  此题失败
```

二、
```
<FilesMatch "(任意后缀)">
setHandler application/x-httpd-php
</FilesMatch>

```
再上传一句话文件

蚁剑即可

---
## mime 绕过


>MIME(Multipurpose Internet Mail Extensions)多用途互联网邮件扩展类型。
>是设定某种扩展名的文件用一种应用程序来打开的方式类型，当该扩展名文件被访问的时候，浏览器会自动使用指定应用程序来打开。
>多用于指定一些客户端自定义的文件名，以及一些媒体文件打开方式。

当上传php文件时 `content-type` 会出现`octet-stream`

![](https://img-blog.csdnimg.cn/20210311230053143.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
修改content-type 即可

![](https://img-blog.csdnimg.cn/20210311230113477.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## 00截断
%00截断上传漏洞 php 版本<5.3.4  文件上传绕过之00截断：

[详细原理及其运用](https://blog.csdn.net/weixin_44840696/article/details/90581104)

打开得到：

```bash
if (!empty($_POST['submit'])) {
    $name = basename($_FILES['file']['name']);
    $info = pathinfo($name);
    $ext = $info['extension'];
    $whitelist = array("jpg", "png", "gif");
    if (in_array($ext, $whitelist)) {
        $des = $_GET['road'] . "/" . rand(10, 99) . date("YmdHis") . "." . $ext;
        if (move_uploaded_file($_FILES['file']['tmp_name'], $des)) {
            echo "<script>alert('上传成功')</script>";
        } else {
            echo "<script>alert('上传失败')</script>";
        }
    } else {
        echo "文件类型不匹配";
    }
}

```

![](https://img-blog.csdnimg.cn/2021031123030371.png#pic_center)

我们上传的文件经过 `des` 的变化 被储存 且更改文件名

![](https://img-blog.csdnimg.cn/20210311230330893.png#pic_center)

如果我们 在url road处添加%00（ascii对应null）就会截断后面一切

所以就储存在12.php

![](https://img-blog.csdnimg.cn/2021031123034882.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


---
## 双写绕过

得到：

```bash
<!--
$name = basename($_FILES['file']['name']);
$blacklist = array("php", "php5", "php4", "php3", "phtml", "pht", "jsp", "jspa", "jspx", "jsw", "jsv", "jspf", "jtml", "asp", "aspx", "asa", "asax", "ascx", "ashx", "asmx", "cer", "swf", "htaccess", "ini");
$name = str_ireplace($blacklist, "", $name);
-->

```
会将黑名单替换为空

![](https://img-blog.csdnimg.cn/20210311230513940.png#pic_center)

双写后缀  `22.pphphp`  蚁剑



