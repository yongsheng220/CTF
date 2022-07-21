---
title: DVWA
categories: 
---
## Brute Force
### low
1.爆破

![](https://img-blog.csdnimg.cn/20210313171349254.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
<!--more-->
2.sql：
看源码：

```bash
$qry = "SELECT * FROM `users` WHERE user='$user' AND password='$pass';";
```
因为 and 优先级比 or 高
当构造：`admin’ or ‘`  时其实语句为：

```bash
“SELECT * FROM `users` WHERE user='admin’or (‘' AND password='$pass';")
```

所以密码随便输入或者不输入就行，只需要满足user存在即可

---
### Medium
抓包爆破

---
### High
增加登陆失败延时
爆破时很慢


---
## Command Execution
### low
![](https://img-blog.csdnimg.cn/20210313171556125.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

就是
; | || & &&命令

---
###	Medium
过滤了 ;  &&

---
## SQL Injection
### low
![](https://img-blog.csdnimg.cn/20210313171645382.png#pic_center)
无过滤

---
### Medium
数字型注入

1 or 1=1#

---


