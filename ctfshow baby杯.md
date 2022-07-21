---
title: ctfshow baby杯
categories: 赛题wp
---
# 完美的缺点

<!--more-->
```php
<?php
highlight_file(__FILE__);
error_reporting(0);
ini_set('open_basedir', '/var/www/html/');

$file_name = substr($_GET['file_name'], 0,16);
$file_content=substr($_GET['file_content'], 0,32);

file_put_contents('/c/t/f/s/h/o/w/'.$file_name, $file_content);

if(file_get_contents('php://input')==='ctfshow'){
    include($file_name);
}
```

ini_set()用来设置php.ini的值，在函数执行的时候生效，脚本结束后，设置失效。无需打开php.ini文件，就能修改配置。函数用法如下:
```php
ini_set ( string $varname , string $newvalue ) : string
```

`Open_basedir`是PHP设置中为了`防御PHP跨目录进行文件（目录）读写的方法`，`所有PHP中有关文件读、写的函数都会经过open_basedir的检查。`

Open_basedir实际上是`一些目录的集合`，在定义了open_basedir以后，php可以读写的文件、目录都`将被限制在这些目录中`

 一般情况下，我们最多可以绕过open_basedir的限制对其进行列目录。绕过open_basedir进行读写文件危害较大，在php5.3以后很少有能够绕过open_basedir读写文件的方法。

---
思路：所以首先限制了读写目录，对参数file_name长度进行限制，看到file_put_contents更改了目录，所以写文件已经不可能了，只能用到include

想到伪协议 学习到了data的新姿势

![](https://img-blog.csdnimg.cn/20210605210946779.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
所以构造：
```
file_name=data;,<?=`nl *`;
```
正好16长度

![](https://img-blog.csdnimg.cn/20210605211010440.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


---

# Baby_php

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2021-05-31 13:40:37
# @Last Modified by:   h1xa
# @Last Modified time: 2021-05-31 16:36:27
# @email: h1xa@ctfer.com
# @link: https://ctfer.com

*/


error_reporting(0);

class fileUtil{

    private $name;
    private $content;


    public function __construct($name,$content=''){
        $this->name = $name;
        $this->content = $content;
        ini_set('open_basedir', '/var/www/html');
    }

    public function file_upload(){
        if($this->waf($this->name) && $this->waf($this->content)){
            return file_put_contents($this->name, $this->content);
        }else{
            return 0;
        }
    }

    private function waf($input){
        return !preg_match('/php/i', $input);
    }

    public function file_download(){
        if(file_exists($this->name)){
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="'.$this->name.'"');
            header('Content-Transfer-Encoding: binary');
            echo file_get_contents($this->name);
        }else{
            return False;
        }
    }

    public function __destruct(){

    }

}

$action = $_GET['a']?$_GET['a']:highlight_file(__FILE__);

if($action==='upload'){
    die('Permission denied');
}

switch ($action) {
    case 'upload':
        $name = $_POST['name'];
        $content = $_POST['content'];
        $ft = new fileUtil($name,$content);
        if($ft->file_upload()){
            echo $name.' upload success!';
        }
        break;
    case 'download':
        $name = $_POST['name'];
        $ft = new fileUtil($name,$content);
        if($ft->file_download()===False){
            echo $name.' download failed';
        }
        break;
    default:
        echo 'baby come on';
        break;
}
```

源码看得懂
三目运算符那里:
```
var_dump(highlight_file(__FILE__));
得到：bool(true)
```

如果对`$_GET['a']不进⾏赋值`，则默认值为`true`

所以$action=true，进入switch语句
```
var_dump(true=='upload'); 
得到bool(true)
```
所以进入fileUtil

上传2.txt写上一句话，再上传.user.ini指向2.txt，访问 index.php执行语句

![](https://img-blog.csdnimg.cn/20210605211317796.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


---
# 应该不难

![](https://img-blog.csdnimg.cn/20210605211353963.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
[Discuz!X 3.4 任意文件删除配合install过程getshell](https://www.zhihuifly.com/t/topic/2879)

---
# Ctfshowcms
目录结构：

![](https://img-blog.csdnimg.cn/20210605211505123.png#pic_center)
data/settings.php
```php
<?php
$DB_HOST='127.0.0.1:3306';
$DB_USER='feng';
$DB_PWD='feng';
$DB_NAME='ctfshow';
?>
```

index.php
```php
<?php

define("ROOT_PATH",__DIR__);

error_reporting(0);

$want = addslashes($_GET['feng']);
$want = $want==""?"index":$want;

include('files/'.$want.".php");
```

install/index.php

```php
<?php
header('Content-Type:text/html;charset=utf-8');
if(file_exists("installLock.txt")){
    echo "你已经安装了ctfshowcms，请勿重复安装。";
    exit;
}

echo "欢迎安装ctfshowcms~"."<br>";


$user=$_POST['user'];
$password=md5($_POST['password']);
$dbhost=$_POST['dbhost'];
$dbuser=$_POST['dbuser'];
$dbpwd=$_POST['dbpwd'];
$dbname=$_POST['dbname'];
if($user==""){
    echo "CMS管理员用户名不能为空！";
    exit();
}
if($password==""){
    echo "CMS管理员密码不能为空！";
    exit();
}
if($dbhost==""){
    echo "数据库地址不能为空！";
    exit();
}
if($dbuser==""){
    echo "数据库用户名不能为空！";
    exit();
}
if($dbpwd==""){
    echo "数据库密码不能为空！";
    exit();
}
if($dbname==""){
    echo "数据库名不能为空！";
    exit();
}
// 连接数据库
$db = mysql_connect ( $dbhost, $dbuser, $dbpwd )  or die("数据库连接失败");

// 选择使用哪个数据库
$a = mysql_select_db ( $dbname, $db );
// 数据库编码方式
$b = mysql_query ( 'SET NAMES ' . 'utf-8', $db );

if(file_exists("ctfshow.sql")){
    echo "正在写入数据库！";
}else{
    die("sql文件不存在");
}

$content = "<?php
\$DB_HOST='".$dbhost."';
\$DB_USER='".$dbuser."';
\$DB_PWD='".$dbpwd."';
\$DB_NAME='".$dbname."';
?>
";


file_put_contents(ROOT_PATH."/data/settings.php",$content);
echo "数据库设置写入成功！~"."<br>";

$of = fopen(ROOT_PATH.'/install/installLock.txt','w');
if($of){
    fwrite($of,"ctfshowcms");
}
echo "安装成功！";
```

指向files/index.php，存在文件包含

![](https://img-blog.csdnimg.cn/20210605211712544.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
直接访问`install/index.php`是不行的，该目录下存在installLock.txt，所以尝试在`index.php下包含install/index.php`，可行

![](https://img-blog.csdnimg.cn/20210605211748898.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
如果想利用这个`file_put_contents`写马到`settings.php`是一种思路，但是上面有限制：

![](https://img-blog.csdnimg.cn/202106052118350.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
因为我们是include来的二次安装，所以在现在的目录下并不存在ctfshow.sql文件所以直接会die

那么能利用的就是：任意连接数据库

![](https://img-blog.csdnimg.cn/20210605211915380.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
存在⼀个数据库任意连接的问题，可以构造⼀个恶意的mysql客户端来读取任意文件。


参考文章：[MySQL 服务端恶意读取客户端任意文件漏洞](https://www.modb.pro/db/51823)

正好学习了mysql

新建一个test1库:
```
CREATE DATABASE test1;
```
![](https://img-blog.csdnimg.cn/20210605212054172.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
新建一个2@host的用户:
```
CREATE USER '2'@'host' IDENTIFIED BY '2';
```

![](https://img-blog.csdnimg.cn/20210605212113683.png#pic_center)
赋权，设置可以任意ip连接，刷新:
```
GRANT ALL ON test1.* TO '2'@'host';
update user set host = '%' where user = '2' limit 1;
flush privileges;
```

![](https://img-blog.csdnimg.cn/20210605212201275.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
记得注释：

![](https://img-blog.csdnimg.cn/20210605212215789.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
继续：

![](https://img-blog.csdnimg.cn/20210605212226766.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
因为我还开了一个mysql，所以设置恶意mysql端口为3307，

`User，pwd，name都为1`

![](https://img-blog.csdnimg.cn/20210605212254996.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
cat log:

![](https://img-blog.csdnimg.cn/20210605212313336.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# baby_captcha
听一个验证码，登陆时有一个302，拦截爆破密码

![](https://img-blog.csdnimg.cn/20210605212342269.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


