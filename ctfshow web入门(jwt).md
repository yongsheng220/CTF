---
title: ctfshow web入门 (jwt)
categories: ctfshow
---
# 介绍
jwt由三部分组成header、payload、signature

header 示例
```
{
  'typ': 'JWT',
  'alg': 'HS256'
}
```

<!--more-->
payload 示例
```
{
  "sub": "1234567890",
  "name": "John Doe"
}
```
signature

jwt的第三部分是一个签证信息，这个签证信息由三部分组成：
```
header (base64编码)
payload (base64编码)
secret（密钥）
这个部分需要base64加密后的header和base64加密后的payload使用.连接组成的字符串，然后通过header中声明的加密方式进行加盐secret组合加密，然后就构成了jwt的第三部分。
```

# 345
![](https://img-blog.csdnimg.cn/20210518150949712.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
访问：url/admin/

因为如果访问/admin 是访问目录

访问/admin/ 是访问admin目录下的index.php jsp aspx

直接base64解码改为admin，再访问/admin/

# 346-347

![](https://img-blog.csdnimg.cn/20210518151026869.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
看不到了

去 jwt.io

![](https://img-blog.csdnimg.cn/20210518151049322.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
改内容，猜密钥为123456

# 348
爆破

![](https://img-blog.csdnimg.cn/20210518151113718.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

# 349-350
等学完node.js再来
