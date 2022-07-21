---
title: CTFHub 信息泄露
categories: ctf题目
---
## 信息泄露
![](https://img-blog.csdnimg.cn/20210309230320467.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

<!--more-->
---
## 目录遍历
一个一个找

---
## phpinfo
进去时phpinfo 搜索ctfhub

---
## 备份文件下载

![](https://img-blog.csdnimg.cn/20210309230445984.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
1.网站源码

![](https://img-blog.csdnimg.cn/20210309230503949.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
Dir扫到www.zip

下载后

![](https://img-blog.csdnimg.cn/20210309230601148.png#pic_center)
访问/flag_650819433.txt

---
2.bak文件

访问index.php.bak

---
3.vim缓存

访问  /.index.php.swp

---
4.DS_Store

`.DS_Store` 是 Mac OS 保存文件夹的自定义属性的隐藏文件。通过.DS_Store可以知道这个目录里面所有文件的清单。

访问：index.php/.DS_Store下载后Kali打开：


![](https://img-blog.csdnimg.cn/20210309230905925.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
访问2e080071c13c2540912270d99ea33a95.txt


---
## Git泄露
![](https://img-blog.csdnimg.cn/20210309230936566.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

1.log

dir扫一下

![](https://img-blog.csdnimg.cn/20210309231009196.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
githack 一下：

![](https://img-blog.csdnimg.cn/20210309231023916.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
使用 `git log` 查看`历史记录`：

![](https://img-blog.csdnimg.cn/20210309231055448.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
当前所处的版本为 remove flag，flag 在 add flag 这次提交中 与 add flag c2b5f5…… `这次提交进行比对`:
`git diff c2b5f5……` :

![](https://img-blog.csdnimg.cn/20210309231123600.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

2.stash

githack之后：
发现stash文件

![](https://img-blog.csdnimg.cn/20210309231150521.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

```bash
git stash list
git stash pop
```

![](https://img-blog.csdnimg.cn/2021030923121726.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

发现目录多了一个txt：

![](https://img-blog.csdnimg.cn/20210309231229628.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
[stash](https://blog.csdn.net/qq_46222050/article/details/108221042)

---
3.index
```bash
 git log 
 git diff ……
```


---
## svn 泄露
安装dvcs-ripper

```bash
./rip-svn.pl -v -u http://challenge-18e7006170a7b79d.sandbox.ctfhub.com:10080/.svn/
```

缺少库就没进行下去

---
## HG泄露

```bash
./rip-hg.pl -v -u http://challenge-8f6fef67e7887256.sandbox.ctfhub.com:10080/.hg/
```

![](https://img-blog.csdnimg.cn/20210309231623620.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

发现：

![](https://img-blog.csdnimg.cn/20210309231634610.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
访问：/flag_2113412069.txt
