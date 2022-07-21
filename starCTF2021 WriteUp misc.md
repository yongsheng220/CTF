---
title: starCTF2021-MISC-Writeup
categories: 赛题wp
---
两天的比赛：
![](https://img-blog.csdnimg.cn/20210124033659289.jpg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

总结：拿到的文件都是py脚本，又长又难懂。在网上看看别人的wp学习学习,顺一下思路。<!--more-->

[MISC](https://blog.csdn.net/mochu7777777/article/details/112794962)

## 1.signin

>Welcome to *CTF 2021, join telegram to get flag: https://t.me/starCTF

- 这道题去链接时候网页怎么都进不去，在确定我的网络没问题时，只有在外网时才会这样，幸好电脑上有VPN，链接果然进去了

![](https://img-blog.csdnimg.cn/20210124035055848.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


## 2.MineGame

   - 运行环境3G直接劝退了,看了wp之后，既然是.exe文件的小游戏，所以要看它里面有什么，找一个这种调试的工具试一试看；
   
 [题目附件](https://adworld.xctf.org.cn/media/uploads/task/f9fd04cdbed4469d856b92b9a648041a.zip)
 
 下载完MATLAB，之后运行MineGame.exe发现是扫雷，而且运行程序大概十秒后就会自动结束程序，首先运行MineGame.exe，然后使用Cheat Engine打开这个进程，然后点击左下角的Advanced Options暂停进程

然后利用CE可以在内存种搜索字符*CTF的十六进制编码
 >字符：*CTF
十六进制编码：2A 00 43 00 54 00 46 00

- 00是因为在工具里存在‘.’，其实*CTF的十六进制是2a435446
	加00后为下图所示

- CE修改器(Cheat Engine)是一款内存修改编辑工具,它允许你修改你的游戏,所以你将总是赢.它包括16进制编辑,反汇编程序,内存查找工具。与同类修改工具相比,它具有强大的反汇编功能,且自身附带了辅助工具制作工具,可以用它直接生成辅助工具。


![](https://img-blog.csdnimg.cn/20210124040057835.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

在内存中找到了好几个地址有该字符串，在27E17576980地址找到完整的flag

![](https://img-blog.csdnimg.cn/20210124040237882.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


## 3.little tricks

 这个长知识，DiskGenius是一款磁盘分区及数据恢复软件。DiskGenius支持对GPT磁盘(使用GUID分区表)的分区操作。除具备基本的分区建立、删除、格式化等磁盘管理功能。

ll2用file一查看发现是windows磁盘镜像
![](https://img-blog.csdnimg.cn/20210124042102701.png#pic_center)

尝试修改vhdx，然后尝试了下弱密码12345678就直接打开了，
里面只有个password.txt，并没发现其他的

![](https://img-blog.csdnimg.cn/20210124042140170.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
DiskGenius打开，发现两个pdf文件

![](https://img-blog.csdnimg.cn/20210124042238567.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
直接打开较大的pdf，两个flag重叠了，上面的是假的，下面的是真的

![](https://img-blog.csdnimg.cn/2021012404230847.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

## 4.puzzle

   - 拼图游戏
- linux下拼图工具  gaps [安装教程](https://www.jianshu.com/p/d9e9019e8148?from=singlemessage)

![](https://img-blog.csdnimg.cn/20210124042631424.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
可以处理一下对比度，亮度等
然后用gaps跑跑，看看每一代训练结果

![](https://img-blog.csdnimg.cn/20210124042756390.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210124042804786.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
基本能看出来
![](https://img-blog.csdnimg.cn/20210124042827416.png#pic_center)

## 5.Feedback

- We need your FeedBack!
https://forms.gle/UjK5RWBU7XA5DmHz5
- vpn

![](https://img-blog.csdnimg.cn/20210124042945875.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

