---
title: CTFshow 福利抽奖
categories: 
---
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210305151210172.jpg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)


印象深刻，记录一下
<!--more-->

![](https://img-blog.csdnimg.cn/202103051513481.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
进入页面没有输入框，提交框，还以为是卡了，开启环境直接给flag

原来框被隐藏了，考点就是这里

浏览器 F12 打开，再打开另一个正常的题目，找不同

在复制粘贴正常页面的缺失的 html 之后，算是恢复了：

![](https://img-blog.csdnimg.cn/20210305151644927.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

---
但是点击submit发现没有反应，缺少 event，无法提交到服务器

再去看正常的题目发现二者value值不同，提交的服务器地址相同

直接修改value为1089，在这个提交框提交，成功！

![](https://img-blog.csdnimg.cn/20210305151900215.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

