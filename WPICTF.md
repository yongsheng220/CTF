---
title: WPICTF2021
categories: 赛题wp
---

# wpi-admin1-2-3

进入网址：

![](https://img-blog.csdnimg.cn/20210427193414394.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

<!--more-->
弱密码爆破：

![](https://img-blog.csdnimg.cn/20210427193426290.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
登录dennisb账号：

![](https://img-blog.csdnimg.cn/20210427193441784.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
找到登录窗口连接：

![](https://img-blog.csdnimg.cn/2021042719352965.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210427193541972.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
一看session，jwt伪造session

Flaskunsign：

![](https://img-blog.csdnimg.cn/20210427193555840.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

想着暴力破解找到密钥，半个小时没结果果断放弃

又一次被cookie坑了

尝试一波SQL注入就进去了，用户名处有格式检测，在密码处万能密码直接进

![](https://img-blog.csdnimg.cn/20210427193643472.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
```
dennisb@uupeye.edu
admin'or 1=1--+
```
紧接着是一个JSON文件上传

让上传一个配置

![](https://img-blog.csdnimg.cn/20210427193714612.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
查看网页源码：

![](https://img-blog.csdnimg.cn/20210427193723440.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
其他开发人员注意：下面是一个帮助开发的JSON配置示例。
一旦开发了后端，不要忘记删除它。

访问后可以看到一些数据：

![](https://img-blog.csdnimg.cn/20210427193734680.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
猜测是让我们按照这个模板，将名字成绩等替换，再上传

下载后将成绩改为A

![](https://img-blog.csdnimg.cn/20210427193803683.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20210427193812892.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

还是不行，放弃，找到wp再来

# Glute
Foremost 分离

# suspicious-traffic

流量分析

>我在可疑客户端和服务器之间获取了数据包捕获。看起来真奇怪，你能看看吗？‎

直接追踪tcp流，看到 w，查找下一个流，右下角那里一直点就行了

![](https://img-blog.csdnimg.cn/20210427193915622.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzUzMjYzNzg5,size_16,color_FFFFFF,t_70#pic_center)

