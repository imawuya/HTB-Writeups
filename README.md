# HTB-Writeups

自己的一些打靶思路。在线看：https://imawuya.github.io/HTB-Writeups/

## 目录

| 靶机 | 难度 | 关键路径 |
| :--- | :--- | :--- |
| [Layover](https://imawuya.github.io/HTB-Writeups/posts/layover/) | Medium | RDP 跳板 → 802.11 流量抓门户凭据 → Craft CMS RCE → CUPS 提权 |
| [DevHub](https://imawuya.github.io/HTB-Writeups/posts/devhub/) | Medium | MCPJam Inspector 未授权 RCE → Jupyter Token → OPSMCP 硬编码 Key → root 私钥 |
| [Expressway](https://imawuya.github.io/HTB-Writeups/posts/expressway/) | Easy | IKEv1 Aggressive 泄露 PSK → 离线爆破 → sudo CVE-2025-32463 |
| [Autopilot](https://imawuya.github.io/HTB-Writeups/posts/autopilot/) | Insane | grommunio 邮件服务器 → Nextcloud 数据目录 PHP 执行 → postfix-script 提权 → 邮件捞 AD 凭据 → WS02 → 域管令牌 |
| [Management](https://imawuya.github.io/HTB-Writeups/posts/management/) | Easy | AES-GCM 加密 bundle → OpenAM CVE-2026-33439 → GLPI 密码复用 → sudo rdiff-backup 参数覆盖 |
| [Stream](https://imawuya.github.io/HTB-Writeups/posts/stream/) | Medium | Spring Boot heapdump → H2 / ClickHouse 凭据复用 → XML 解析器 XXE → ClickHouse 定时任务提权 |
