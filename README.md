# HTB-Writeups

自己的一些打靶思路。在线看：https://imawuya.github.io/HTB-Writeups/

## 目录

| 靶机 | 难度 | 关键路径 |
| :--- | :--- | :--- |
| [Layover](https://imawuya.github.io/HTB-Writeups/posts/layover/) | Medium | RDP 跳板 → 802.11 流量抓门户凭据 → Craft CMS RCE → CUPS 提权 |
| [DevHub](https://imawuya.github.io/HTB-Writeups/posts/devhub/) | Medium | MCPJam Inspector 未授权 RCE → Jupyter Token → OPSMCP 硬编码 Key → root 私钥 |
| [Expressway](https://imawuya.github.io/HTB-Writeups/posts/expressway/) | Easy | IKEv1 Aggressive 泄露 PSK → 离线爆破 → sudo CVE-2025-32463 |
