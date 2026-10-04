#!/usr/bin/env python3
"""把一个 HTB 靶场目录(三文件结构)导入成 Hugo 博客文章。

从 <box_dir>/walkthrough.md 生成 content/posts/<slug>.md,
若存在 <box_dir>/attack-path.png 则复制到 static/images/ 并插入正文。

用法:
  python scripts/import-writeup.py ../Layover-Linux-Medium \\
      --slug layover \\
      --title "HTB Layover Writeup" \\
      --date 2026-10-04 \\
      --tags "HTB,Linux,Medium,Craft CMS,CUPS"
"""
import argparse
import os
import re
import shutil
import sys
from datetime import date

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("box_dir", nargs="?", help="靶场目录(含 walkthrough.md)")
    ap.add_argument("--md", help="直接指定源 md 文件(覆盖 box_dir/walkthrough.md)")
    ap.add_argument("--slug", required=True, help="输出文件名,如 layover")
    ap.add_argument("--title", required=True, help="文章标题")
    ap.add_argument("--date", default=str(date.today()))
    ap.add_argument("--tags", default="", help="逗号分隔")
    ap.add_argument("--categories", default="Writeup")
    ap.add_argument("--description", default="", help="留空则取正文首段")
    a = ap.parse_args()

    wk = a.md if a.md else os.path.join(a.box_dir or "", "walkthrough.md")
    if not os.path.isfile(wk):
        sys.exit("[!] 找不到 " + wk)
    body = open(wk, encoding="utf-8").read()

    # 去掉开头的 h1 —— 标题由 front matter 提供
    body = re.sub(r"^\s*#\s+.*?\n", "", body, count=1).lstrip("\n")

    # 攻击路径图
    box_root = os.path.dirname(os.path.abspath(wk))
    img = os.path.join(box_root, "attack-path.png")
    if os.path.isfile(img):
        dst_dir = os.path.join(ROOT, "static", "images")
        os.makedirs(dst_dir, exist_ok=True)
        dst_name = a.slug + "-attack-path.png"
        shutil.copyfile(img, os.path.join(dst_dir, dst_name))
        img_md = "\n![%s 攻击路径](/images/%s)\n" % (a.slug, dst_name)
        parts = body.split("\n---\n", 1)
        body = (parts[0] + "\n" + img_md + "\n---\n" + parts[1]
                if len(parts) == 2 else body + img_md)
        print("[+] 已复制图片 -> static/images/" + dst_name)

    tags = [t.strip() for t in a.tags.split(",") if t.strip()]
    cats = [c.strip() for c in a.categories.split(",") if c.strip()]
    desc = a.description or body.strip().split("\n")[0][:120]

    fm = [
        "---",
        'title: "%s"' % a.title,
        "date: %s" % a.date,
        "draft: false",
        'description: "%s"' % desc.replace('"', "'"),
        "tags: [%s]" % ", ".join('"%s"' % t for t in tags),
        "categories: [%s]" % ", ".join('"%s"' % c for c in cats),
        "isStarred: false",
        "---",
        "",
    ]

    out_dir = os.path.join(ROOT, "content", "posts")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, a.slug + ".md")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(fm) + "\n" + body)
    print("[+] 已生成 " + out)


if __name__ == "__main__":
    main()
