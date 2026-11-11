"""导入 HarmBench 的行为集（1528 条，510 个语义类别）。

为什么是"导入数据"而不是"接入框架"：
    HarmBench 是论文配套仓库，不是 pip 包，也没有稳定的 Python API。
    它真正的资产是两样东西：
        1. 1528 条行为（behavior）+ 语义分类 —— 这个能直接用，就是本文件干的
        2. 一个 LLM 分类器（judge）用来判"模型是否照做了" —— 这个我们替不了，
           它要跑 Llama-2-13B。我们自己的 compliance 判定器是词表级的弱判定，
           把两者混算会得出"ASR 30%"这种经不起追问的数字。

所以这批用例进的是 **weak 桶**，报告里必须单独列，不能和 canary/tool_goal 混。

数据文件不入库（vendor/ 已在 .gitignore 里）：
    HarmBench 的行为集来自 AdvBench 等多个上游数据集，许可条款跟它的代码（MIT）不同。
    仓库里只放导入脚本，别人 clone 后自己 --download 一份，各自承担各自的使用责任。

用法：
    python importers/harmbench.py --download            # 拉一份到 vendor/harmbench/
    python importers/harmbench.py -o seeds/harmbench.jsonl
    python importers/harmbench.py --list                # 只看类别分布
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CSV = os.path.join(ROOT, "vendor", "harmbench", "harmbench_behaviors_text_all.csv")
URL = ("https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/"
       "data/behavior_datasets/harmbench_behaviors_text_all.csv")

# HarmBench 的语义类别 → 本项目的危害域。没列到的原样保留，
# 不做映射默认值：硬塞进 compliance 只会让判定器"看起来覆盖了"其实全靠词表碰运气。
DOMAIN_MAP = {
    "chemical_biological": "harmful_compliance",
    "cybercrime_intrusion": "harmful_compliance",
    "harassment_bullying": "harmful_compliance",
    "harmful": "harmful_compliance",
    "illegal": "harmful_compliance",
    "misinformation_disinformation": "harmful_compliance",
    "copyright": "harmful_compliance",
}


def download(path: str = DEFAULT_CSV) -> str:
    import urllib.request
    os.makedirs(os.path.dirname(path), exist_ok=True)
    print(f"下载 HarmBench 行为集 → {path}")
    urllib.request.urlretrieve(URL, path)   # noqa: S310
    size = os.path.getsize(path)
    print(f"  完成，{size/1024:.0f} KB")
    return path


def load(path: str) -> list:
    rows = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            behavior = (r.get("Behavior") or "").strip()
            if not behavior:
                continue
            ctx = (r.get("ContextString") or "").strip()
            rows.append({
                "source": "harmbench",
                "behavior_id": (r.get("BehaviorID") or "").strip(),
                "behavior": behavior,
                "semantic": (r.get("SemanticCategory") or "").strip(),
                "functional": (r.get("FunctionalCategory") or "").strip(),
                "tags": [t for t in (r.get("Tags") or "").split(",") if t],
                "category_hint": DOMAIN_MAP.get(
                    (r.get("SemanticCategory") or "").strip(), "harmful_compliance"),
                # 带上下文的题目（比如"续写这段文字"）必须把上下文一起发，
                # 只发 behavior 会改变题意
                "payload": (ctx + "\n\n" + behavior) if ctx else behavior,
            })
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=DEFAULT_CSV)
    ap.add_argument("-o", "--out", default="seeds/harmbench.jsonl")
    ap.add_argument("--download", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.download:
        download(args.csv)
    if not os.path.exists(args.csv):
        print(f"找不到 {args.csv}\n先跑：python importers/harmbench.py --download")
        sys.exit(1)

    rows = load(args.csv)
    if args.limit:
        rows = rows[: args.limit]
    if args.list:
        from collections import Counter
        c = Counter(r["semantic"] for r in rows)
        print(f"共 {len(rows)} 条，{len(c)} 个语义类别：")
        for k, v in c.most_common():
            print(f"  {k:36} {v}")
        return

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"导出 {len(rows)} 条 → {args.out}")
    print("  ⚠️ 这批只能走 compliance 弱判定（HarmBench 原判据要 Llama-2-13B 分类器，"
          "我们没接）。报告里必须放在 weak 桶，禁止和 strong 混算。")


if __name__ == "__main__":
    main()
