"""把 runs/*.json 渲染成一份能交给别人看的 markdown 报告。

为什么单独写一个而不是"看终端输出"：
    终端输出只保留最后一次，且没有跨运行对比。真正需要回答的问题是
    "同一个被测对象，加固前后差多少"、"换了模型之后数字还能不能比"，
    这要靠把多次运行摆在一张表里。

三条硬规则（和 evolve.py 一致，这里只是呈现层）：
    1. is_mock=True 的运行单独一个区块，且不许出现任何结论性措辞。
    2. 跨模型的数字不合并、不排名，只并列。换模型等于换被测对象。
    3. skipped_runtime>0 说明有请求失败，该次运行的分母要标出来。

用法：
    python report.py                          # 扫 runs/real_*.json → REPORT.md
    python report.py --runs "runs/*.json" --out docs/report.md
    python report.py --min-judgeable 100      # 只收样本量够的（默认 0，全收）
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import time

ROOT = os.path.dirname(os.path.abspath(__file__))

# 样本量低于这个数就不写百分比结论，只写原始计数。
# 12 条用例算出 8.3% 和 0% 的差别，在噪声里毫无意义——这一条是实测换来的。
MIN_SAMPLE = 30


def load(path: str) -> dict | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(d, dict) or "summary" not in d:
        return None
    return d


def _pct(a: int, b: int) -> str:
    return f"{a / b * 100:.1f}%" if b else "—"


def _fname(p: str) -> str:
    return os.path.basename(p)


def describe(d: dict) -> dict:
    s = d["summary"]
    m = d.get("meta") or {}
    j = s.get("judgeable") or 0
    return {
        "model": m.get("model") or "?",
        "ts": m.get("ts") or "?",
        "judgeable": j,
        "asr": s.get("final_asr"),
        "seed_asr": s.get("seed_asr"),
        "broken": s.get("final_broken"),
        "variants": s.get("variants"),
        "rounds": s.get("rounds"),
        "skip_runtime": s.get("skipped_runtime") or 0,
        "skipped_total": s.get("skipped") or 0,
        # 早期版本的 summary 没有 skipped_runtime 字段，那时请求失败被算成
        # "未攻破"进了分母。这种记录不能当证据，只能标出来。
        "legacy": "skipped_runtime" not in s,
        "skip_preflight": s.get("skipped_preflight") or 0,
        "mock": bool(s.get("is_mock")),
        "stop": s.get("stop_reason") or "?",
        "by_strength": s.get("by_strength") or {},
        "family": s.get("family") or {},
        "attempt_only": s.get("attempt_only") or 0,
        "small": j < MIN_SAMPLE,
    }


def section_overview(rows: list) -> list[str]:
    out = ["## 1. 全部运行一览", "",
           "| 运行 | 模型 | 时间 | 判定数 | ASR | 变体 | 轮次 | 请求失败 | 备注 |",
           "|---|---|---|---:|---:|---:|---:|---:|---|"]
    for name, e in rows:
        notes = []
        if e["mock"]:
            notes.append("**干跑**")
        if e["small"]:
            notes.append("样本 < %d" % MIN_SAMPLE)
        if e["skip_runtime"]:
            notes.append(f"**{e['skip_runtime']} 条无依据**")
        if not e["variants"]:
            notes.append("未产生变体")
        if e["legacy"]:
            notes.append("**旧格式**")
        out.append(
            f"| `{name}` | {e['model']} | {e['ts']} | {e['judgeable']} | "
            f"{e['asr']}% | {e['variants']} | {e['rounds']} | "
            f"{e['skip_runtime']} | {'、'.join(notes) or '—'} |")
    out.append("")
    return out


def section_by_model(rows: list) -> list[str]:
    """按模型分组。这里刻意不做排名——跨模型比大小是错的。"""
    groups: dict[str, list] = {}
    for name, e in rows:
        if e["mock"]:
            continue
        groups.setdefault(e["model"], []).append((name, e))
    if len(groups) <= 1:
        return []

    out = ["## 2. 按被测模型分组（跨模型不可比）", "",
           "换模型 = 换被测对象。下表的数字只能竖着读（同模型不同配置），"
           "不能横着比谁更安全。", ""]
    for model, items in sorted(groups.items()):
        out.append(f"**{model}**")
        out.append("")
        for name, e in items:
            out.append(f"- `{name}`：{e['broken']}/{e['judgeable']} = {e['asr']}%"
                       f"（strong 桶见下节）")
        out.append("")
    return out


def section_strength(name: str, d: dict) -> list[str]:
    s = d["summary"]
    bs = s.get("by_strength") or {}
    if not bs:
        return []
    out = [f"### {name} · 按判定强度分层", "",
           "| 强度 | 攻破/总数 | ASR | 涉及判定器 | 可解释性 |",
           "|---|---:|---:|---|---|"]
    explain = {"strong": "可直接下结论（串匹配/带外信标）",
               "medium": "可用，需说明局限",
               "weak": "只能当线索，不进摘要"}
    for k in ("strong", "medium", "weak"):
        if k not in bs:
            continue
        e = bs[k]
        out.append(f"| {k} | {e.get('broken')}/{e.get('total')} | "
                   f"{e.get('asr')}% | {', '.join(e.get('detectors') or [])} | "
                   f"{explain.get(k, '')} |")
    out.append("")
    return out


def section_cases(name: str, d: dict, limit: int = 8) -> list[str]:
    cases = d.get("cases") or {}
    broken = [(cid, c) for cid, c in cases.items() if c.get("broken")]
    if not broken:
        return []
    out = [f"### {name} · 攻破明细（{len(broken)} 条）", "",
           "| 用例 | 名称 | 判定器 | 证据 |", "|---|---|---|---|"]
    for cid, c in broken[:limit]:
        seed = c.get("seed") or {}
        ev = (seed.get("reason") or "")[:90].replace("|", "／")
        out.append(f"| {cid} | {c.get('name', '')[:24]} | {c.get('detector')} | {ev} |")
    if len(broken) > limit:
        out.append(f"| … | 另有 {len(broken) - limit} 条 | | 见原始 JSON |")
    out.append("")
    return out


def section_hygiene(rows: list) -> list[str]:
    problems = []
    for name, e in rows:
        if e["skip_runtime"]:
            problems.append(f"- `{name}`：{e['skip_runtime']} 条请求失败/无判定依据，"
                            f"已剔出分母。看这个文件前先确认不是模型服务挂了")
        if not e["variants"] and e["rounds"] == 1:
            problems.append(f"- `{name}`：只有 1 轮且无变体。`--rounds 1` 是"
                            f"「只跑种子轮」，不代表变异失败")
        if e["small"]:
            problems.append(f"- `{name}`：判定数 {e['judgeable']} < {MIN_SAMPLE}，"
                            f"百分比只能当参考，不能当结论")
        if e["legacy"] and e["skipped_total"]:
            problems.append(
                f"- `{name}`：**旧格式记录**（summary 里没有 `skipped_runtime` 字段）。"
                f"该版本把请求失败记成「未攻破」并计入分母，本次另有 "
                f"{e['skipped_total']} 条被跳过。这条记录不能作为证据引用")
    if not problems:
        return []
    return ["## 数据卫生检查", "",
            "下列问题会直接改变数字的解读方式，读表前先看这一段。", ""] + problems + [""]


def build(paths: list, min_judgeable: int = 0) -> str:
    runs = []
    for p in paths:
        d = load(p)
        if not d:
            continue
        e = describe(d)
        if e["judgeable"] < min_judgeable:
            continue
        runs.append((_fname(p), e, d))

    # 真实跑测在前，干跑垫底——顺序本身就是一种提示
    runs.sort(key=lambda x: (x[1]["mock"], x[1]["ts"]))

    lines = ["# agentprobe 测评报告", "",
             f"生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}　·　"
             f"收录运行 {len(runs)} 次　·　"
             f"每次运行都是独立快照，不做跨运行合并", ""]

    rows = [(n, e) for n, e, _ in runs]
    lines += section_overview(rows)
    lines += section_hygiene(rows)
    lines += section_by_model(rows)

    real = [(n, e, d) for n, e, d in runs if not e["mock"]]
    if real:
        lines += ["## 3. 逐次运行明细", ""]
        for name, e, d in real:
            lines += [f"### {name}", "",
                      f"- 模型 `{e['model']}`　判定 {e['judgeable']} 条　"
                      f"ASR {e['broken']}/{e['judgeable']} = {e['asr']}%",
                      f"- 变异 {e['variants']} 个，{e['rounds']} 轮，停止原因：{e['stop']}",
                      f"- 仅有越界尝试未生效：{e['attempt_only']} 条（不计入攻破）", ""]
            lines += section_strength(name, d)
            lines += section_cases(name, d)

    mocks = [(n, e, d) for n, e, d in runs if e["mock"]]
    if mocks:
        lines += ["## 4. 干跑记录（不构成任何安全结论）", "",
                  "以下运行使用内置桩件，只证明流程能跑通：", ""]
        for name, e, d in mocks:
            lines += [f"- `{name}`：{e['judgeable']} 条，ASR {e['asr']}%"]
        lines += [""]

    lines += ["---", "",
              "本报告由 `report.py` 从 `runs/*.json` 直接渲染，未做任何人工润色。"
              "数字有疑问请回查原始 JSON 里的 `cases` 字段。", ""]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default=os.path.join(ROOT, "runs", "real_*.json"),
                    help="glob，默认 runs/real_*.json")
    ap.add_argument("--out", default=os.path.join(ROOT, "REPORT.md"))
    ap.add_argument("--min-judgeable", type=int, default=0,
                    help="只收判定数 ≥ N 的运行（样本太小的自动排除）")
    args = ap.parse_args()

    paths = sorted(glob.glob(args.runs))
    if not paths:
        print(f"没有匹配到文件：{args.runs}")
        return
    text = build(paths, args.min_judgeable)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"报告已生成：{args.out}（{len(paths)} 个候选文件）")


if __name__ == "__main__":
    main()
