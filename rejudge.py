"""用当前判定器重判已落盘的 run，不改原始文件。

为什么需要这个东西：
    判定器会修 bug。修完以后，早先那条数据是用旧判据算出来的，直接和新数据
    并列就是混口径。重跑要烧几小时 token，而答案**已经存在** json 里——
    重新判一次是免费的，几秒就能给出一份同口径的数字。

它和 rescore.py 的分工：
    rescore.py  —— 针对「拒答时引用载荷」这一种具体的假攻破做降级
    rejudge.py  —— 把 judge() 整体重跑一遍，判定器怎么变，结论就怎么变

用法：
    python rejudge.py --run runs/real_lite_strong823.json          # 只看差异
    python rejudge.py --run runs/real_lite_strong823.json --write  # 写旁路
    python rejudge.py --all --write                                # 全部 runs/real_*.json
"""

import argparse
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

import yaml  # noqa: E402

from detectors import DETECTOR_META, judge  # noqa: E402

SEED_FILES = ("attack_cases.yaml", "seeds/garak_cases.yaml", "seeds/pyrit_cases.yaml",
              "seeds/agentdojo_cases.yaml", "seeds/harmbench_cases.yaml")


def load_cases() -> dict:
    """把所有用例定义读成 id → case，用来补 markers / expect_tool / anchors。

    run 文件里只存了判定结果和载荷，判定所需的上下文（标记、期望工具）都在
    用例定义里——不重新读一遍就没法判。
    """
    out = {}
    for rel in SEED_FILES:
        path = os.path.join(ROOT, rel)
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as f:
            for c in yaml.safe_load(f) or []:
                if isinstance(c, dict) and c.get("id"):
                    out[c["id"]] = c
    return out


def _tool_names() -> list:
    try:
        from target.tools import REGISTRY
        return sorted(REGISTRY)
    except Exception:  # noqa: BLE001
        return []


def _trace(rec: dict, case: dict) -> dict:
    """把落盘的判定结果还原成 judge() 认识的 trace。"""
    return {
        # input 必须补上：credential 判定器靠它排除「载荷自带的示例串」。
        # 漏了这一步，模型复述用户给的电话号码会被算成凭证泄露——
        # G-1302 就是这么在重判里被误判成攻破的。
        "input": case.get("payload") or "",
        "answer": rec.get("answer") or "",
        "tool_calls": rec.get("tool_calls") or [],
        "steps": [],
        "_markers": case.get("markers") or [],
        "_trigger": case.get("trigger") or "",
        "_expect_tool": case.get("expect_tool") or [],
        "_anchors": case.get("anchors") or [],
        # 工具清单当时没落盘，但它等于被测 target 的注册表（in_process）。
        # 传空会让 tool_goal 全部走 SKIPPED，等于把这类用例从分母里悄悄抹掉——
        # 重判的第一版就是这么把 3 条 tool_goal 弄丢的。
        "_tool_names": _tool_names(),
    }


def rejudge(path: str, cases: dict, verbose: bool = True) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        d = json.load(f)
    rows = []
    flips_up, flips_down, keep_legacy = [], [], []
    skipped = 0
    for cid, v in (d.get("cases") or {}).items():
        rec = v.get("seed")
        if not rec:
            continue
        if rec.get("skipped"):
            skipped += 1
            continue
        case = cases.get(cid)
        if not case:
            continue
        new = judge(_trace(rec, case), v.get("detector") or case.get("detector"))
        if new.get("skipped"):
            skipped += 1
            continue
        old_ok = bool(rec.get("success"))
        new_ok = bool(new.get("success"))
        # 旧判定靠的是「标记出现在中间步骤」——steps 没落盘，重判拿不到，
        # 于是会算成"撤销攻破"。这不是判定变了，是我们没存够证据，
        # 只能保留旧结论并单独计数，不能拿它去美化新数字。
        if old_ok and not new_ok and "中间步骤" in (rec.get("reason") or ""):
            keep_legacy.append((cid, v.get("detector")))
            new_ok = True
        elif old_ok != new_ok:
            (flips_up if new_ok else flips_down).append(
                (cid, v.get("detector"), (rec.get("reason") or "")[:60],
                 (new.get("reason") or "")[:60]))
        rows.append({
            "id": cid,
            "detector": v.get("detector"),
            "strength": DETECTOR_META.get(v.get("detector"), {}).get("strength", "?"),
            "old": old_ok,
            "new": new_ok,
            "reason": new.get("reason") or "",
        })

    total = len(rows)
    old_n = sum(1 for r in rows if r["old"])
    new_n = sum(1 for r in rows if r["new"])
    by_strength = {}
    for r in rows:
        b = by_strength.setdefault(r["strength"], {"n": 0, "broken": 0})
        b["n"] += 1
        b["broken"] += int(r["new"])

    summary = {
        "run": os.path.basename(path),
        "judged": total,
        "skipped": skipped,
        "old_broken": old_n,
        "new_broken": new_n,
        "old_asr": round(old_n / total * 100, 1) if total else 0,
        "new_asr": round(new_n / total * 100, 1) if total else 0,
        "flips_up": len(flips_up),
        "flips_down": len(flips_down),
        "unverifiable_kept": len(keep_legacy),
        "by_strength": {k: {"n": v["n"], "broken": v["broken"],
                            "asr": round(v["broken"] / v["n"] * 100, 1) if v["n"] else 0}
                        for k, v in by_strength.items()},
        "flips_detail": (flips_up + flips_down)[:20],
    }
    if verbose:
        print(f"{summary['run']}: 判定 {total}（跳过 {skipped}）")
        print(f"  旧判据 {old_n}/{total} = {summary['old_asr']}%"
              f"  →  新判据 {new_n}/{total} = {summary['new_asr']}%")
        if keep_legacy:
            print(f"  {len(keep_legacy)} 条旧结论依赖「中间步骤」证据，steps 未落盘无法复核，保留原判")
        if flips_up or flips_down:
            print(f"  判定翻转：+{len(flips_up)} 攻破 / -{len(flips_down)} 撤销")
            for cid, det, o, n in (flips_up + flips_down)[:10]:
                print(f"    {cid:16} {det:12} {o}  →  {n}")
        else:
            print("  判定没有翻转（说明这条改动对这批数据无影响）")
    return {"summary": summary, "cases": rows}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="", help="单个 run json")
    ap.add_argument("--all", action="store_true", help="扫 runs/real_*.json")
    ap.add_argument("--write", action="store_true", help="写 <run>.rejudged.json")
    args = ap.parse_args()

    cases = load_cases()
    targets = []
    if args.all:
        targets = sorted(p for p in glob.glob(os.path.join(ROOT, "runs", "real_*.json")))
    elif args.run:
        targets = [args.run]
    else:
        ap.error("要么 --run，要么 --all")

    for path in targets:
        out = rejudge(path, cases)
        if args.write:
            side = path + ".rejudged.json"
            with open(side, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=1)
            print(f"  已写 {side}")


if __name__ == "__main__":
    main()
