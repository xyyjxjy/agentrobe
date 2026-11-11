"""Day 1 验收脚本：跑单条攻击用例，打印完整 trace 与判定结果。

用法：
    python run_once.py list              # 列出所有用例
    python run_once.py run D-01          # 跑一条（基线，未加固）
    python run_once.py run I-01 --hard   # 跑一条（加固版，Day 6 用）
    python run_once.py all               # 顺序跑全部，打印简要汇总
"""

import argparse
import json
import os
import sys
import time

import yaml
from dotenv import load_dotenv

load_dotenv()

from detectors import judge                # noqa: E402
from llm_client import model_name, stats   # noqa: E402
from target.agent import run_agent         # noqa: E402

CASES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attack_cases.yaml")


def load_cases() -> list:
    with open(CASES_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def print_trace(case: dict, trace: dict, verdict: dict) -> None:
    line = "─" * 68
    print(f"\n{line}")
    print(f"[{case['id']}] {case['name']}  ({case['category']} / {case['owasp']})")
    print(f"判定器：{case['detector']}")
    print(line)
    print(f"\n▶ 输入 payload：\n{trace['input'].strip()[:500]}\n")

    for i, step in enumerate(trace.get("steps", []), 1):
        if step["role"] == "assistant":
            print(f"  [{i}] 模型输出：{step['content'].strip()[:300]}")
        else:
            print(f"  [{i}] 调用 {step['name']}({json.dumps(step['args'], ensure_ascii=False)})")
            print(f"      返回：{step['result'].strip()[:200]}")

    print(f"\n▶ 最终回答：\n{(trace.get('answer') or '(空)').strip()[:600]}\n")
    print(f"▶ 工具调用次数：{len(trace.get('tool_calls', []))}")
    if trace.get("error"):
        print(f"▶ 异常：{trace['error']}")

    if verdict["success"]:
        mark = "✅ 攻击成功"
    elif verdict.get("attempt"):
        mark = "⚠️ 有越界尝试但未生效（不计入成功）"
    else:
        mark = "❌ 攻击失败"
    print(f"\n▶ 判定结果：{mark}")
    print(f"  依据：{verdict['reason']}")
    print(f"{line}\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["list", "run", "all"])
    ap.add_argument("case_id", nargs="?")
    ap.add_argument("--hard", action="store_true", help="使用加固版系统提示词")
    ap.add_argument("--limit", type=int, default=0, help="只跑前 N 条，用于快速冒烟")
    ap.add_argument("--cat", default="", help="只跑某一类别，如 direct_injection")
    args = ap.parse_args()

    cases = load_cases()

    if args.action == "list":
        print(f"\n共 {len(cases)} 条用例\n")
        for c in cases:
            print(f"  {c['id']:<8}{c['category']:<22}{c['detector']:<14}{c['name']}")
        print()
        return

    if args.action == "run":
        if not args.case_id:
            print("请指定用例编号，例如：python run_once.py run D-01")
            sys.exit(1)
        case = next((c for c in cases if c["id"] == args.case_id), None)
        if not case:
            print(f"未找到用例 {args.case_id}")
            sys.exit(1)
        trace = run_agent(case["payload"], hardened=args.hard)
        verdict = judge(trace, case["detector"])
        print_trace(case, trace, verdict)
        return

    # all：只打一行摘要，便于快速扫一眼基线
    todo = [c for c in cases if not args.cat or c["category"] == args.cat]
    if args.limit:
        todo = todo[: args.limit]

    t_start = time.time()
    ok = 0
    att_only = 0
    for i, c in enumerate(todo, 1):
        t0 = time.time()
        trace = run_agent(c["payload"], hardened=args.hard)
        v = judge(trace, c["detector"])
        if v["success"]:
            ok += 1
            flag = "✅"
        elif v.get("attempt"):
            att_only += 1
            flag = "⚠️"
        else:
            flag = "❌"
        print(f"{flag} [{i:>2}/{len(todo)}] {c['id']:<8}{c['name']}  ({time.time()-t0:.1f}s)", flush=True)

    rate = ok / len(todo) * 100 if todo else 0
    print(f"\n攻击成功率：{ok}/{len(todo)} = {rate:.1f}%")
    if att_only:
        print(f"另有 {att_only} 条仅有越界尝试但未生效（不计入成功率）")
    print(f"总耗时：{time.time()-t_start:.1f}s  模型：{model_name()}  "
          f"调用次数：{stats()['calls']}  token：{stats()['tokens']}")


if __name__ == "__main__":
    main()
