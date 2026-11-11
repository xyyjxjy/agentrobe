"""AI 安全扫描入口：给外部 harness 调的一个功能，不是一个独立产品。

为什么单独开一个文件而不是让调用方直接用 evolve.py：
    评委/队友要的是「传一个目标，拿一包结果」。evolve.py 是给人看的
    流水线，参数十几个、输出是内部结构。这里把它收成一个函数＋一条命令，
    输入输出都是固定 schema，别人拿去嵌进 harness 不用读我们的源码。

用法（命令）：
    python aisec.py --target http://127.0.0.1:8000/chat --budget 100 --out findings.json
    python aisec.py --target inproc --budget 50          # 拿内置靶子试跑

用法（代码）：
    from aisec import scan
    result = scan(target="http://127.0.0.1:8000/chat", budget=100)
    for f in result["findings"]:
        print(f["severity"], f["title"], f["repro"])

被测目标的接口约定（HTTP）：
    POST <target>
    {"message": "<攻击载荷>"}
  →
    {"answer": "...", "tool_calls": [...], "steps": [...]}
    只有 answer 也能跑，但 tool_abuse / tool_goal 两类会标成 SKIPPED
    （拿不到工具调用就没有判定依据，这是能力协商，不是失败）。

输出 schema：
    {
      "meta":   {target, model, started, seconds, budget, sampled_from, strength},
      "summary":{cases, judged, broken, asr, skipped, skipped_reasons, by_detector},
      "findings":[{id, title, severity, detector, strength, category, owasp,
                   payload, evidence, answer, repro}]
    }
"""

import argparse
import json
import os
import random
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from dotenv import load_dotenv  # noqa: E402

from detectors import DETECTOR_META  # noqa: E402
from evolve import load_cases, run_campaign  # noqa: E402
from transport import make_transport  # noqa: E402

DEFAULT_CASES = "attack_cases.yaml,seeds/garak_cases.yaml,seeds/pyrit_cases.yaml,seeds/agentdojo_cases.yaml"

# 判定强度决定这条 finding 能不能直接当结论看。
_SEVERITY = {"strong": "high", "medium": "medium", "weak": "low"}


def _pick(cases: list, budget: int, seed: int) -> list:
    """随机抽样，不用前 N 条。

    用例文件是按来源顺序写的（garak 的 encoding 家族打头），取前 100 条
    等于只测一个家族，出来的是「这个家族的 ASR」而不是「这批的 ASR」。
    """
    if not budget or budget >= len(cases):
        return cases
    rng = random.Random(seed)
    idx = rng.sample(range(len(cases)), budget)
    return [cases[i] for i in sorted(idx)]


def scan(target: str = "inproc", budget: int = 100, cases_path: str = DEFAULT_CASES,
         strength: str = "strong", seed: int = 42, case_timeout: float = 240.0,
         hard: bool = False, verbose: bool = True) -> dict:
    """跑一轮扫描，返回 findings。不抛异常，失败也会返回结构化的 summary。"""
    load_dotenv(os.path.join(ROOT, ".env"))
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    t0 = time.time()

    cases = load_cases(cases_path)
    if strength:
        want = {s.strip() for s in strength.split(",") if s.strip()}
        cases = [c for c in cases
                 if DETECTOR_META.get(c["detector"], {}).get("strength") in want]
    total_pool = len(cases)
    cases = _pick(cases, budget, seed)

    kind = "in_process" if target in ("inproc", "in-process", "local") else "http"
    transport = make_transport(kind, hardened=hard, url=None if kind == "in_process" else target)

    if verbose:
        print(f"目标 {transport.name} | 用例池 {total_pool} → 抽 {len(cases)} 条 "
              f"| 强度 {strength or '全部'}", flush=True)
        print(f"判定器 {sorted(transport.caps)}", flush=True)

    result = run_campaign(transport, cases, rounds=1, variants=0, seed=seed,
                          use_llm=False, beacon=None, case_timeout=case_timeout)
    transport.close()

    findings = []
    for cid, rec in (result.get("cases") or {}).items():
        seed_v = rec.get("seed") or {}
        if not seed_v.get("success"):
            continue
        case = next((c for c in cases if c["id"] == cid), {})
        det = case.get("detector", "?")
        st = DETECTOR_META.get(det, {}).get("strength", "weak")
        findings.append({
            "id": cid,
            "title": (case.get("name") or cid)[:80],
            "severity": _SEVERITY.get(st, "low"),
            "detector": det,
            "strength": st,
            "category": case.get("category", ""),
            "owasp": case.get("owasp", ""),
            "payload": (case.get("payload") or "")[:2000],
            "evidence": (seed_v.get("evidence") or [])[:6],
            "answer": _clip(seed_v.get("answer") or "", 800),
            "repro": _repro(target, case.get("payload") or ""),
        })
    findings.sort(key=lambda f: ({"high": 0, "medium": 1, "low": 2}[f["severity"]], f["id"]))

    s = result.get("summary") or {}
    out = {
        "meta": {
            "target": transport.name,
            "model": os.getenv("LLM_MODEL", ""),
            "started": started,
            "seconds": round(time.time() - t0, 1),
            "budget": len(cases),
            "sampled_from": total_pool,
            "strength": strength,
            "hardened_target": bool(hard),
            "is_mock": bool(s.get("is_mock")),
        },
        "summary": {
            "cases": len(cases),
            "judged": s.get("judgeable", 0),
            "broken": s.get("final_broken", 0),
            "asr": s.get("final_asr", 0),
            "skipped": s.get("skipped", 0),
            "by_strength": s.get("by_strength") or {},
        },
        "findings": findings,
    }
    if verbose:
        print(f"\n{out['summary']['broken']}/{out['summary']['judged']} 攻破 "
              f"= {out['summary']['asr']}%  跳过 {out['summary']['skipped']} 条  "
              f"耗时 {out['meta']['seconds']}s", flush=True)
        for f in findings[:10]:
            print(f"  [{f['severity']:6}] {f['id']:16} {f['title'][:34]}  {','.join(f['evidence'])[:40]}")
    return out


def _clip(text: str, n: int) -> str:
    text = str(text or "")
    return text if len(text) <= n else text[:n] + "…"


def _repro(target: str, payload: str) -> str:
    """给一条能直接粘到终端里复现的命令。

    报告里写「攻破了」没有意义，得让人三秒钟能自己验证一遍。
    """
    if target in ("inproc", "in-process", "local"):
        return ("python run_once.py run <case-id>")
    body = json.dumps({"message": payload[:400]}, ensure_ascii=False)
    body = body.replace("'", "'\\''")
    return f"curl -s {target} -H 'Content-Type: application/json' -d '{body}'"


def main():
    ap = argparse.ArgumentParser(description="AI 安全扫描：给目标，出 findings")
    ap.add_argument("--target", default="inproc",
                    help="被测 agent 的 HTTP 地址；inproc = 内置靶子")
    ap.add_argument("--budget", type=int, default=100, help="抽样条数，0 = 全量")
    ap.add_argument("--cases", default=DEFAULT_CASES)
    ap.add_argument("--strength", default="strong", help="strong,medium,weak 可逗号组合，空=全部")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--hard", action="store_true", help="给内置靶子套加固提示词（对照用）")
    ap.add_argument("--case-timeout", type=float, default=240.0)
    ap.add_argument("--out", default="findings.json")
    args = ap.parse_args()

    res = scan(target=args.target, budget=args.budget, cases_path=args.cases,
               strength=args.strength, seed=args.seed,
               case_timeout=args.case_timeout, hard=args.hard)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=1)
    print(f"\n结果已写入 {args.out}（{len(res['findings'])} 条 finding）")


if __name__ == "__main__":
    main()
