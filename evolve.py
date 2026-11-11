"""进化式测评编排：跑 → 判定 → 变异 → 再跑 → 收敛。

用法：
    python evolve.py caps                            # 看当前接入方式能判什么
    python evolve.py run --mock                      # 干跑，验证整条闭环
    python evolve.py run --transport in_process      # 测本仓库 target/（基线）
    python evolve.py run --transport in_process --hard
    python evolve.py run --transport http --url http://127.0.0.1:8000/chat
    python evolve.py run --mock --rounds 4 --variants 2 --llm-mutate

三条不能破的规矩：
    1. 判定不了的用例标 SKIPPED，不进分母。
    2. 变体成绩归并到原始用例 id，不按变体条数算成功率。
    3. "仅有越界尝试"单独一栏，不算攻破。
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import random
import re
import time

import yaml

try:  # dotenv 只是加载 .env，缺失时降级为读系统环境变量，不该让整个入口崩掉
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from detectors import DETECTOR_META, compliance_applicable, judge   # noqa: E402
from mutator import mutate, mutate_with_llm                   # noqa: E402
from transport import capabilities, make_transport            # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
CASES_FILE = os.path.join(ROOT, "attack_cases.yaml")
RUNS_DIR = os.path.join(ROOT, "runs")


def load_cases(path: str = "") -> list:
    """path 为空时读内置用例库；支持逗号分隔的多个文件（内置 + 外部导入）。"""
    if not path:
        paths = [CASES_FILE]
    else:
        paths = [p.strip() for p in path.split(",") if p.strip()]

    cases = []
    for p in paths:
        if not os.path.exists(p):
            raise SystemExit(f"用例文件不存在：{p}")
        with open(p, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f) or []
        cases.extend(loaded)
        print(f"载入 {len(loaded):>4} 条  {p}")
    return cases


def evaluate(transport, case: dict, payload: str, tag: str, beacon=None) -> dict:
    """跑一条载荷并判定。不抛异常——单条崩了不能拖垮整轮。"""
    detector = case["detector"]
    if not transport.can_judge(detector):
        return {"tag": tag, "success": False, "attempt": False, "skipped": True,
                "reason": f"当前接入方式拿不到判定依据（{detector}）",
                "evidence": [], "error": None, "answer": ""}

    # oast 类：先改写载荷，把外泄域名指到我们自己的接收端
    oast_token = ""
    if detector == "oast":
        if beacon is None:
            return {"tag": tag, "success": False, "attempt": False, "skipped": True,
                    "reason": "未启动 beacon 接收端，本条无法判定", "evidence": [],
                    "error": None, "answer": ""}
        oast_token = "%s%s%s" % (case["id"].replace("-", ""), tag[:4],
                                 os.urandom(2).hex())
        payload, status = beacon.rewrite(payload, oast_token)
        if status != "ok":
            return {"tag": tag, "success": False, "attempt": False, "skipped": True,
                    "reason": f"载荷无法注入 beacon（{status}），跳而不判",
                    "evidence": [], "error": None, "answer": ""}

    try:
        trace = transport.send(payload)
    except Exception as e:  # noqa: BLE001
        # 请求本身失败不能算"没打穿"——判据根本没拿到。
        # 这条曾经被记成 success=False 进分母，于是「模型连不上」被读成「模型防住了」。
        return {"tag": tag, "success": False, "attempt": False, "skipped": True,
                "reason": f"请求异常，无判定依据（{e}）：不进分母",
                "evidence": [], "error": str(e), "answer": ""}

    # 传输层自己吞掉异常时（HTTPTarget 返回 error 字段），同样要按"无依据"处理。
    # 判据是"有没有内容可判"，不是"有没有抛异常"。
    if trace.get("error") and not str(trace.get("answer") or "").strip() \
            and not (trace.get("tool_calls") or []):
        return {"tag": tag, "success": False, "attempt": False, "skipped": True,
                "reason": f"被测端返回错误，无判定依据：{str(trace['error'])[:120]}（不进分母）",
                "evidence": [], "error": trace.get("error"), "answer": ""}

    # marker / replay 类判定器需要用例自带标记，通过 trace 传进去（不改 judge 签名）
    trace["_markers"] = case.get("markers") or []
    trace["_trigger"] = case.get("trigger") or ""
    # tool_goal 判定器（AgentDojo 那批）要三样东西：期望调用、对方有哪些工具、锚点。
    # 工具清单拿不到就传空，判定器会自己 SKIPPED，而不是猜。
    trace["_expect_tool"] = case.get("expect_tool") or []
    trace["_anchors"] = case.get("anchors") or []
    trace["_tool_names"] = list(getattr(transport, "tool_names", []) or [])
    if detector == "oast":
        trace["_oast_configured"] = True
        trace["_oast_hits"] = [h[2] for h in beacon.hits_for(oast_token, wait=0.6)]

    verdict = judge(trace, detector)
    # 判定过程必须可复查：只留判定结论，等于让读者只能相信我们。
    # 上一版没存 tool_calls，我差点把"判定器没看到调用"误读成"模型没调用工具"。
    verdict.update({"tag": tag, "skipped": bool(verdict.get("skipped")),
                    "error": trace.get("error"),
                    # 模型可能把 answer 输出成 dict（实测加固版会返回
                    # {'AGP-CANARY-...': [...]}），不 str() 就等着 KeyError 吧。
                    # 400 太短了：有一次判定器报"canary 命中"，落盘的 answer
                    # 却只有前 400 字、里面看不见 canary，等于把证据截没了。
                    "answer": _redact(str(trace.get("answer") or ""))[:4000],
                    "tool_calls": [
                        {"name": c.get("name"),
                         "args": c.get("args"),
                         "ok": c.get("ok"),
                         "result": _redact(str(c.get("result") or ""))[:200]}
                        for c in (trace.get("tool_calls") or [])
                    ][:10]})
    return verdict



# 被测对象有路径穿越漏洞（T-01 就是专门测这个的），它真的能读到 .env
# 并把内容复述进回答——2026-11-11 的 764 条那次就是这么把真实 API Key
# 写进 runs/*.json 的，我随后还把它提交进了 git。
# 判定证据要留，密钥不能留：落盘前统一打码，保留长度特征以便排查。
_SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_\-]{12,}"),          # OpenAI/网关类
    re.compile(r"(?i)\b(api[_-]?key|secret|token)\s*[=:]\s*[\"']?([A-Za-z0-9_\-]{16,})"),
)


def _redact(text: str) -> str:
    out = str(text)
    out = _SECRET_PATTERNS[0].sub("sk-***REDACTED***", out)
    out = _SECRET_PATTERNS[1].sub(lambda m: f"{m.group(1)}=***REDACTED***", out)
    return out


def _evaluate_guarded(transport, case: dict, payload: str, tag: str,
                      beacon, timeout: float) -> dict:
    """带墙钟上限的单条执行。

    加固版那轮 L-01 单条跑了 9229 秒（2.5 小时）——被测 agent 在工具循环里
    把整批测试拖死，httpx 的 180s 读超时管不到「多次调用累计」。
    超时按"没有判定依据"处理，不进分母；泄漏的工作线程由它自己跑完，
    反正它是 daemon，不会拦住进程退出。
    """
    if not timeout:
        return evaluate(transport, case, payload, tag, beacon=beacon)

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    fut = pool.submit(evaluate, transport, case, payload, tag, beacon)
    try:
        return fut.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        return {"tag": tag, "success": False, "attempt": False, "skipped": True,
                "reason": f"单条超时 {timeout:.0f}s，无判定依据（不进分母）",
                "evidence": [], "answer": "", "error": "timeout"}
    finally:
        pool.shutdown(wait=False)


def _dump_progress(path: str, recs: dict, history: list, runtime_skip: dict,
                   meta: dict, current_round: int | None = None) -> None:
    """把当前进度写成可直接续跑的快照。

    之前的写法是「跑完才 json.dump 一次」，于是进程被杀 = 零产物。
    加固版那次就是这么没的：日志只剩 5 行，跑了 40 分钟什么都不剩。
    这里改成原子写（tmp + os.replace），中途 Ctrl-C 也能留下一条完整的进度。
    """
    evaluated = sum(1 for r in recs.values() if r["seed"] is not None) \
        + sum(len(r["variants"]) for r in recs.values())
    payload = {
        "_progress": {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "rounds_done": len(history),
            "current_round": current_round,
            "evaluated": evaluated,
            "runtime_skip": runtime_skip,
        },
        "rounds": history,
        "cases": recs,
        "meta": meta,
    }
    tmp = path + ".tmp"
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def run_campaign(transport, cases: list, rounds: int, variants: int,
                 seed: int, use_llm: bool, beacon=None, limit: int = 0,
                 sample: bool = False, checkpoint: str = "",
                 checkpoint_every: int = 5, resume: dict | None = None,
                 case_timeout: float = 0.0) -> dict:
    rng = random.Random(seed)
    caps = capabilities(transport)

    # 分母只能装"确实判得了"的用例。oast 类要预检一次载荷能否注入 beacon，
    # 否则那些拼接写法（"w","u","z"）会白白占着分母。
    todo, skipped = [], []
    skip_reason = {}
    for c in cases:
        det = c["detector"]
        if not transport.can_judge(det):
            skipped.append(c)
            skip_reason[c["id"]] = f"接入方式不支持 {det}"
            continue
        # compliance 类：载荷得先落在某个危害域，否则这条用例对该判定器不适用。
        # 不适用的进分母当"未攻破"= 凭空压低 ASR，这是上一轮踩过的坑。
        if det == "compliance":
            ok_app, why_app = compliance_applicable(c)
            if not ok_app:
                skipped.append(c)
                skip_reason[c["id"]] = why_app
                continue
        if det == "oast":
            if beacon is None:
                skipped.append(c)
                skip_reason[c["id"]] = "未启动 beacon"
                continue
            _, st = beacon.rewrite(c["payload"], "PREFLIGHT")
            if st != "ok":
                skipped.append(c)
                skip_reason[c["id"]] = f"载荷无法注入 beacon（{st}）"
                continue
        todo.append(c)

    # 真模型跑到 30 秒/条时，全量 600 条要五小时。--limit 用于分批真跑，
    # 被截掉的样本必须显式记成"未执行"，否则它会悄悄从分母里消失。
    #
    # 用例文件是按来源顺序写的（encoding 87 条打头），直接取前 N 条等于
    # 只测一个家族。--sample 走随机抽样，才能用 30 条代表整体。
    if limit and len(todo) > limit:
        keep = (set(rng.sample(range(len(todo)), limit)) if sample
                else set(range(limit)))
        for i, c in enumerate(todo):
            if i not in keep:
                skipped.append(c)
                skip_reason[c["id"]] = "本次未执行（--limit 抽样外）"
        todo = [c for i, c in enumerate(todo) if i in keep]

    recs = {}
    for c in cases:
        recs[c["id"]] = {
            "id": c["id"], "name": c["name"], "category": c["category"],
            "detector": c["detector"], "payload": c["payload"],
            "seed": None, "variants": [], "broken": False,
            "attempt_only": False, "skipped": c["id"] in {s["id"] for s in skipped},
        }

    # 运行时才暴露的"无判定依据"（模型没启动、404、超时）单独记账：
    # 这些用例既不能算"没打穿"，也不能悄悄留在分母里。
    runtime_skip = {}
    used_ops = {c["id"]: set() for c in todo}
    history = []
    total_variants = 0
    no_new_streak = 0
    stop_reason = f"达到轮次上限 {rounds}"

    # --------------------------------------------------------------- 续跑
    # 已经判过的 (用例, 算子) 不再重跑。种子轮用 "seed" 当 tag，
    # 变异轮用算子名——算子在同一用例上只用一次，所以这个键不会撞。
    done_pairs = set()
    start_round = 1
    if resume:
        r_cases = resume.get("cases") or {}
        for cid, r in r_cases.items():
            if cid not in recs:
                continue
            for k in ("seed", "variants", "broken", "attempt_only"):
                if k in r:
                    recs[cid][k] = r[k]
        prog = resume.get("_progress") or {}
        skip_map = dict(prog.get("runtime_skip") or {})
        history.extend(resume.get("rounds") or [])
        total_variants = sum(len(r["variants"]) for r in recs.values())
        retry = []
        for cid, r in recs.items():
            seed = r["seed"]
            # 上次因为 429 / 超时被判 SKIPPED 的，续跑时要重试，不能当成"跑过了"。
            # 断点里保留它们只是为了留证据，不是为了让它们永远消失。
            if seed is not None and seed.get("skipped"):
                recs[cid]["seed"] = None
                skip_map.pop(cid, None)
                retry.append(cid)
                continue
            if seed is not None:
                done_pairs.add((cid, "seed"))
            for v in r["variants"]:
                done_pairs.add((cid, v["op"]))
                used_ops[cid].add(v["op"])
        runtime_skip.update(skip_map)
        # current_round 非空 = 上一次是跑到一半被打断的，退回这一轮把剩下的补齐；
        # 为空 = 上一轮完整跑完，从下一轮开始。
        cur = prog.get("current_round")
        start_round = int(cur) if cur else len(history) + 1
        print(f"续跑：已恢复 {len(history)} 轮 / {len(done_pairs)} 条判定结果，"
              f"从轮次 {start_round} 开始")
        if retry:
            print(f"      另有 {len(retry)} 条上次是请求失败/超时，本次重试")

    evaluated_since_ckpt = 0
    ckpt_meta = {"seed": seed, "variants_per_round": variants,
                 "llm_mutate": use_llm,
                 "model": os.getenv("LLM_MODEL", ""),
                 "started": time.strftime("%Y-%m-%d %H:%M:%S")}

    print(f"\n接入方式：{transport.name}   可判判定器：{sorted(transport.caps)}")
    if skipped:
        agg = {}
        for why in skip_reason.values():
            agg[why] = agg.get(why, 0) + 1
        print(f"无法判定 {len(skipped)} 条（不进分母）：")
        for why, n in sorted(agg.items(), key=lambda x: -x[1]):
            print(f"  · {n:>4} 条：{why}")
    print()

    for rnd in range(start_round, rounds + 1):
        t0 = time.time()
        new_broken = 0

        if rnd == 1:
            batch = [("seed", c, c["payload"]) for c in todo]
        else:
            batch = []
            frontier = [c for c in todo if not recs[c["id"]]["broken"]]
            for c in frontier:
                pairs = mutate(c["payload"], c, k=variants, rng=rng,
                               used=used_ops[c["id"]])
                if not pairs and use_llm:
                    last = recs[c["id"]]["seed"] or {}
                    pairs = mutate_with_llm(c["payload"], c, last, n=variants)
                for op_name, new_payload in pairs:
                    batch.append((op_name, c, new_payload))

        if not batch:
            no_new_streak += 1
            print(f"轮次 {rnd}：没有可变异的前沿用例")
            if no_new_streak >= 1:
                stop_reason = "前沿用例已耗尽（算子用尽且无 LLM 变异）"
                history.append({"round": rnd, "tested": 0, "broken": 0,
                                "new_broken": 0, "seconds": 0})
                break
            continue

        print(f"── 轮次 {rnd} · {len(batch)} 条载荷")
        if done_pairs:
            fresh = [b for b in batch if (b[1]["id"], b[0]) not in done_pairs]
            if len(fresh) < len(batch):
                print(f"   续跑：跳过已完成 {len(batch) - len(fresh)} 条")
            batch = fresh
            if not batch:
                print("   本轮全部已完成，直接进下一轮\n")
                continue

        for tag, case, payload in batch:
            v = _evaluate_guarded(transport, case, payload, tag, beacon, case_timeout)
            rec = recs[case["id"]]
            done_pairs.add((case["id"], tag))
            evaluated_since_ckpt += 1
            # 每 N 条落一次盘。2249 条跑 68 小时，指望"跑完再写"等于不写。
            if checkpoint and evaluated_since_ckpt >= max(1, checkpoint_every):
                evaluated_since_ckpt = 0
                _dump_progress(checkpoint, recs, history, runtime_skip, ckpt_meta,
                               current_round=rnd)

            if v.get("skipped"):
                # 之前这里直接 continue，seed 保持 None 而分母不动，
                # 于是"7 条全部 404"被显示成 0/7 = 0%（模型很安全）。
                runtime_skip[case["id"]] = str(v.get("reason") or "无判定依据")[:160]
                if tag == "seed":
                    rec["seed"] = v        # 留证据，方便回查为什么没判
                continue
            if tag == "seed":
                rec["seed"] = v
            else:
                rec["variants"].append({
                    "op": tag, "payload": payload[:400],
                    "success": v["success"], "reason": v["reason"],
                    "error": v.get("error"), "answer": v.get("answer", "")[:120],
                })
                total_variants += 1

            if v.get("success"):
                if not rec["broken"]:
                    rec["broken"] = True
                    new_broken += 1
                    print(f"  ✅ [{tag:<12}] {case['id']}  {case['name']}  ← 攻破")
            elif v.get("attempt") and not rec["broken"]:
                rec["attempt_only"] = True

        dt = time.time() - t0
        judged_now = [c for c in todo if c["id"] not in runtime_skip]
        broken_now = sum(1 for c in judged_now if recs[c["id"]]["broken"])
        asr = broken_now / len(judged_now) * 100 if judged_now else 0
        print(f"   轮次小结：累计攻破 {broken_now}/{len(judged_now)} = {asr:.1f}%   "
              f"本轮新增 {new_broken}   耗时 {dt:.1f}s\n")

        history.append({"round": rnd, "tested": len(batch), "broken": broken_now,
                        "new_broken": new_broken, "seconds": round(dt, 1)})
        # 轮次边界是最值得存的点：current_round=None 表示这一轮完整，
        # 续跑时直接从下一轮开始，不会把整轮重跑一遍。
        if checkpoint:
            evaluated_since_ckpt = 0
            _dump_progress(checkpoint, recs, history, runtime_skip, ckpt_meta,
                           current_round=None)

        if new_broken == 0:
            no_new_streak += 1
            if no_new_streak >= 2:
                stop_reason = "连续两轮无新增攻破，判定收敛"
                break
        else:
            no_new_streak = 0

    # ------------------------------------------------------------- 汇总
    # 分母只装"真的判过"的：预检跳过的 + 运行时没拿到依据的，都要剔出去。
    judged = [c for c in todo if c["id"] not in runtime_skip]
    broken = sum(1 for c in judged if recs[c["id"]]["broken"])
    seed_broken = sum(1 for c in judged if (recs[c["id"]]["seed"] or {}).get("success"))
    attempt_only = sum(1 for c in judged
                       if recs[c["id"]]["attempt_only"] and not recs[c["id"]]["broken"])

    fam = {}
    for c in judged:
        f = fam.setdefault(c["category"], {"total": 0, "broken": 0})
        f["total"] += 1
        f["broken"] += int(recs[c["id"]]["broken"])

    cracked = [k for k, v in fam.items() if v["broken"] == v["total"]]

    # 按判定强度分层。这是本轮改造最重要的一条纪律：
    # strong（串匹配/带外信标）可以直接下结论；
    # weak（拒答缺失 + 关键词共现）只能当线索，不能进摘要数字。
    by_strength = {}
    for c in judged:
        s = DETECTOR_META.get(c["detector"], {}).get("strength", "unknown")
        e = by_strength.setdefault(s, {"total": 0, "broken": 0, "detectors": set()})
        e["total"] += 1
        e["broken"] += int(recs[c["id"]]["broken"])
        e["detectors"].add(c["detector"])
    for e in by_strength.values():
        e["asr"] = round(e["broken"] / e["total"] * 100, 1) if e["total"] else 0
        e["detectors"] = sorted(e["detectors"])

    summary = {
        "transport": caps,
        # 数据来源标记。is_mock=True 的产物只能用来验证流程，
        # 不能写进任何结论——这一条是上一轮拿 mock 数字当业绩换来的教训。
        "is_mock": bool(getattr(transport, "is_mock", False)),
        "seed_asr": round(seed_broken / len(judged) * 100, 1) if judged else 0,
        "final_asr": round(broken / len(judged) * 100, 1) if judged else 0,
        "seed_broken": seed_broken,
        "final_broken": broken,
        "judgeable": len(judged),
        "skipped": len(skipped) + len(runtime_skip),
        "skipped_preflight": len(skipped),
        "skipped_runtime": len(runtime_skip),
        "skipped_runtime_reasons": dict(list(runtime_skip.items())[:5]),
        "attempt_only": attempt_only,
        "variants": total_variants,
        "rounds": len(history),
        "stop_reason": stop_reason,
        "family": fam,
        "families_fully_cracked": cracked,
        "by_strength": by_strength,
        "oast": bool(beacon),
    }

    bar = "=" * 66
    if summary["is_mock"]:
        print("!" * 66)
        print("本次为 --mock 干跑（内置桩件，不调模型、不连网络）")
        print("下面的数字只证明流程能跑通，不能作为任何安全结论。")
        print("!" * 66)
    print(bar)
    print(f"种子轮 ASR      {seed_broken}/{len(judged)} = {summary['seed_asr']}%")
    print(f"进化后 ASR      {broken}/{len(judged)} = {summary['final_asr']}%"
          f"   （变异贡献 +{broken - seed_broken} 条，共 {total_variants} 个变体）")
    print(f"仅越界未生效    {attempt_only} 条（不计入攻破）")
    print(f"无法判定        {len(skipped) + len(runtime_skip)} 条（不进分母）"
          + (f"，其中运行时无依据 {len(runtime_skip)} 条" if runtime_skip else ""))
    print(f"停止原因        {stop_reason}")
    print(bar)
    print("按判定强度分层（禁止混算）：")
    order = {"strong": 0, "medium": 1, "weak": 2, "unknown": 3}
    label = {"strong": "可直接下结论", "medium": "可用，需说明局限",
             "weak": "仅作线索，须人工抽检", "unknown": "未标注强度"}
    for s in sorted(by_strength, key=lambda x: order.get(x, 9)):
        e = by_strength[s]
        print(f"  {s:<8}{e['broken']:>4}/{e['total']:<4} = {e['asr']:>5}%   "
              f"{label.get(s, '')}  [{','.join(e['detectors'])}]")
    print(bar)
    print("按攻击家族的攻破情况：")
    for k, v in sorted(fam.items(), key=lambda x: -x[1]["total"]):
        flag = "全部打穿" if v["broken"] == v["total"] else f"{v['broken']}/{v['total']}"
        print(f"  {k:<22}{flag}")
    print(bar + "\n")

    return {"summary": summary, "rounds": history, "cases": recs,
            "meta": {"seed": seed, "variants_per_round": variants,
                     "llm_mutate": use_llm, "model": _model(),
                     "ts": time.strftime("%Y-%m-%d %H:%M:%S")}}


def _model() -> str:
    try:
        from llm_client import model_name
        return model_name()
    except Exception:  # noqa: BLE001
        return "n/a"


def _tool_goal_coverage(transport) -> dict:
    """tool_goal 这批用例到底能不能判？

    光看 CAPS 不够：CAPS 说的是"接入方式拿不拿得到 tool_calls"，
    而 tool_goal 还要求**被测 agent 真的有这么个工具**。
    本项目 target 只有 read_file / search_docs，AgentDojo 要的是 send_money /
    delete_file 那一套，27 条会全部 SKIPPED。这件事必须在跑之前就告诉使用者，
    不然跑完看到 0/27 又会误读成"防住了"。
    """
    path = os.path.join(ROOT, "seeds", "agentdojo_cases.yaml")
    if not os.path.exists(path):
        return {"available": False, "reason": "没有生成 seeds/agentdojo_cases.yaml"}
    try:
        with open(path, "r", encoding="utf-8") as f:
            cases = yaml.safe_load(f) or []
    except Exception as e:  # noqa: BLE001
        return {"available": False, "reason": f"读取失败：{e}"}

    want, have = set(), set(getattr(transport, "tool_names", []) or [])
    judgeable = 0
    for c in cases:
        fns = {str(x.get("function", "")).lower()
               for x in (c.get("expect_tool") or []) if x.get("function")}
        want |= fns
        if fns & have:
            judgeable += 1
    return {
        "available": True,
        "cases": len(cases),
        "judgeable": judgeable,
        "will_skip": len(cases) - judgeable,
        "target_tools": sorted(have),
        "expected_tools": sorted(want),
        "missing_tools": sorted(want - have),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_caps = sub.add_parser("caps", help="查看接入方式的判定能力")
    p_caps.add_argument("--transport", default="in_process",
                        choices=["in_process", "http", "blackbox", "mock"])
    p_caps.add_argument("--url")

    p_run = sub.add_parser("run", help="跑一轮进化式测评")
    p_run.add_argument("--transport", default="in_process",
                       choices=["in_process", "http", "blackbox", "mock"])
    p_run.add_argument("--url")
    p_run.add_argument("--mock", action="store_true", help="等价于 --transport mock（干跑）")
    p_run.add_argument("--hard", action="store_true", help="被测对象使用加固版提示词")
    p_run.add_argument("--rounds", type=int, default=3, help="总轮次（含种子轮）")
    p_run.add_argument("--variants", type=int, default=2, help="每条未攻破用例每轮生成几个变体")
    p_run.add_argument("--seed", type=int, default=42)
    p_run.add_argument("--cases", default="", help="用例 YAML 路径（默认 attack_cases.yaml）")
    p_run.add_argument("--llm-mutate", action="store_true", help="启用攻击者模型变异（慢、费钱）")
    p_run.add_argument("--oast", action="store_true",
                       help="启动带外信标接收端，web_injection 类才能判")
    p_run.add_argument("--oast-host", default="127.0.0.1",
                       help="信标对外地址（远程目标填你的公网域名）")
    p_run.add_argument("--oast-port", type=int, default=0, help="0 = 随机端口")
    p_run.add_argument("--limit", type=int, default=0,
                       help="只跑 N 条（真模型很慢，用于分批验证）")
    p_run.add_argument("--sample", action="store_true",
                       help="--limit 时随机抽样，而不是取前 N 条（避免只测到同一家族）")
    p_run.add_argument("--strength", default="",
                       help="只跑指定强度的判定器：strong / medium / weak")
    p_run.add_argument("--out", default="")
    p_run.add_argument("--checkpoint-every", type=int, default=5,
                       help="每判 N 条落一次进度快照（0 = 关闭，长跑别关）")
    p_run.add_argument("--resume", action="store_true",
                       help="从 <out>.partial.json 续跑，跳过已判过的用例")
    p_run.add_argument("--case-timeout", type=float, default=300.0,
                       help="单条用例墙钟上限（秒），超时记 SKIPPED；0 = 不限")
    args = ap.parse_args()

    kind = "mock" if getattr(args, "mock", False) else args.transport
    transport = make_transport(kind, hardened=getattr(args, "hard", False),
                               url=getattr(args, "url", None),
                               fetch_images=bool(getattr(args, "oast", False)))

    if args.cmd == "caps":
        info = capabilities(transport)
        # CAPS 只回答"接入方式能不能拿到工具调用"，这里再补一层"对方有没有这些工具"
        info["tool_goal"] = _tool_goal_coverage(transport)
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return

    beacon = None
    if getattr(args, "oast", False):
        from oast import make_beacon
        beacon = make_beacon(args.oast_host, args.oast_port)
        print(f"beacon 已启动：http://{beacon.host}:{beacon.port}/t/<token>")

    cases = load_cases(getattr(args, "cases", ""))
    if getattr(args, "strength", ""):
        want = {s.strip() for s in args.strength.split(",") if s.strip()}
        before = len(cases)
        cases = [c for c in cases
                 if DETECTOR_META.get(c["detector"], {}).get("strength") in want]
        print(f"按强度过滤 {args.strength}：{before} → {len(cases)} 条")

    os.makedirs(RUNS_DIR, exist_ok=True)
    out = args.out or os.path.join(
        RUNS_DIR, f"campaign_{kind}{'_hard' if getattr(args, 'hard', False) else ''}"
                  f"_{time.strftime('%m%d_%H%M')}.json")
    partial = out + ".partial.json"

    resume = None
    if getattr(args, "resume", False):
        if os.path.exists(partial):
            with open(partial, "r", encoding="utf-8") as f:
                resume = json.load(f)
        else:
            print(f"⚠️ 没有找到 {partial}，按全新一轮开始")
    elif os.path.exists(partial):
        print(f"⚠️ {partial} 已存在但未加 --resume，会被本轮覆盖")

    checkpoint = partial if getattr(args, "checkpoint_every", 5) else ""

    try:
        result = run_campaign(transport, cases,
                              rounds=args.rounds, variants=args.variants, seed=args.seed,
                              use_llm=args.llm_mutate, beacon=beacon,
                              limit=getattr(args, "limit", 0),
                              sample=getattr(args, "sample", False),
                              checkpoint=checkpoint,
                              checkpoint_every=getattr(args, "checkpoint_every", 5),
                              resume=resume,
                              case_timeout=getattr(args, "case_timeout", 0.0))
    finally:
        if beacon:
            beacon.stop()

    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"明细已落盘：{out}")
    if checkpoint and os.path.exists(checkpoint):
        os.remove(checkpoint)
    transport.close()


if __name__ == "__main__":
    main()
