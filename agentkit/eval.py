"""EvalHarness：框架自带的评测闭环。

把 AgentProbe 的判定器方法论"框架化"：
    - 吃统一的 Trace（不管 agent 是手写 ReAct 还是 LangChain）
    - 用注册的断言函数判定
    - 分层统计，不混算
    - 输出可复现报告

这就是"框架自带评测"——别的 agent 框架没有，是你的差异点。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field


@dataclass
class Assertion:
    """一条行为断言：名字 + 判定函数 + 强度。"""
    name: str
    fn: callable           # trace -> {success, reason, evidence}
    strength: str = "strong"  # strong / medium / weak


@dataclass
class EvalResult:
    case_id: str
    verdicts: dict = field(default_factory=dict)
    broken: bool = False

    def to_dict(self):
        return {"case_id": self.case_id, "verdicts": self.verdicts,
                "broken": self.broken}


class EvalHarness:
    """统一评测入口：runner + 断言集 -> 报告。"""

    def __init__(self, runner):
        self.runner = runner
        self.assertions: dict[str, Assertion] = {}

    def add(self, assertion: Assertion):
        self.assertions[assertion.name] = assertion

    def evaluate(self, cases: list[dict]) -> dict:
        """cases: [{id, payload, expect_strength?}]"""
        results = []
        t0 = time.time()
        for c in cases:
            trace = self.runner.run(c["payload"], session_id=f"eval-{c['id']}")
            verdicts = {}
            for name, a in self.assertions.items():
                if c.get("strength") and a.strength != c["strength"]:
                    continue
                try:
                    verdicts[name] = a.fn(trace.to_dict())
                except Exception as e:  # noqa: BLE001
                    verdicts[name] = {"success": False,
                                      "reason": f"断言异常：{e}"}
            broken = any(v.get("success") for v in verdicts.values())
            results.append(EvalResult(c["id"], verdicts, broken))

        # 分层统计（禁止混算）
        by_strength = {}
        for a in self.assertions.values():
            ids = [r for r in results if a.name in r.verdicts]
            if ids:
                n_broken = sum(1 for r in ids if r.verdicts[a.name].get("success"))
                by_strength.setdefault(a.strength, {"total": 0, "broken": 0})
                by_strength[a.strength]["total"] += len(ids)
                by_strength[a.strength]["broken"] += n_broken

        for s, d in by_strength.items():
            d["asr"] = round(d["broken"] / d["total"] * 100, 1) if d["total"] else 0

        return {
            "runner": type(self.runner).__name__,
            "total": len(results),
            "broken": sum(1 for r in results if r.broken),
            "by_strength": by_strength,
            "seconds": round(time.time() - t0, 1),
            "results": [r.to_dict() for r in results],
        }

    def report(self, result: dict) -> str:
        lines = [
            f"# EvalHarness 报告 — {result['runner']}",
            "",
            f"用例 {result['total']} 条，攻破 {result['broken']} 条，"
            f"耗时 {result['seconds']}s",
            "",
            "| 强度 | 攻破/总数 | ASR |",
            "|---|---:|---:|",
        ]
        for s, d in result["by_strength"].items():
            lines.append(f"| {s} | {d['broken']}/{d['total']} | {d['asr']}% |")
        return "\n".join(lines)
