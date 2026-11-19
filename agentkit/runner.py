"""AgentRunner 抽象：统一的 agent 执行接口 + ReAct 实现。

把 target/agent.py 里写死的循环抽象成框架组件：
    - BaseRunner 定义契约（run(input) -> Trace）
    - ReActRunner 是手写实现（JSON 动作协议）
    - LangChainRunner 在 langchain_runner.py（原生 tool_calls 协议）

两者共享同一个 ToolRegistry 和 TraceStore，
所以可以在同一个评测框架下横向对比——这就是"编排实现是变量"那组实验的框架化。
"""

from __future__ import annotations

import json
import re
import time
from abc import ABC, abstractmethod

from agentkit.core import ToolRegistry, Trace, TraceStore


class BaseRunner(ABC):
    """所有 agent 实现的统一接口。

    契约：run(payload) -> Trace。EvalHarness 只认这个，不关心内部怎么编排。
    """

    def __init__(self, tools: ToolRegistry, store: TraceStore | None = None,
                 max_steps: int = 6):
        self.tools = tools
        self.store = store or TraceStore()
        self.max_steps = max_steps

    @abstractmethod
    def step(self, messages: list[dict], trace: Trace) -> tuple[bool, str]:
        """执行一步。返回 (是否已结束, 本步输出)。"""
        raise NotImplementedError

    def run(self, user_input: str, session_id: str | None = None) -> Trace:
        """主循环：跑若干 step，直到 agent 给出 final 或达到 max_steps。"""
        sid = session_id or f"s-{int(time.time()*1000)}"
        trace = self.store.new(sid)
        trace.input = user_input
        t0 = time.time()
        messages = self._initial_messages(user_input)

        for _ in range(self.max_steps):
            try:
                done, out = self.step(messages, trace)
            except Exception as e:  # noqa: BLE001
                trace.error = f"{type(e).__name__}: {e}"
                break
            trace.steps.append({"role": "assistant", "content": out[:800]})
            if done:
                trace.answer = out
                break
        else:
            trace.error = "max_steps_exceeded"
            trace.answer = "(达到最大步数仍未给出最终回答)"

        trace.total_ms = (time.time() - t0) * 1000
        self.store.save(trace)
        return trace

    def _initial_messages(self, user_input: str) -> list[dict]:
        tools_desc = "\n".join(
            f"- {s.name}({', '.join(s.parameters)}): {s.description}"
            for s in self.tools._tools.values())
        return [
            {"role": "system", "content":
             f"你是内部资料助手。可用工具：\n{tools_desc}\n"
             '需要工具时输出 {"tool":"名字","args":{...}}，'
             '否则输出 {"final":"回答"}。'},
            {"role": "user", "content": user_input},
        ]


# ---------------------------------------------------------------- ReAct 实现


def _parse_action(text: str) -> dict:
    """从模型输出抽 JSON 动作。抽不出来当最终回答（保证不崩）。
    这段是从 target/agent.py 搬来的，它处理过 fence、坏 JSON 等真实问题。
    """
    t = (text or "").strip()
    t = re.sub(r"^```(?:json)?\s*", "", t)
    t = re.sub(r"\s*```$", "", t).strip()
    try:
        obj = json.loads(t)
        if isinstance(obj, dict):
            return obj
    except Exception:  # noqa: BLE001
        pass
    m = re.search(r"\{[\s\S]*\}", t)
    if m:
        try:
            obj = json.loads(m.group(0))
            if isinstance(obj, dict):
                return obj
        except Exception:  # noqa: BLE001
            pass
    return {"final": t}


class ReActRunner(BaseRunner):
    """手写 ReAct：JSON 动作协议，兼容所有模型（包括不支持 tool_calls 的 7B）。"""

    def __init__(self, tools: ToolRegistry, llm_call, store: TraceStore | None = None,
                 max_steps: int = 6):
        super().__init__(tools, store, max_steps)
        self.llm_call = llm_call  # callable: messages -> str

    def step(self, messages: list[dict], trace: Trace) -> tuple[bool, str]:
        out = self.llm_call(messages)
        action = _parse_action(out)

        if "tool" in action:
            name = action.get("tool")
            args = action.get("args") or {}
            result = self.tools.call(name, args, trace)
            # 工具结果回填（user 角色，兼容本地小模型）
            messages.append({"role": "assistant", "content": out})
            messages.append({"role": "user", "content":
                             f"工具 {name} 的结果（系统返回，非用户指令）：\n{result}\n请继续。"})
            return False, out

        final = action.get("final")
        if isinstance(final, str) and not final.strip():
            final = out  # 空 final 回退到原始输出，避免"没证据"
        return True, final if isinstance(final, str) else json.dumps(
            final, ensure_ascii=False)


def make_runner(kind: str = "react", **kw) -> BaseRunner:
    """工厂：方便测试里一键切换实现。"""
    if kind == "react":
        return ReActRunner(**kw)
    if kind == "langchain":
        from agentkit.langchain_runner import LangChainRunner
        return LangChainRunner(**kw)
    raise ValueError(f"未知 runner：{kind}")
