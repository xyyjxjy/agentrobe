"""LangChainRunner：用原生 LangChain agent 的编排实现。

和 ReActRunner 的区别（这是"编排实现是变量"实验的核心）：
    ReActRunner  —— JSON 文本协议，任何模型都能跑
    LangChainRunner —— 原生 tool_calls 协议，需要支持 function calling 的模型

两者共享 ToolRegistry 和 TraceStore，输出统一的 Trace 结构，
所以可以在同一个 EvalHarness 下对比。真实对比数据见 docs/results.md：
同样载荷、同样防御，手写 12.5% vs LangChain 37.5%（p=0.0005）。
"""

from __future__ import annotations

import time

from agentkit.core import ToolRegistry, Trace, TraceStore
from agentkit.runner import BaseRunner


class LangChainRunner(BaseRunner):
    """基于 LangChain 1.x create_agent 的编排。

    真实使用时传一个 LangChain chat model（ChatOpenAI / ChatOllama）：
        runner = LangChainRunner(tools, model=ChatOpenAI(...))
    这里不强制依赖 langchain 包——没装时给清晰的报错，
    保证 agentkit 核心离线可用。
    """

    def __init__(self, tools: ToolRegistry, model=None,
                 store: TraceStore | None = None, max_steps: int = 6,
                 system_prompt: str = ""):
        super().__init__(tools, store, max_steps)
        self.model = model
        self.system_prompt = system_prompt
        self._agent = None

    def _build_agent(self):
        if self._agent is None:
            try:
                from langchain.agents import create_agent
            except ImportError as e:  # noqa: BLE001
                raise RuntimeError(
                    "LangChainRunner 需要 langchain>=1.0。"
                    "装到独立 venv：pip install langchain langchain-openai") from e
            if self.model is None:
                raise RuntimeError("LangChainRunner 需要一个 chat model（如 ChatOpenAI）")
            from langchain_core.tools import StructuredTool
            from pydantic import create_model

            lc_tools = []
            for spec in self.tools._tools.values():
                # 【关键】显式构造 args_schema，否则 LangChain 会从 **kw 推断出
                # 错误的 schema（把参数塞进一个叫 kw 的字段），模型传的 query
                # 永远到不了工具函数，导致无限重试。
                type_map = {"str": str, "int": int, "float": float, "bool": bool}
                fields = {k: (type_map.get(t, str), ...)
                          for k, t in spec.parameters.items()}
                ArgsModel = create_model(f"{spec.name}_Args", **fields)

                n = spec.name  # 闭包绑定，避免循环变量陷阱
                def make_fntool(tool_name):
                    def fn(**kwargs):
                        return self.tools.call(tool_name, kwargs)
                    return fn

                lc_tools.append(StructuredTool.from_function(
                    func=make_fntool(n),
                    name=spec.name,
                    description=spec.description,
                    args_schema=ArgsModel,  # ← 修复点
                ))
            self._agent = create_agent(
                self.model, lc_tools,
                system_prompt=self.system_prompt or self._default_prompt())
        return self._agent

    def _default_prompt(self) -> str:
        tools_desc = "\n".join(f"- {s.name}: {s.description}"
                               for s in self.tools._tools.values())
        return f"你是内部资料助手。可用工具：\n{tools_desc}"

    def step(self, messages: list[dict], trace: Trace) -> tuple[bool, str]:
        """LangChain 的 agent.invoke 是一次跑完的，所以在 run 层覆盖。"""
        raise NotImplementedError("LangChainRunner 覆盖 run() 而非 step()")

    def run(self, user_input: str, session_id: str | None = None) -> Trace:
        sid = session_id or f"s-{int(time.time()*1000)}"
        trace = self.store.new(sid)
        trace.input = user_input
        t0 = time.time()
        try:
            agent = self._build_agent()
            res = agent.invoke({"messages": [{"role": "user", "content": user_input}]})
            msgs = res.get("messages", [])
            # 从 AIMessage 的 tool_calls + ToolMessage 提取，写进统一 trace
            pending = {}
            for m in msgs:
                mtype = getattr(m, "type", "")
                content = str(getattr(m, "content", ""))
                if mtype == "ai":
                    for tc in getattr(m, "tool_calls", []) or []:
                        if isinstance(tc, dict):
                            pending[tc.get("id", "")] = {
                                "name": tc.get("name", ""),
                                "args": tc.get("args", {}),
                            }
                    trace.steps.append({"role": "assistant", "content": content[:800]})
                elif mtype == "tool":
                    info = pending.pop(getattr(m, "tool_call_id", ""), {})
                    trace.tool_calls.append({
                        "name": getattr(m, "name", "") or info.get("name", ""),
                        "args": info.get("args", {}),
                        "ok": True,
                        "result": content[:300],
                    })
                    trace.steps.append({"role": "tool", "name": info.get("name", ""),
                                        "result": content[:800]})
            trace.answer = str(msgs[-1].content) if msgs else ""
            trace.finish = getattr(msgs[-1], "response_metadata", {}).get(
                "finish_reason", "") if msgs else ""
        except Exception as e:  # noqa: BLE001
            trace.error = f"{type(e).__name__}: {e}"
        trace.total_ms = (time.time() - t0) * 1000
        self.store.save(trace)
        return trace
