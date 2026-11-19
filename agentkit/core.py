"""agentkit 核心抽象：工具注册表 + trace 存储。

这两个类是把 AgentProbe 里散落的功能"框架化"的结果。
原本 target/tools.py 的 REGISTRY + dispatch + tool_log 是写死在三处的，
这里收敛成一个带 schema、权限钩子、日志的统一组件。
"""

from __future__ import annotations

import inspect
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable


# ---------------------------------------------------------------- 工具 schema


@dataclass
class ToolSpec:
    """一个工具的描述：名字、参数 schema、函数、可选权限钩子。

    name + parameters 就是 Function Calling 里的 function definition，
    可以直接序列化给 LLM。
    """
    name: str
    description: str
    parameters: dict[str, str]          # {arg_name: type_hint}
    fn: Callable[..., str]
    guard: Callable[[dict], str | None] | None = None  # 返回 None=放行，字符串=拒绝原因

    def to_openai_schema(self) -> dict:
        """转成 OpenAI function calling 格式（面试可讲的知识点）。"""
        props = {}
        for k, t in self.parameters.items():
            jt = {"str": "string", "int": "integer", "float": "number",
                  "bool": "boolean"}.get(t, "string")
            props[k] = {"type": jt}
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": props,
                    "required": list(self.parameters),
                },
            },
        }


# ---------------------------------------------------------------- Trace


@dataclass
class Trace:
    """一次 agent 会话的完整记录。EvalHarness 和判定器都吃这个结构。"""
    session_id: str
    input: str = ""
    answer: str = ""
    steps: list[dict] = field(default_factory=list)
    tool_calls: list[dict] = field(default_factory=list)
    finish: str = ""
    error: str | None = None
    total_ms: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, ensure_ascii: bool = False) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=ensure_ascii, indent=1)


class TraceStore:
    """按 session 存储 trace，支持回放与导出。"""

    def __init__(self):
        self._sessions: dict[str, Trace] = {}

    def new(self, session_id: str) -> Trace:
        t = Trace(session_id=session_id)
        self._sessions[session_id] = t
        return t

    def get(self, session_id: str) -> Trace | None:
        return self._sessions.get(session_id)

    def save(self, trace: Trace) -> None:
        self._sessions[trace.session_id] = trace

    def replay(self, session_id: str) -> list[dict]:
        """回放：把 steps 按顺序返回，方便定位"哪一步开始错"。"""
        t = self._sessions.get(session_id)
        return t.steps if t else []

    def export(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({k: v.to_dict() for k, v in self._sessions.items()},
                      f, ensure_ascii=False, indent=1)


# ---------------------------------------------------------------- 工具注册表


class ToolRegistry:
    """工具注册 + 调用的统一入口。

    比 target/tools.py 的裸 REGISTRY 多了三样：
        1. schema（能导出给 LLM 做 function calling）
        2. guard 权限钩子（加固/脆弱两种策略可切换）
        3. 调用日志自动写进 trace（可观测）

    新增工具只需 register()，编排层不用改——这是"工具层与编排层解耦"。
    """

    def __init__(self):
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        self._tools[spec.name] = spec

    def tool(self, name: str, description: str, parameters: dict[str, str],
             guard: Callable | None = None):
        """装饰器形式的注册，用起来更自然。"""
        def deco(fn: Callable):
            self.register(ToolSpec(name, description, parameters, fn, guard))
            return fn
        return deco

    def schemas(self) -> list[dict]:
        return [s.to_openai_schema() for s in self._tools.values()]

    def names(self) -> list[str]:
        return list(self._tools)

    def call(self, name: str, args: dict, trace: Trace | None = None) -> str:
        """统一调用入口：校验 → 权限 → 执行 → 记录，成功失败都写日志。"""
        entry: dict[str, Any] = {
            "name": name, "args": args or {},
            "ts": time.strftime("%H:%M:%S"),
        }
        spec = self._tools.get(name)
        if spec is None:
            entry.update(ok=False, result=f"未知工具：{name}")
            self._log(trace, entry)
            return entry["result"]

        # 参数校验：缺必填参数直接拒
        missing = [k for k in spec.parameters if k not in (args or {})]
        if missing:
            entry.update(ok=False, result=f"参数缺失：{missing}")
            self._log(trace, entry)
            return entry["result"]

        # 权限钩子
        if spec.guard:
            deny = spec.guard(args)
            if deny:
                entry.update(ok=False, result=deny)
                self._log(trace, entry)
                return deny

        # 执行
        try:
            result = spec.fn(**args)
            entry.update(ok=True, result=str(result)[:500])
        except TypeError as e:
            entry.update(ok=False, result=f"参数类型错误：{e}")
        except Exception as e:  # noqa: BLE001
            entry.update(ok=False, result=f"执行异常：{e}")
        self._log(trace, entry)
        return entry["result"]

    @staticmethod
    def _log(trace: Trace | None, entry: dict) -> None:
        if trace is not None:
            trace.tool_calls.append(entry)
