"""agentkit — 可复用的 LLM Agent 开发框架。

从 AgentProbe 中抽象出的三层核心：
    ToolRegistry  工具注册 + schema 校验 + 权限钩子 + 调用日志
    TraceStore    结构化 trace + 回放 + 导出
    AgentRunner   统一的 agent 执行抽象（ReAct / LangChain 双实现）

设计原则：
    1. 被测对象与测评工具解耦——Transport 契约（payload in, trace out）不变
    2. 可观测是一等公民——每次工具调用、每步决策都落进 trace
    3. 框架不绑死模型——本地 Ollama / 云端 OpenAI 兼容端点都能接

用法：
    from agentkit import ToolRegistry, TraceStore, AgentRunner
"""

from agentkit.core import ToolRegistry, TraceStore, ToolSpec, Trace
from agentkit.runner import ReActRunner, BaseRunner, make_runner
from agentkit.eval import EvalHarness, Assertion

__all__ = [
    "ToolRegistry", "TraceStore", "ToolSpec", "Trace",
    "ReActRunner", "BaseRunner", "make_runner",
    "EvalHarness", "Assertion",
]
