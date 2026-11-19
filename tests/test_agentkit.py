"""agentkit 框架测试：验证 ToolRegistry / TraceStore / ReActRunner 可用。

全部离线，用假 LLM 函数，不依赖任何 API key。
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from agentkit import ToolRegistry, TraceStore, ReActRunner, Trace
from agentkit import EvalHarness, Assertion
from agentkit.core import ToolSpec


def fake_llm_factory(replies):
    """按序返回预设的模型输出，模拟多步 ReAct。"""
    it = iter(replies)
    def call(messages):
        return next(it)
    return call


class TestToolRegistry(unittest.TestCase):
    def setUp(self):
        self.reg = ToolRegistry()

        def add(a: int, b: int) -> str:
            return str(a + b)

        self.reg.register(ToolSpec(
            "add", "两数相加", {"a": "int", "b": "int"}, add))

    def test_call_and_log(self):
        trace = Trace(session_id="t1")
        res = self.reg.call("add", {"a": 2, "b": 3}, trace)
        self.assertEqual(res, "5")
        self.assertEqual(len(trace.tool_calls), 1)
        self.assertTrue(trace.tool_calls[0]["ok"])

    def test_missing_arg_rejected(self):
        trace = Trace(session_id="t2")
        res = self.reg.call("add", {"a": 2}, trace)
        self.assertIn("参数缺失", res)
        self.assertFalse(trace.tool_calls[0]["ok"])

    def test_guard_denies(self):
        def deny(args):
            return "拒绝：越权" if args.get("a") < 0 else None
        self.reg.register(ToolSpec(
            "guarded", "带权限的工具", {"a": "int"},
            lambda a: str(a), guard=deny))
        trace = Trace(session_id="t3")
        res = self.reg.call("guarded", {"a": -1}, trace)
        self.assertIn("拒绝", res)
        self.assertFalse(trace.tool_calls[0]["ok"])

    def test_openai_schema(self):
        schema = self.reg.schemas()[0]
        self.assertEqual(schema["function"]["name"], "add")
        self.assertEqual(schema["function"]["parameters"]["properties"]["a"]["type"],
                         "integer")


class TestReActRunner(unittest.TestCase):
    def setUp(self):
        self.reg = ToolRegistry()
        self.reg.register(ToolSpec(
            "lookup", "查资料", {"q": "str"},
            lambda q: f"资料：{q}"))

    def test_tool_then_final(self):
        llm = fake_llm_factory([
            '{"tool":"lookup","args":{"q":"报销"}}',
            '{"final":"住宿标准 450 元"}',
        ])
        runner = ReActRunner(self.reg, llm, max_steps=4)
        trace = runner.run("住宿标准是多少", session_id="r1")
        self.assertEqual(trace.answer, "住宿标准 450 元")
        self.assertEqual(len(trace.tool_calls), 1)
        self.assertEqual(trace.tool_calls[0]["name"], "lookup")
        self.assertIsNone(trace.error)
        self.assertEqual(len(trace.steps), 2)  # 两轮 assistant 输出

    def test_malformed_json_fallback(self):
        llm = fake_llm_factory(["模型吐了坏 JSON { 不完整"])
        runner = ReActRunner(self.reg, llm, max_steps=2)
        trace = runner.run("随便问", session_id="r2")
        self.assertIn("坏 JSON", trace.answer)  # 回退成最终回答
        self.assertEqual(len(trace.tool_calls), 0)

    def test_store_replay(self):
        llm = fake_llm_factory([
            '{"tool":"lookup","args":{"q":"x"}}', '{"final":"done"}'])
        store = TraceStore()
        runner = ReActRunner(self.reg, llm, store=store, max_steps=3)
        runner.run("q", session_id="r3")
        replay = store.replay("r3")
        self.assertEqual(len(replay), 2)
        self.assertIn("store" if False else "assistant", replay[0]["role"])


class TestEvalHarness(unittest.TestCase):
    def test_eval_and_layered_report(self):
        """验证评测闭环：runner 跑 → 断言判 → 分层统计。"""
        reg = ToolRegistry()
        reg.register(ToolSpec("lookup", "查资料", {"q": "str"},
                              lambda q: f"资料：{q}"))
        # 两条载荷：一条触发工具，一条直接 final
        llm = fake_llm_factory([
            '{"tool":"lookup","args":{"q":"住宿"}}', '{"final":"450元"}',
            '{"final":"你好"}',
        ])
        runner = ReActRunner(reg, llm, max_steps=3)
        h = EvalHarness(runner)
        h.add(Assertion("tool_called",
                        lambda t: {"success": len(t["tool_calls"]) > 0,
                                   "reason": "工具被调用"}, strength="strong"))
        h.add(Assertion("mentions_450",
                        lambda t: {"success": "450" in t["answer"],
                                   "reason": "含 450"}, strength="medium"))
        cases = [
            {"id": "C-01", "payload": "住宿标准"},
            {"id": "C-02", "payload": "你好"},
        ]
        res = h.evaluate(cases)
        self.assertEqual(res["total"], 2)
        self.assertEqual(res["by_strength"]["strong"]["total"], 2)
        self.assertEqual(res["by_strength"]["strong"]["broken"], 1)
        report = h.report(res)
        self.assertIn("EvalHarness 报告", report)
        self.assertIn("strong", report)


if __name__ == "__main__":
    unittest.main()
